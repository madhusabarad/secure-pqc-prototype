"""Comprehensive tests for keyservice: enrolment, rotation, revocation, backup, and persistence."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import logging
import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from pqcrypto.kem import ml_kem_768

import keyservice
from keyservice import (
    ALGORITHM,
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_RETIRING,
    STATUS_REVOKED,
    STATUS_UNKNOWN,
    BackupIntegrityError,
    DuplicateDeviceError,
    KeyNotFoundError,
    KeyService,
    NoActiveKeyError,
    StorageIntegrityError,
    ValidationError,
    create_backup,
    enrol,
    get_active_keys,
    get_key_status,
    get_public_keys,
    is_key_usable,
    is_revoked,
    list_user_keys,
    recover,
    restore_backup,
    revoke,
    rotate,
    verify_backup,
)
from keyservice.storage import resolve_state_dir


class _ListLogHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(self.format(record))


class KeyServiceCompleteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self._temp_dir.name)
        self._old_env = os.environ.get("TRACK4_STATE_DIR")
        self._old_grace_env = os.environ.get("TRACK4_KEY_GRACE_PERIOD_SECONDS")
        os.environ["TRACK4_STATE_DIR"] = str(self.state_dir)
        os.environ.pop("TRACK4_KEY_GRACE_PERIOD_SECONDS", None)

    def tearDown(self) -> None:
        if self._old_env is None:
            os.environ.pop("TRACK4_STATE_DIR", None)
        else:
            os.environ["TRACK4_STATE_DIR"] = self._old_env
        if self._old_grace_env is None:
            os.environ.pop("TRACK4_KEY_GRACE_PERIOD_SECONDS", None)
        else:
            os.environ["TRACK4_KEY_GRACE_PERIOD_SECONDS"] = self._old_grace_env
        self._temp_dir.cleanup()

    def test_enrol_generates_valid_ml_kem_768_keypair_and_metadata(self) -> None:
        result = enrol("alice", "laptop-01")

        self.assertEqual(result["user"], "alice")
        self.assertEqual(result["device"], "laptop-01")
        self.assertEqual(result["algorithm"], ALGORITHM)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["status"], STATUS_ACTIVE)
        self.assertTrue(result["usable_for_new_session"])
        self.assertTrue(result["usable_for_existing_session"])
        self.assertIsNone(result["revoked_at"])
        self.assertTrue(result["key_id"].startswith("mlkem768-"))
        self.assertNotIn("secret_key", result)
        self.assertNotIn("private_key", result)

        pk_bytes = base64.b64decode(result["public_key"])
        self.assertEqual(len(pk_bytes), ml_kem_768.PUBLIC_KEY_SIZE)

        private_file = self.state_dir / "keyservice" / "private" / f"{result['key_id']}.key"
        self.assertTrue(private_file.exists())
        private_payload = json.loads(private_file.read_text(encoding="utf-8"))
        sk_bytes = base64.b64decode(private_payload["secret_key_b64"])
        self.assertEqual(len(sk_bytes), ml_kem_768.SECRET_KEY_SIZE)

        ciphertext, shared_secret_enc = ml_kem_768.encrypt(pk_bytes)
        shared_secret_dec = ml_kem_768.decrypt(sk_bytes, ciphertext)
        self.assertEqual(shared_secret_enc, shared_secret_dec)

    def test_unique_key_ids_across_devices_and_users(self) -> None:
        k1 = enrol("alice", "laptop")
        k2 = enrol("alice", "phone")
        k3 = enrol("bob", "laptop")

        key_ids = {k1["key_id"], k2["key_id"], k3["key_id"]}
        public_keys = {k1["public_key"], k2["public_key"], k3["public_key"]}
        self.assertEqual(len(key_ids), 3)
        self.assertEqual(len(public_keys), 3)

    def test_duplicate_device_enrolment_does_not_overwrite(self) -> None:
        original = enrol("alice", "workstation")

        with self.assertRaises(DuplicateDeviceError):
            enrol("alice", "workstation")

        fetched = get_key_status(original["key_id"])
        self.assertEqual(fetched["key_id"], original["key_id"])
        self.assertEqual(fetched["public_key"], original["public_key"])
        self.assertEqual(fetched["version"], 1)
        self.assertEqual(fetched["status"], STATUS_ACTIVE)

    def test_successful_rotation_increments_version_and_preserves_history(self) -> None:
        k1 = enrol("alice", "laptop")
        rotated = rotate("alice", grace_period_seconds=120)

        self.assertEqual(rotated["user"], "alice")
        self.assertEqual(rotated["rotated_count"], 1)
        self.assertEqual(rotated["version"], 2)
        self.assertEqual(rotated["status"], STATUS_ACTIVE)
        self.assertEqual(rotated["previous_key_id"], k1["key_id"])
        self.assertNotEqual(rotated["key_id"], k1["key_id"])
        self.assertNotEqual(rotated["public_key"], k1["public_key"])

        new_pk = base64.b64decode(rotated["public_key"])
        new_private = json.loads(
            (self.state_dir / "keyservice" / "private" / f"{rotated['key_id']}.key").read_text(
                encoding="utf-8"
            )
        )
        new_sk = base64.b64decode(new_private["secret_key_b64"])
        ct, ss_enc = ml_kem_768.encrypt(new_pk)
        self.assertEqual(ss_enc, ml_kem_768.decrypt(new_sk, ct))

        old_status = get_key_status(k1["key_id"])
        self.assertEqual(old_status["status"], STATUS_RETIRING)
        self.assertEqual(old_status["version"], 1)
        self.assertFalse(old_status["usable_for_new_session"])
        self.assertTrue(old_status["usable_for_existing_session"])

        active_keys = get_active_keys("alice")
        self.assertEqual([k["key_id"] for k in active_keys], [rotated["key_id"]])

        history = list_user_keys("alice")
        self.assertEqual([h["version"] for h in history], [1, 2])

    def test_grace_period_enforcement_and_expiration(self) -> None:
        svc = KeyService(state_dir=self.state_dir, grace_period_seconds=60)
        t0 = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
        k1 = svc.enrol("alice", "laptop", now=t0)
        t_rotate = t0 + timedelta(seconds=10)
        k2 = svc.rotate("alice", now=t_rotate)

        during_grace = t_rotate + timedelta(seconds=30)
        self.assertEqual(svc.get_key_status(k1["key_id"], now=during_grace)["status"], STATUS_RETIRING)
        self.assertFalse(svc.is_key_usable(k1["key_id"], for_new_session=True, now=during_grace))
        self.assertTrue(svc.is_key_usable(k1["key_id"], for_new_session=False, now=during_grace))
        self.assertTrue(svc.is_key_usable(k2["key_id"], for_new_session=True, now=during_grace))

        after_grace = t_rotate + timedelta(seconds=60)
        self.assertEqual(svc.get_key_status(k1["key_id"], now=after_grace)["status"], STATUS_EXPIRED)
        self.assertFalse(svc.is_key_usable(k1["key_id"], for_new_session=True, now=after_grace))
        self.assertFalse(svc.is_key_usable(k1["key_id"], for_new_session=False, now=after_grace))

    def test_revocation_event_metadata_idempotency_and_grace_override(self) -> None:
        svc = KeyService(state_dir=self.state_dir, grace_period_seconds=600)
        t0 = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
        k1 = svc.enrol("alice", "laptop", now=t0)
        k2 = svc.rotate("alice", now=t0 + timedelta(seconds=5))

        rev1 = svc.revoke(k1["key_id"], now=t0 + timedelta(seconds=10))
        self.assertEqual(rev1["status"], STATUS_REVOKED)
        self.assertIsNotNone(rev1["revoked_at"])
        self.assertTrue(rev1["revocation_event_id"].startswith("rev-"))
        self.assertEqual(rev1["revocation_seq"], 1)
        self.assertFalse(rev1["usable_for_new_session"])
        self.assertFalse(rev1["usable_for_existing_session"])

        # Repeated revocation must be idempotent with identical event ID and sequence.
        rev_repeat = svc.revoke(k1["key_id"], now=t0 + timedelta(seconds=15))
        self.assertEqual(rev_repeat["revocation_event_id"], rev1["revocation_event_id"])
        self.assertEqual(rev_repeat["revocation_seq"], 1)
        self.assertEqual(rev_repeat["revoked_at"], rev1["revoked_at"])

        # Even inside grace period, revoked key is never accepted.
        still_within_grace = t0 + timedelta(seconds=20)
        self.assertFalse(
            svc.is_key_usable(k1["key_id"], for_new_session=False, now=still_within_grace)
        )

        # Revoking active key k2 increments sequence number and prevents rotation resurrection.
        rev2 = svc.revoke(k2["key_id"], now=t0 + timedelta(seconds=25))
        self.assertEqual(rev2["revocation_seq"], 2)
        with self.assertRaises(NoActiveKeyError):
            svc.rotate("alice", now=t0 + timedelta(seconds=30))

        with self.assertRaises(KeyNotFoundError):
            svc.revoke("mlkem768-nonexistent")

    def test_messaging_integration_helpers_is_revoked_and_get_public_keys(self) -> None:
        self.assertFalse(is_revoked("never-enrolled"))
        self.assertEqual(get_public_keys("never-enrolled"), [])

        k1 = enrol("alice", "laptop")
        self.assertFalse(is_revoked("alice"))
        pks_before = get_public_keys("alice")
        self.assertEqual(len(pks_before), 1)
        self.assertEqual(pks_before[0]["key_id"], k1["key_id"])
        self.assertNotIn("secret_key", pks_before[0])

        k2 = rotate("alice", grace_period_seconds=300)
        pks_rotated = get_public_keys("alice")
        self.assertEqual([k["key_id"] for k in pks_rotated], [k2["key_id"]])
        self.assertFalse(is_revoked("alice"))

        # Revoking retired k1 keeps k2 active; user alice still has usable k2.
        revoke(k1["key_id"])
        self.assertFalse(is_revoked("alice"))
        self.assertEqual([k["key_id"] for k in get_public_keys("alice")], [k2["key_id"]])

        # Revoking active k2 marks user alice revoked and removes all usable keys.
        revoke(k2["key_id"])
        self.assertTrue(is_revoked("alice"))
        self.assertEqual(get_public_keys("alice"), [])

    def test_multiple_rotations_across_multiple_devices(self) -> None:
        laptop_v1 = enrol("alice", "laptop")
        phone_v1 = enrol("alice", "phone")

        rot1 = rotate("alice", grace_period_seconds=300)
        self.assertEqual(rot1["rotated_count"], 2)
        self.assertEqual([k["version"] for k in rot1["new_keys"]], [2, 2])

        rot2 = rotate("alice", grace_period_seconds=300)
        self.assertEqual(rot2["rotated_count"], 2)
        self.assertEqual([k["version"] for k in rot2["new_keys"]], [3, 3])

        history = list_user_keys("alice")
        self.assertEqual(len(history), 6)
        self.assertEqual(get_key_status(laptop_v1["key_id"])["status"], STATUS_RETIRING)
        self.assertEqual(get_key_status(phone_v1["key_id"])["status"], STATUS_RETIRING)

    def test_backup_verification_restore_and_revocation_preservation(self) -> None:
        k1 = enrol("alice", "laptop")
        k2 = enrol("bob", "phone")
        revoke(k1["key_id"])

        backup_info = create_backup()
        backup_path = Path(backup_info["backup_path"])
        self.assertTrue(backup_path.exists())
        verified = verify_backup(backup_path)
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["key_count"], 2)
        self.assertEqual(verified["revocation_count"], 1)

        # Simulate corrupted registry.json and recover from validated backup.
        registry_path = self.state_dir / "keyservice" / "registry.json"
        registry_path.write_text("{corrupted json", encoding="utf-8")
        with self.assertRaises(StorageIntegrityError):
            get_key_status(k2["key_id"])

        restored = restore_backup(backup_path)
        self.assertTrue(restored["restored"])
        self.assertEqual(get_key_status(k1["key_id"])["status"], STATUS_REVOKED)
        self.assertEqual(get_key_status(k2["key_id"])["status"], STATUS_ACTIVE)
        self.assertEqual([k["key_id"] for k in get_public_keys("bob")], [k2["key_id"]])
        self.assertTrue(is_revoked("alice"))

    def test_corrupted_backup_rejected_without_overwriting_valid_state(self) -> None:
        k1 = enrol("alice", "laptop")
        backup_info = create_backup()
        backup_path = Path(backup_info["backup_path"])

        # Tamper with backup JSON -> must be rejected and live state left intact.
        tampered = json.loads(backup_path.read_text(encoding="utf-8"))
        tampered["keys"][k1["key_id"]]["version"] = 99
        tampered_path = self.state_dir / "tampered_backup.json"
        tampered_path.write_text(json.dumps(tampered), encoding="utf-8")

        with self.assertRaises(BackupIntegrityError):
            verify_backup(tampered_path)
        with self.assertRaises(BackupIntegrityError):
            restore_backup(tampered_path)

        # Live state remains valid and untouched.
        live = get_key_status(k1["key_id"])
        self.assertEqual(live["version"], 1)
        self.assertEqual(live["status"], STATUS_ACTIVE)

    def test_older_backup_cannot_reactivate_subsequently_revoked_key(self) -> None:
        k1 = enrol("alice", "laptop")
        pre_revoke_backup = create_backup()["backup_path"]

        # Revoke k1 AFTER the backup was created.
        revoke(k1["key_id"])
        self.assertEqual(get_key_status(k1["key_id"])["status"], STATUS_REVOKED)

        # Restoring pre-revocation backup must NOT reactivate k1.
        restore_backup(pre_revoke_backup)
        self.assertEqual(get_key_status(k1["key_id"])["status"], STATUS_REVOKED)
        self.assertTrue(is_revoked("alice"))
        self.assertEqual(get_public_keys("alice"), [])

    def test_crash_recovery_cleans_stale_temp_files(self) -> None:
        k1 = enrol("alice", "laptop")
        stale_tmp = self.state_dir / "keyservice" / ".registry.json.crashed.tmp"
        stale_tmp.write_text("partial", encoding="utf-8")

        summary = recover()
        self.assertTrue(summary["recovered"])
        self.assertEqual(summary["key_count"], 1)
        self.assertFalse(stale_tmp.exists())
        self.assertEqual(get_key_status(k1["key_id"])["status"], STATUS_ACTIVE)

    def test_concurrent_updates_do_not_lose_data(self) -> None:
        def _enrol_worker(idx: int) -> str:
            return enrol(f"user-{idx}", f"dev-{idx}")["key_id"]

        with ThreadPoolExecutor(max_workers=6) as pool:
            ids = list(pool.map(_enrol_worker, range(12)))

        self.assertEqual(len(set(ids)), 12)
        for idx, kid in enumerate(ids):
            st = get_key_status(kid)
            self.assertEqual(st["user"], f"user-{idx}")
            self.assertEqual(st["status"], STATUS_ACTIVE)

    def test_persistence_across_separate_python_processes(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent.parent
        env = os.environ.copy()
        env["TRACK4_STATE_DIR"] = str(self.state_dir)
        env["TRACK4_KEY_GRACE_PERIOD_SECONDS"] = "120"

        enrolled = json.loads(
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import json, keyservice; print(json.dumps(keyservice.enrol('alice', 'tablet')))",
                ],
                cwd=repo_root,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )
        rotated = json.loads(
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import json, keyservice; print(json.dumps(keyservice.rotate('alice')))",
                ],
                cwd=repo_root,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys, keyservice; keyservice.revoke(sys.argv[1])",
                enrolled["key_id"],
            ],
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )

        checked = json.loads(
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import json, sys, keyservice; "
                        "print(json.dumps({"
                        "'old': keyservice.get_key_status(sys.argv[1]), "
                        "'new': keyservice.get_key_status(sys.argv[2]), "
                        "'is_revoked': keyservice.is_revoked('alice'), "
                        "'pub_keys': keyservice.get_public_keys('alice'), "
                        "'unknown': keyservice.get_key_status('mlkem768-missing')"
                        "}))"
                    ),
                    enrolled["key_id"],
                    rotated["key_id"],
                ],
                cwd=repo_root,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )
        self.assertEqual(checked["old"]["status"], STATUS_REVOKED)
        self.assertEqual(checked["new"]["status"], STATUS_ACTIVE)
        self.assertFalse(checked["is_revoked"])
        self.assertEqual([k["key_id"] for k in checked["pub_keys"]], [rotated["key_id"]])
        self.assertEqual(checked["unknown"]["status"], STATUS_UNKNOWN)

    def test_zero_grace_period_expires_immediately_across_processes(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent.parent
        env = os.environ.copy()
        env["TRACK4_STATE_DIR"] = str(self.state_dir)
        env["TRACK4_KEY_GRACE_PERIOD_SECONDS"] = "0"

        k1 = json.loads(
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import json, keyservice; print(json.dumps(keyservice.enrol('zoe', 'badge')))",
                ],
                cwd=repo_root,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import json, keyservice; print(json.dumps(keyservice.rotate('zoe')))",
            ],
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        expired_status = json.loads(
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import json, sys, keyservice; print(json.dumps(keyservice.get_key_status(sys.argv[1])))",
                    k1["key_id"],
                ],
                cwd=repo_root,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )
        self.assertEqual(expired_status["status"], STATUS_EXPIRED)
        self.assertFalse(expired_status["usable_for_new_session"])
        self.assertFalse(expired_status["usable_for_existing_session"])

    def test_default_state_dir_outside_repo_when_env_unset(self) -> None:
        os.environ.pop("TRACK4_STATE_DIR", None)
        repo_root = Path(__file__).resolve().parent.parent.parent
        resolved = resolve_state_dir()
        self.assertFalse(resolved.is_relative_to(repo_root))

    def test_invalid_inputs_and_unknown_status_are_handled(self) -> None:
        invalid_values: list[object] = [
            "",
            "   ",
            " alice",
            "alice ",
            "alice\n",
            "alice\x00bob",
            "a" * 129,
            None,
            123,
        ]
        for bad in invalid_values:
            with self.subTest(bad_user=bad):
                with self.assertRaises(ValidationError):
                    enrol(bad, "device-1")  # type: ignore[arg-type]
                with self.assertRaises(ValidationError):
                    rotate(bad)  # type: ignore[arg-type]
                with self.assertRaises(ValidationError):
                    is_revoked(bad)  # type: ignore[arg-type]
                with self.assertRaises(ValidationError):
                    get_public_keys(bad)  # type: ignore[arg-type]
            with self.subTest(bad_device=bad):
                with self.assertRaises(ValidationError):
                    enrol("alice", bad)  # type: ignore[arg-type]
            with self.subTest(bad_key_id=bad):
                with self.assertRaises(ValidationError):
                    get_key_status(bad)  # type: ignore[arg-type]
                with self.assertRaises(ValidationError):
                    revoke(bad)  # type: ignore[arg-type]

        for bad_path in ("../escape", "dir/key", "dir\\key"):
            with self.assertRaises(ValidationError):
                get_key_status(bad_path)
            with self.assertRaises(ValidationError):
                revoke(bad_path)

        for bad_grace in (-1, -0.01, float("nan"), float("inf"), True, "abc"):
            with self.subTest(bad_grace=bad_grace):
                with self.assertRaises(ValidationError):
                    rotate("alice", grace_period_seconds=bad_grace)  # type: ignore[arg-type]

        with self.assertRaises(NoActiveKeyError):
            rotate("unknown-user")

        unknown = get_key_status("mlkem768-doesnotexist")
        self.assertEqual(unknown["status"], STATUS_UNKNOWN)
        self.assertFalse(is_key_usable("mlkem768-doesnotexist", for_new_session=True))
        self.assertFalse(is_key_usable("mlkem768-doesnotexist", for_new_session=False))

    def test_private_key_material_not_exposed_in_logs_output_backup_or_registry(self) -> None:
        ks_logger = logging.getLogger("keyservice")
        old_level = ks_logger.level
        ks_logger.setLevel(logging.DEBUG)
        handler = _ListLogHandler()
        ks_logger.addHandler(handler)
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()

        try:
            with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                enrolled = enrol("carol", "sensor-node")
                rotated = rotate("carol", grace_period_seconds=60)
                backup_summary = create_backup()
                revoked = revoke(enrolled["key_id"])
                status = get_key_status(rotated["key_id"])
                pub_keys = get_public_keys("carol")
        finally:
            ks_logger.removeHandler(handler)
            ks_logger.setLevel(old_level)

        secrets_to_check: list[str] = []
        for kid in (enrolled["key_id"], rotated["key_id"]):
            private_file = self.state_dir / "keyservice" / "private" / f"{kid}.key"
            private_payload = json.loads(private_file.read_text(encoding="utf-8"))
            secret_b64 = private_payload["secret_key_b64"]
            secret_hex = base64.b64decode(secret_b64).hex()
            secrets_to_check.extend([secret_b64, secret_b64[:32], secret_hex[:32]])

        registry_text = (self.state_dir / "keyservice" / "registry.json").read_text(encoding="utf-8")
        combined_output = "\n".join(
            [
                *handler.messages,
                stdout_buf.getvalue(),
                stderr_buf.getvalue(),
                json.dumps(enrolled),
                json.dumps(rotated),
                json.dumps(backup_summary),
                json.dumps(revoked),
                json.dumps(status),
                json.dumps(pub_keys),
                registry_text,
            ]
        )

        for secret_fragment in secrets_to_check:
            self.assertNotIn(secret_fragment, combined_output)
        self.assertNotIn("secret_key", combined_output)

    def test_registry_integrity_tamper_detection(self) -> None:
        enrolled = enrol("dave", "edge-01")
        registry_path = self.state_dir / "keyservice" / "registry.json"
        data = json.loads(registry_path.read_text(encoding="utf-8"))
        data["keys"][enrolled["key_id"]]["status"] = "revoked"
        registry_path.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaises(StorageIntegrityError):
            get_key_status(enrolled["key_id"])

        self.assertTrue(hasattr(keyservice, "is_revoked"))


if __name__ == "__main__":
    unittest.main()
