"""Comprehensive tests for the distributed three-node revocation infrastructure."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from keyservice import enrol, revoke
from nodes import (
    DEFAULT_NODE_IDS,
    DuplicateEventError,
    Node,
    NodeCluster,
    NodeIntegrityError,
    NodeOfflineError,
    OutdatedEventError,
    RevocationEvent,
    get_cluster_status,
    initialize_cluster,
    sync_nodes,
)


def _make_event(
    event_id: str,
    sequence_number: int,
    key_id: str,
    user: str = "alice",
    device: str = "laptop",
    version: int = 1,
) -> RevocationEvent:
    return RevocationEvent(
        event_id=event_id,
        sequence_number=sequence_number,
        key_id=key_id,
        user=user,
        device=device,
        version=version,
        revoked_at=datetime.now(timezone.utc).isoformat(),
        source="keyservice",
    ).with_checksum()


class NodesClusterTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self._temp_dir.name)
        self._old_env = os.environ.get("TRACK4_STATE_DIR")
        os.environ["TRACK4_STATE_DIR"] = str(self.state_dir)

    def tearDown(self) -> None:
        if self._old_env is None:
            os.environ.pop("TRACK4_STATE_DIR", None)
        else:
            os.environ["TRACK4_STATE_DIR"] = self._old_env
        self._temp_dir.cleanup()

    def test_three_node_initialization_and_independent_storage(self) -> None:
        init_result = initialize_cluster()
        self.assertEqual(tuple(init_result["node_ids"]), DEFAULT_NODE_IDS)

        for nid in DEFAULT_NODE_IDS:
            node_dir = self.state_dir / "nodes" / nid
            self.assertTrue((node_dir / "state.json").exists())
            node = Node(nid)
            self.assertTrue(node.is_online())
            self.assertEqual(node.get_state()["last_applied_seq"], 0)

        status = get_cluster_status()
        self.assertTrue(status["consistent"])
        self.assertEqual(len(status["nodes"]), 3)

    def test_revocation_propagation_from_keyservice_to_all_three_nodes(self) -> None:
        initialize_cluster()
        k1 = enrol("alice", "laptop")
        rev = revoke(k1["key_id"])

        self.assertIn("propagation", rev)
        self.assertEqual(set(rev["propagation"]["applied_nodes"]), set(DEFAULT_NODE_IDS))
        self.assertEqual(rev["propagation"]["offline_nodes"], [])

        cluster = NodeCluster()
        self.assertTrue(cluster.is_consistent())
        for nid in DEFAULT_NODE_IDS:
            node = cluster.get_node(nid)
            self.assertTrue(node.is_key_revoked(k1["key_id"]))
            self.assertEqual(node.get_key_status(k1["key_id"])["status"], "revoked")
            self.assertEqual(node.get_state()["last_applied_seq"], 1)

    def test_duplicate_outdated_and_replay_event_rejection(self) -> None:
        initialize_cluster()
        node = Node("node-1")

        ev1 = _make_event("rev-event-001", 1, "mlkem768-key1")
        ev2 = _make_event("rev-event-002", 2, "mlkem768-key2")
        ev_stale_seq = _make_event("rev-event-stale", 2, "mlkem768-key3")
        ev_lower_seq = _make_event("rev-event-lower", 1, "mlkem768-key4")

        res1 = node.apply_revocation_event(ev1)
        self.assertTrue(res1["applied"])
        self.assertEqual(res1["last_applied_seq"], 1)

        # Replay / duplicate event ID rejected.
        with self.assertRaises(DuplicateEventError):
            node.apply_revocation_event(ev1)

        res2 = node.apply_revocation_event(ev2)
        self.assertEqual(res2["last_applied_seq"], 2)

        # Outdated / equal or lower sequence numbers with unseen IDs rejected.
        with self.assertRaises(OutdatedEventError):
            node.apply_revocation_event(ev_stale_seq)
        with self.assertRaises(OutdatedEventError):
            node.apply_revocation_event(ev_lower_seq)

        # Tampered checksum rejected.
        tampered = ev2.to_dict()
        tampered["key_id"] = "mlkem768-tampered"
        with self.assertRaises(NodeIntegrityError):
            node.apply_revocation_event(tampered)

        state = node.get_state()
        self.assertEqual(state["sync_metadata"]["rejected_duplicates"], 1)
        self.assertEqual(state["sync_metadata"]["rejected_outdated"], 2)
        self.assertFalse(node.is_key_revoked("mlkem768-key3"))
        self.assertFalse(node.is_key_revoked("mlkem768-key4"))

    def test_offline_node_handling_and_recovery_synchronization(self) -> None:
        cluster = NodeCluster()
        cluster.initialize_nodes()
        k1 = enrol("alice", "laptop")
        k2 = enrol("bob", "phone")
        cluster.sync_all()

        # Take node-3 offline before revoking k1 and k2.
        cluster.set_node_online("node-3", False)
        with self.assertRaises(NodeOfflineError):
            cluster.get_node("node-3").apply_revocation_event(_make_event("rev-manual", 1, k1["key_id"]))

        rev1 = revoke(k1["key_id"])
        self.assertEqual(set(rev1["propagation"]["applied_nodes"]), {"node-1", "node-2"})
        self.assertEqual(rev1["propagation"]["offline_nodes"], ["node-3"])

        rev2 = revoke(k2["key_id"])
        self.assertEqual(rev2["propagation"]["offline_nodes"], ["node-3"])

        # node-1 and node-2 have seq=2; node-3 is still at seq=0 while offline.
        self.assertTrue(cluster.get_node("node-1").is_key_revoked(k1["key_id"]))
        self.assertTrue(cluster.get_node("node-2").is_key_revoked(k2["key_id"]))
        self.assertFalse(cluster.get_node("node-3").is_key_revoked(k1["key_id"]))

        # Bring node-3 back online and recover/sync.
        cluster.set_node_online("node-3", True)
        recovered = cluster.recover_node("node-3")
        self.assertTrue(recovered["recovered"])
        self.assertEqual(recovered["sync"]["status"], "synced")
        self.assertEqual(recovered["sync"]["applied_revocations"], 2)
        self.assertEqual(recovered["sync"]["last_applied_seq"], 2)

        self.assertTrue(cluster.is_consistent())
        self.assertTrue(cluster.get_node("node-3").is_key_revoked(k1["key_id"]))
        self.assertTrue(cluster.get_node("node-3").is_key_revoked(k2["key_id"]))

    def test_revoked_key_never_becomes_valid_again_after_metadata_sync_or_restart(self) -> None:
        cluster = NodeCluster()
        cluster.initialize_nodes()
        k1 = enrol("alice", "laptop")
        revoke(k1["key_id"])

        node1 = cluster.get_node("node-1")
        self.assertTrue(node1.is_key_revoked(k1["key_id"]))

        # Attempt to sync stale "active" metadata for k1 onto node-1 must be ignored.
        node1.sync_key_metadata(
            {
                k1["key_id"]: {
                    "key_id": k1["key_id"],
                    "user": "alice",
                    "device": "laptop",
                    "version": 1,
                    "status": "active",
                    "public_key_sha256": k1["public_key_sha256"],
                    "grace_until": None,
                    "revoked_at": None,
                    "revocation_event_id": None,
                    "revocation_seq": None,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            },
            source="stale-peer",
        )
        self.assertTrue(node1.is_key_revoked(k1["key_id"]))
        self.assertEqual(node1.get_key_status(k1["key_id"])["status"], "revoked")

    def test_wal_crash_recovery_replays_uncheckpointed_revocation(self) -> None:
        node = Node("node-1")
        node.initialize()

        # Simulate a crash right after WAL append + fsync before state.json was replaced.
        ev = _make_event("rev-wal-crash-1", 1, "mlkem768-crashkey")
        with open(node.wal_path, "ab") as handle:
            handle.write((json.dumps(ev.to_dict(), sort_keys=True) + "\n").encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())

        # New Node instance / process recovers from WAL automatically.
        restarted_node = Node("node-1")
        recovered_state = restarted_node.recover()
        self.assertEqual(recovered_state["last_applied_seq"], 1)
        self.assertTrue(restarted_node.is_key_revoked("mlkem768-crashkey"))
        self.assertEqual(recovered_state["sync_metadata"]["recovered_wal_events"], 1)

    def test_persistence_and_synchronization_across_separate_python_processes(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent.parent
        env = os.environ.copy()
        env["TRACK4_STATE_DIR"] = str(self.state_dir)

        subprocess.run(
            [sys.executable, "-c", "import nodes; nodes.initialize_cluster()"],
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        enrolled = json.loads(
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import json, keyservice; print(json.dumps(keyservice.enrol('alice', 'node-dev')))",
                ],
                cwd=repo_root,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )
        # Take node-2 offline in process 3.
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import nodes; nodes.NodeCluster().set_node_online('node-2', False)",
            ],
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        # Revoke in process 4.
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
        # Bring node-2 online and sync in process 5.
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import nodes; c = nodes.NodeCluster(); c.set_node_online('node-2', True); c.sync_all()",
            ],
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        # Verify consistency and revocation across all 3 nodes in process 6.
        cluster_status = json.loads(
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import json, nodes; print(json.dumps(nodes.get_cluster_status()))",
                ],
                cwd=repo_root,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )
        self.assertTrue(cluster_status["consistent"])
        for nid in DEFAULT_NODE_IDS:
            self.assertIn(enrolled["key_id"], cluster_status["nodes"][nid]["revoked_key_ids"])
            self.assertEqual(cluster_status["nodes"][nid]["last_applied_seq"], 1)


if __name__ == "__main__":
    unittest.main()
