#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater top-level metadata update workflow"""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from typing import Iterable, Optional

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.api.metadata import (
    TOP_LEVEL_ROLE_NAMES,
    Metadata,
    Root,
    Snapshot,
    Targets,
    Timestamp,
)
from tuf.exceptions import (
    BadVersionNumberError,
    ExpiredMetadataError,
    ReplayedMetadataError,
    RepositoryError,
    UnsignedMetadataError,
)
from tuf.ngclient import Updater


# pylint: disable=too-many-public-methods
class TestRefresh(unittest.TestCase):
    """Test update of top-level metadata following
    'Detailed client workflow' in the specification."""

    # set dump_dir to trigger repository state dumps
    dump_dir: Optional[str] = None

    past_datetime = datetime.utcnow().replace(microsecond=0) - timedelta(days=5)

    def setUp(self) -> None:
        # pylint: disable=consider-using-with
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

        self.sim = RepositorySimulator()

        # boostrap client with initial root metadata
        with open(os.path.join(self.metadata_dir, "root.json"), "bw") as f:
            f.write(self.sim.signed_roots[0])

        if self.dump_dir is not None:
            # create test specific dump directory
            name = self.id().split(".")[-1]
            self.sim.dump_dir = os.path.join(self.dump_dir, name)
            os.mkdir(self.sim.dump_dir)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _run_refresh(self) -> Updater:
        """Create a new Updater instance and refresh"""
        if self.dump_dir is not None:
            self.sim.write()

        updater = Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
        )
        updater.refresh()
        return updater

    def _init_updater(self) -> Updater:
        """Create a new Updater instance"""
        if self.dump_dir is not None:
            self.sim.write()

        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
        )

    def _assert_files_exist(self, roles: Iterable[str]) -> None:
        """Assert that local metadata files exist for 'roles'"""
        expected_files = sorted([f"{role}.json" for role in roles])
        local_metadata_files = sorted(os.listdir(self.metadata_dir))
        self.assertListEqual(local_metadata_files, expected_files)

    def _assert_content_equals(
        self, role: str, version: Optional[int] = None
    ) -> None:
        """Assert that local file content is the expected"""
        expected_content = self.sim.fetch_metadata(role, version)
        with open(os.path.join(self.metadata_dir, f"{role}.json"), "rb") as f:
            self.assertEqual(f.read(), expected_content)

    def _assert_version_equals(self, role: str, expected_version: int) -> None:
        """Assert that local metadata version is the expected"""
        md = Metadata.from_file(os.path.join(self.metadata_dir, f"{role}.json"))
        self.assertEqual(md.signed.version, expected_version)

    def test_first_time_refresh(self) -> None:
        # Metadata dir contains only the mandatory initial root.json
        self._assert_files_exist([Root.type])

        # Add one more root version to repository so that
        # refresh() updates from local trusted root (v1) to
        # remote root (v2)
        self.sim.root.version += 1
        self.sim.publish_root()

        self._run_refresh()

        self._assert_files_exist(TOP_LEVEL_ROLE_NAMES)
        for role in TOP_LEVEL_ROLE_NAMES:
            version = 2 if role == Root.type else None
            self._assert_content_equals(role, version)

    def test_trusted_root_missing(self) -> None:
        os.remove(os.path.join(self.metadata_dir, "root.json"))
        with self.assertRaises(OSError):
            self._run_refresh()

        # Metadata dir is empty
        self.assertFalse(os.listdir(self.metadata_dir))

    def test_trusted_root_expired(self) -> None:
        # Create an expired root version
        self.sim.root.expires = self.past_datetime
        self.sim.root.version += 1
        self.sim.publish_root()

        # Update to latest root which is expired but still
        # saved as a local root.
        updater = self._init_updater()
        with self.assertRaises(ExpiredMetadataError):
            updater.refresh()

        self._assert_files_exist([Root.type])
        self._assert_content_equals(Root.type, 2)

        # Local root metadata can be loaded even if expired
        updater = self._init_updater()

        # Create a non-expired root version and refresh
        self.sim.root.expires = self.sim.safe_expiry
        self.sim.root.version += 1
        self.sim.publish_root()
        updater.refresh()

        # Root is successfully updated to latest version
        self._assert_files_exist(TOP_LEVEL_ROLE_NAMES)
        self._assert_content_equals(Root.type, 3)

    def test_trusted_root_unsigned(self) -> None:
        # Local trusted root is not signed
        root_path = os.path.join(self.metadata_dir, "root.json")
        md_root = Metadata.from_file(root_path)
        md_root.signatures.clear()
        md_root.to_file(root_path)

        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

        # The update failed, no changes in metadata
        self._assert_files_exist([Root.type])
        md_root_after = Metadata.from_file(root_path)
        self.assertEqual(md_root.to_bytes(), md_root_after.to_bytes())

    def test_max_root_rotations(self) -> None:
        # Root must stop looking for new versions after Y number of
        # intermediate files were downloaded.
        updater = self._init_updater()
        updater.config.max_root_rotations = 3

        # Create some number of roots greater than 'max_root_rotations'
        while self.sim.root.version < updater.config.max_root_rotations + 3:
            self.sim.root.version += 1
            self.sim.publish_root()

        md_root = Metadata.from_file(
            os.path.join(self.metadata_dir, "root.json")
        )
        initial_root_version = md_root.signed.version

        updater.refresh()

        # Assert that root version was increased with no more
        # than 'max_root_rotations'
        self._assert_version_equals(
            Root.type, initial_root_version + updater.config.max_root_rotations
        )

    def test_intermediate_root_incorrectly_signed(self) -> None:
        # Check for an arbitrary software attack

        # Intermediate root v2 is unsigned
        self.sim.root.version += 1
        root_signers = self.sim.signers[Root.type].copy()
        self.sim.signers[Root.type].clear()
        self.sim.publish_root()

        # Final root v3 is correctly signed
        self.sim.root.version += 1
        self.sim.signers[Root.type] = root_signers
        self.sim.publish_root()

        # Incorrectly signed intermediate root is detected
        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

        # The update failed, latest root version is v1
        self._assert_files_exist([Root.type])
        self._assert_content_equals(Root.type, 1)

    def test_intermediate_root_expired(self) -> None:
        # The expiration of the new (intermediate) root metadata file
        # does not matter yet

        # Intermediate root v2 is expired
        self.sim.root.expires = self.past_datetime
        self.sim.root.version += 1
        self.sim.publish_root()

        # Final root v3 is up to date
        self.sim.root.expires = self.sim.safe_expiry
        self.sim.root.version += 1
        self.sim.publish_root()

        self._run_refresh()

        # Successfully updated to root v3
        self._assert_files_exist(TOP_LEVEL_ROLE_NAMES)
        self._assert_content_equals(Root.type, 3)

    def test_final_root_incorrectly_signed(self) -> None:
        # Check for an arbitrary software attack
        self.sim.root.version += 1  # root v2
        self.sim.signers[Root.type].clear()
        self.sim.publish_root()

        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

        # The update failed, latest root version is v1
        self._assert_files_exist([Root.type])
        self._assert_content_equals(Root.type, 1)

    def test_new_root_same_version(self) -> None:
        # Check for a rollback_attack
        # Repository serves a root file with the same version as previous
        self.sim.publish_root()
        with self.assertRaises(ReplayedMetadataError):
            self._run_refresh()

        # The update failed, latest root version is v1
        self._assert_files_exist([Root.type])
        self._assert_content_equals(Root.type, 1)

    def test_new_root_nonconsecutive_version(self) -> None:
        # Repository serves non-consecutive root version
        self.sim.root.version += 2
        self.sim.publish_root()
        with self.assertRaises(ReplayedMetadataError):
            self._run_refresh()

        # The update failed, latest root version is v1
        self._assert_files_exist([Root.type])
        self._assert_content_equals(Root.type, 1)

    def test_final_root_expired(self) -> None:
        # Check for a freeze attack
        # Final root is expired
        self.sim.root.expires = self.past_datetime
        self.sim.root.version += 1
        self.sim.publish_root()

        with self.assertRaises(ExpiredMetadataError):
            self._run_refresh()

        # The update failed but final root is persisted on the file system
        self._assert_files_exist([Root.type])
        self._assert_content_equals(Root.type, 2)

    def test_new_timestamp_unsigned(self) -> None:
        # Check for an arbitrary software attack
        self.sim.signers[Timestamp.type].clear()
        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

        self._assert_files_exist([Root.type])

    def test_new_timestamp_version_rollback(self) -> None:
        # Check for a rollback attack
        self.sim.timestamp.version = 2
        self._run_refresh()

        self.sim.timestamp.version = 1
        with self.assertRaises(ReplayedMetadataError):
            self._run_refresh()

        self._assert_version_equals(Timestamp.type, 2)

    def test_new_timestamp_snapshot_rollback(self) -> None:
        # Check for a rollback attack.
        self.sim.snapshot.version = 2
        self.sim.update_timestamp()  # timestamp v2
        self._run_refresh()

        # Snapshot meta version is smaller than previous
        self.sim.timestamp.snapshot_meta.version = 1
        self.sim.timestamp.version += 1  # timestamp v3

        with self.assertRaises(ReplayedMetadataError):
            self._run_refresh()

        self._assert_version_equals(Timestamp.type, 2)

    def test_new_timestamp_expired(self) -> None:
        # Check for a freeze attack
        self.sim.timestamp.expires = self.past_datetime
        self.sim.update_timestamp()

        with self.assertRaises(ExpiredMetadataError):
            self._run_refresh()

        self._assert_files_exist([Root.type])

    def test_new_timestamp_fast_foward_recovery(self) -> None:
        """Test timestamp fast-forward recovery using key rotation.

        The timestamp recovery is made by the following steps
         - Remove the timestamp key
         - Create and add a new key for timestamp
         - Bump and publish root
         - Rollback the timestamp version
        """

        # attacker updates to a higher version
        self.sim.timestamp.version = 99999

        # client refreshes the metadata and see the new timestamp version
        self._run_refresh()
        self._assert_version_equals(Timestamp.type, 99999)

        # repo add new timestamp keys and recovers the timestamp version
        self.sim.root.roles["timestamp"].keyids.clear()
        self.sim.signers["timestamp"].clear()
        key, signer = self.sim.create_key()
        self.sim.root.add_key("timestamp", key)
        self.sim.add_signer("timestamp", signer)
        self.sim.root.version += 1
        self.sim.publish_root()
        self.sim.timestamp.version = 1

        # client refresh the metadata and see the initial timestamp version
        self._run_refresh()
        self._assert_version_equals(Timestamp.type, 1)

    def test_new_snapshot_hash_mismatch(self) -> None:
        # Check against timestamp role’s snapshot hash

        # Update timestamp with snapshot's hashes
        self.sim.compute_metafile_hashes_length = True
        self.sim.update_timestamp()  # timestamp v2
        self._run_refresh()

        # Modify snapshot contents without updating
        # timestamp's snapshot hash
        self.sim.snapshot.expires += timedelta(days=1)
        self.sim.snapshot.version += 1  # snapshot v2
        self.sim.timestamp.snapshot_meta.version = self.sim.snapshot.version
        self.sim.timestamp.version += 1  # timestamp v3

        # Hash mismatch error
        with self.assertRaises(RepositoryError):
            self._run_refresh()

        self._assert_version_equals(Timestamp.type, 3)
        self._assert_version_equals(Snapshot.type, 1)

    def test_new_snapshot_unsigned(self) -> None:
        # Check for an arbitrary software attack
        self.sim.signers[Snapshot.type].clear()
        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

        self._assert_files_exist([Root.type, Timestamp.type])

    def test_new_snapshot_version_mismatch(self) -> None:
        # Check against timestamp role’s snapshot version

        # Increase snapshot version without updating timestamp
        self.sim.snapshot.version += 1
        with self.assertRaises(BadVersionNumberError):
            self._run_refresh()

        self._assert_files_exist([Root.type, Timestamp.type])

    def test_new_snapshot_version_rollback(self) -> None:
        # Check for a rollback attack
        self.sim.snapshot.version = 2
        self.sim.update_timestamp()
        self._run_refresh()

        self.sim.snapshot.version = 1
        self.sim.update_timestamp()

        with self.assertRaises(ReplayedMetadataError):
            self._run_refresh()

        self._assert_version_equals(Snapshot.type, 2)

    def test_new_snapshot_expired(self) -> None:
        # Check for a freeze attack
        self.sim.snapshot.expires = self.past_datetime
        self.sim.update_snapshot()

        with self.assertRaises(ExpiredMetadataError):
            self._run_refresh()

        self._assert_files_exist([Root.type, Timestamp.type])

    def test_new_targets_hash_mismatch(self) -> None:
        # Check against snapshot role’s targets hashes

        # Update snapshot with target's hashes
        self.sim.compute_metafile_hashes_length = True
        self.sim.update_snapshot()
        self._run_refresh()

        # Modify targets contents without updating
        # snapshot's targets hashes
        self.sim.targets.version += 1
        self.sim.snapshot.meta[
            "targets.json"
        ].version = self.sim.targets.version
        self.sim.snapshot.version += 1
        self.sim.update_timestamp()

        with self.assertRaises(RepositoryError):
            self._run_refresh()

        self._assert_version_equals(Snapshot.type, 3)
        self._assert_version_equals(Targets.type, 1)

    def test_new_targets_unsigned(self) -> None:
        # Check for an arbitrary software attack
        self.sim.signers[Targets.type].clear()
        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

        self._assert_files_exist([Root.type, Timestamp.type, Snapshot.type])

    def test_new_targets_version_mismatch(self) -> None:
        # Check against snapshot role’s targets version

        # Increase targets version without updating snapshot
        self.sim.targets.version += 1
        with self.assertRaises(BadVersionNumberError):
            self._run_refresh()

        self._assert_files_exist([Root.type, Timestamp.type, Snapshot.type])

    def test_new_targets_expired(self) -> None:
        # Check for a freeze attack.
        self.sim.targets.expires = self.past_datetime
        self.sim.update_snapshot()

        with self.assertRaises(ExpiredMetadataError):
            self._run_refresh()

        self._assert_files_exist([Root.type, Timestamp.type, Snapshot.type])

    def test_compute_metafile_hashes_length(self) -> None:
        self.sim.compute_metafile_hashes_length = True
        self.sim.update_snapshot()
        self._run_refresh()
        self._assert_version_equals("timestamp", 2)
        self._assert_version_equals("snapshot", 2)

        self.sim.compute_metafile_hashes_length = False
        self.sim.update_snapshot()
        self._run_refresh()

        self._assert_version_equals("timestamp", 3)
        self._assert_version_equals("snapshot", 3)


if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestRefresh.dump_dir = tempfile.mkdtemp()
        print(f"Repository Simulator dumps in {TestRefresh.dump_dir}")
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
