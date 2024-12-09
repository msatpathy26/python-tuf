#!/usr/bin/env python3
import shutil
from importlib.metadata import metadata
from pathlib import Path
from shutil import rmtree
from copy import deepcopy

from securesystemslib.signer import SSlibKey, CryptoSigner, Signature
from tuf.api.serialization.json import JSONSerializer, JSONDeserializer

from Montavista.log import exit_with_error, print_warning, print_traceback, print_info
from datetime import datetime, timedelta, timezone
from key.rsa import RSAkey
from typing import Union

from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    Metadata,
    Root,
    Snapshot,
    Targets,
    Timestamp,
    TargetFile,
    VerificationResult,
    RootVerificationResult,
)

SPEC_VERSION = ".".join(SPECIFICATION_VERSION)

def _in(days: float) -> datetime:
    """Adds 'days' to now and returns datetime object w/o microseconds."""
    return datetime.now(timezone.utc).replace(microsecond=0) + timedelta(
        days=days
    )

class MVRepo:
    def __init__(self):
        self.consistent_snapshot = False
        self.signers = {"root":[], "targets": [], "timestamp":[], "snapshot":[]}
        self.role_types = ("targets", "timestamp", "snapshot", "root")
        self.roles_last = {"root": None, "targets": None, "timestamp":None, "snapshot":None}
        self.roles_threshold = {"root": 2, "targets": 1, "timestamp": 1, "snapshot": 1}
        self.expiry = {"root": _in(365), "targets": _in(30), "snapshot": _in(30), "timestamp": _in(1) }
        #self.roles = {"targets": Metadata(Targets(expires=self.expiry["targets"])),
        #              "snapshot": Metadata(Snapshot(expires=self.expiry["snapshot"])),
        #              "timestamp": Metadata(Timestamp(expires=self.expiry["timestamp"])),
        #              "root": Metadata(Root(expires=self.expiry["root"], consistent_snapshot=self.consistent_snapshot)),
        #              }
        self.roles = {"root": None, "targets": None, "timestamp":None, "snapshot":None}
        self.public_keys = {"root": [], "targets": [], "timestamp":[], "snapshot":[]}

    def set_signer(self, role: str, encryption: str, private_key: str = "", prompt = True) -> CryptoSigner:
        """initialize signer objects for roles using private key files

            Args:
                * role: role name
                    valid inputs : "root" | "targets" | "snapshot" | "timestamp"
                * encryption: encryption algorithm
                    valid inputs: "rsa" |"ecdsa" | "ed25519"
                * private_key: private key file path
                * prompt: If set to True, should prompt for providing private key file path
                            (incase not passed directly or correctly as an argument using private_key)
            Returns:
                None
        """
        signer = None
        if not Path(private_key).is_file():
            if prompt == True:
                private_key = input(f"Invalid Private key file!!\nEnter the private key path again for '{role}':")
            else:
                exit_with_error(f"Private file not found at:{private_key}")

        # TBD: Verify the key formats are correct before using

        if encryption.upper() == 'RSA':
            _key = RSAkey().get_signer(pvtkey_file=private_key)
        elif encryption.upper() == 'ECDSA':
            raise NotImplementedError # TBD: Pending implementation
        elif encryption.upper() == 'ED25519':
            raise NotImplementedError # TBD: Pending implementation
        else:
            exit_with_error(f"Invalid decryption algorithm:{key_type}")

        self.signers[role].append(_key)

    def set_role_threshold(self, role: str, threshold: int):
        """initialize threshold value for each role

            Args:
                * role: role name
                    valid inputs : "root" | "targets" | "snapshot" | "timestamp"
                    * threshold: integer between 1 & 3
            Returns:
                None
        """
        if threshold > 0 and threshold <= 3:
            self.roles_threshold[role] = threshold

    def get_role_threshold(self, role: str):
        """Get threshold value for a role

            Args:
                * role: role name
                    valid inputs : "root" | "targets" | "snapshot" | "timestamp"
            Returns:
                None
        """
        return self.roles["root"].signed.roles[role].threshold

    def _update_version(self, role: str):
        """Bumps metadata version along with updating the expiry"""
        self.roles[role].signed.version += 1
        self.roles[role].signed.expires = self.expiry[role]

    def _add_public_key(self, public_key: SSlibKey, role: str):
        """Adds public key for metadata. Required at repository creation time.
        Do not call this method directly to set public keys of out-of-band signers

            Args:
                * public_key: public key object (SSlibKey) for the signer
                * role: role name
                      valid inputs : "root" | "targets" | "snapshot" | "timestamp"
            Returns:
                None
        """
        if self.roles["root"]:
            self.roles["root"].signed.add_key(public_key, role)
        else:
            exit_with_error("ROOT role is not initialized")

    def set_out_of_band_publickey(self, public_key: SSlibKey, role: str):
        """Add public key for signers performing out-of-band signing.
           Required to be provided before repository creation.

            Args:
                * public_key: public key object (SSlibKey) for the signer
                * role: role name
                    valid inputs : "root" | "targets" | "snapshot" | "timestamp"
            Returns:
                None
        """
        if role not in self.role_types:
            exit_with_error(f"Invalid role:{role}")

        self.public_keys[role].append(public_key)

    def _role_sign(self, rolename: str, extra_signer: CryptoSigner = None ) -> Signature:
        """ To sign the metadata during
            - repository creation
            - out-of-band signing
            - adding targets (TBD)
            - Auto signing of timestamp metadata (TBD)
            - Key rotation (TBD)

            Args:
                * rolename: role name
                        valid inputs : "root" | "targets" | "snapshot" | "timestamp"
                * extra_signer: This has to be passed explicitly for out-of-band signing only
            Returns:
                A securesystemslib.signer.Signature object
        """
        _signature = None

        if self.roles[rolename]:
            if extra_signer:
                _signature = self.roles[rolename].sign(extra_signer, append = True)
            elif self.signers[rolename]:
                for _signer in self.signers[rolename]:
                    _signature = self.roles[rolename].sign(_signer, append = True)
            else:
                _signature = None
                print_warning(f"Failed to sign for role {rolename}")

        return _signature

    def _store_to_file(self, role: str):
        """ Saves metadata objects into json files"""

        PRETTY = JSONSerializer(compact=False)
        _file_path = Path(self.metadata_dir).joinpath(f"{role}.json")
        try:
            self.roles[role].to_file(filename=_file_path, serializer=PRETTY)
        except Exception as e:
            exit_with_error(f"{type(e).__name__}–{e}")

    def create(self, repo_path = "", force = True):
        """ Creates a repository directory tree in the following way:
        tufrepo/
        ├── metadata/
        │   ├── root.json
        │   ├── snapshot.json
        │   ├── targets.json
        │   └── timestamp.json
        └── targets/
        This requires the pre-initialization of signers for all roles through
        set_signer method.

            Args:
                * repo_path: path at which repository needs to be created
                    Defaults to './tufrepo/'
                * force: overwrites existing repository at same path, if left as 'True'
            Returns:
                None
        """
        #Check if signers are set
        for _role in ("root", "timestamp", "targets", "snapshot"):
            if self.signers[_role] == None:
                exit_with_error(f"Signer not set for role:{_role}")

        # Create directory path, pick default as tufrepo in $pwd
        if not repo_path:
            repo_path = "./tufrepo"

        # set sub-directories paths for targets and metadata under it
        repo_dir = Path(repo_path).resolve()
        targets_dir = repo_dir.joinpath("targets")
        metadata_dir = repo_dir.joinpath("metadata")

        try:
            #Delete old directory if enabled for overwrite
            if force and repo_dir.exists():
                rmtree(repo_dir)

            #Create the repo directory structure
            repo_dir.mkdir(0o755)
            targets_dir.mkdir(0o755)
            metadata_dir.mkdir(0o755)

        except Exception as e:
            print_traceback(e, "Failed to create repo directory.")

        #store the path variables into the object
        self.repo_path = repo_dir
        self.targets_dir = targets_dir
        self.metadata_dir = metadata_dir

        #Initialize role metadata
        self.roles = {"targets": Metadata(Targets(expires=self.expiry["targets"])),
                      "snapshot": Metadata(Snapshot(expires=self.expiry["snapshot"])),
                      "timestamp": Metadata(Timestamp(expires=self.expiry["timestamp"])),
                      "root": Metadata(Root(expires=self.expiry["root"], consistent_snapshot=self.consistent_snapshot)),
                      }

        #set the threshold values for each roles
        for role in self.role_types:
            self.roles["root"].signed.roles[role].threshold = self.roles_threshold[role]

        # Add signer public key to each role metadata and sign them
        for role in self.role_types:
            for signer in self.signers[role]:
                _public_key = signer.public_key
                self._add_public_key(_public_key, role)

            #Add any available public keys for out of band signing (currently for root only)
            for _public_key in self.public_keys[role]:
                self._add_public_key(_public_key, role)

            self._role_sign(role)

        #Validate each metadata. If you have added public keys which are yet to be-
        #signed by the respective private key out-of-band, you will get a warning message,
        #which is normal. Ensure the out-of-band signing is completed before using the repo.
        for role in self.role_types:
            vr = self._get_verification_result(role, self.roles[role])
            if not vr:
                #TBD: Only for unsigned root metadata warning; otherwise fail!
                print_warning(f"Role {role} failed to verify:\n{vr}")
                #raise ValueError(f"Role {role} failed to verify")

        #Save each metadata to file
        for role in self.role_types:
            self._store_to_file(role)

    def _get_verification_result(
        self, role: str, md: Metadata
    ) -> Union[VerificationResult, RootVerificationResult]:
        """Verify roles metadata using the existing repository metadata"""
        if role == "root":
            assert isinstance(md.signed, Root)
            previous = self.roles_last["root"]

            return md.signed.get_root_verification_result(
                previous, md.signed_bytes, md.signatures
            )
        if role in ["timestamp", "snapshot", "targets"]:
            delegator: Signed = self.roles["root"].signed
        else:
            #delegator = self.targets()
            delegator = self.roles["targets"].signed
        return delegator.get_verification_result(
            role, md.signed_bytes, md.signatures
        )

    def auto_sign(self, role: str, repo_path: str = "./tufrepo"):
        """ For signing the timestamp and snapshot metadata automatically on expiry
            This needs the respective signer keys to be initialized.
            Args:
               * rolename: role name
                          valid inputs : "snapshot" | "timestamp"
               * repo_path: Path of the repository. Defaults to "./tufrepo"
               Returns:
                  None
        """
        #Verify the role type passed
        if role not in ("snapshot", "timestamp"):
            exit_with_error("Auto signing is available only for 'snapshot' or 'timestamp' at the moment")

        # Verify the signer is initialized already for the role
        if not self.signers[role]:
            exit_with_error(f"Signer not available to sign for {metadata}.json")

        #Re-initialize attributes to avoid propagation of stale data
        self.repo_path = Path(repo_path).resolve()
        self.metadata_dir = Path(self.repo_path).joinpath("metadata")
        self._clear_repo_cache()

        #Load role metadata from json files
        for _role in self.role_types:
            self._load_from_file(_role)

        #Abort if repo setup is incomplete (e.g. out-of-band signing pending)
        if self.roles[role].signed.version == 0:
            exit_with_error(f"Repo setup incomplete for role:{role}")

        #Keep the backup of original metadata states before changing for validation later
        self.roles_last = deepcopy(self.roles)

        #Update version, expiry and re-sign
        if role == "snapshot":
            self._do_snapshot()
        elif role == "timestamp":
            self._do_timestamp()

        # Validate metadata
        vr = self._get_verification_result(role, self.roles[role])
        if not vr:
            raise ValueError(f"Role {role} failed to verify")

        #Save the updated metadata to file
        self._store_to_file(role)


    def add_targets(self, repo_path :str , file_list :list = []):
        """ Add target files to the repository
            * This needs the respective signer keys to be initialized.

            Args:
               * repo_path: Path of the repository. Defaults to "./tufrepo"
               * file_list: List of files to be added with complete path
            Returns:
               None
        """
        self.repo_path = Path(repo_path).resolve()
        self.targets_dir = Path(self.repo_path).joinpath("targets")
        self.metadata_dir = Path(self.repo_path).joinpath("metadata")

        targets = []
        #Check if list is empty
        if not list:
            exit_with_error("No target files are specified")
        else:
            #Add files absolute path to targets list
            for f in file_list:
                if Path(f).is_file():
                    targets.append(Path(f).resolve())
                else:
                    exit_with_error(f"Non-existent file:{f}")
        #Every transaction is atomic. Read metadata from disk at write back at end of txn
        #No two copies (in-memory vs disk)
        self._clear_repo_cache()

        #Abort if repo setup is incomplete(pending Out-of-band signatures)
        for role in self.role_types:
            self._load_from_file(role)
            if self.roles[role].signed.version == 0:
                exit_with_error(f"Repo setup incomplete for role:{role}")

        #Keep copy of the original version before altering metadata
        self.roles_last = deepcopy(self.roles)

        #_target_prefix = Path(self.targets_dir).name

        self.roles["targets"].signed.targets.clear()

        #Update file info into targets metadata & copy files into targets dir
        for _target_srcpath in targets:
            target_path = Path(_target_srcpath).name
            target_file_info = TargetFile.from_file(target_path, _target_srcpath)
            _target_destpath =  Path(self.targets_dir) / Path(_target_srcpath).name
            self.roles["targets"].signed.targets[str(target_path)] = target_file_info
            shutil.copyfile(_target_srcpath, _target_destpath, follow_symlinks=False)
        #Update metadata version and expiry
        self._update_version("targets")
        # Sign metadata
        for _signer in self.signers["targets"]:
            #TBD: Consider replacing it with _role_sign
            self.roles["targets"].sign(_signer)

        self._do_snapshot()
        self._do_timestamp()

        #Metadata validation
        for role in ( "targets", "snapshot", "timestamp"):
            vr = self._get_verification_result(role, self.roles[role])
            if not vr:
                #TBD: Consider roleback of copied files
                raise ValueError(f"Role {role} failed to verify")

        #Write metadata to file
        for role in ("targets", "snapshot", "timestamp"):
            self._store_to_file(role)

    def _do_snapshot(self):
        """ Updates the snapshot metadata by
            - syncing the targets metadata version
            - bumping the snapshot metadata version
            - updating the snapshot expiry
            The payload is signed my the snapshot signer roles post update.
            Args:
               None
            Returns:
               None
        """
        self.roles['snapshot'].signed.meta['targets.json'].version = self.roles['targets'].signed.version
        self._update_version("snapshot")
        for _signer in self.signers["snapshot"]:
            self.roles["snapshot"].sign(_signer)

    def _do_timestamp(self):
        """ Updates the timestamp metadata by
            - syncing the snapshot metadata version in timestamp.json
            - bumping the timestamp metadata version
            - updating the timestamp expiry
            The payload is signed my the timestamp signer roles post update.
            Args:
               None
            Returns:
               None
        """
        self.roles["timestamp"].signed.snapshot_meta.version = self.roles["snapshot"].signed.version
        self._update_version("timestamp")
        for _signer in self.signers["timestamp"]:
            self.roles["timestamp"].sign(_signer)

    def _clear_repo_cache(self):
        """Clears all previous initializations before fresh update"""

        self.roles = {key: None for key in self.roles}
        #TBD: Add any other attributes requiring a reset

    def _load_from_file(self, role: str):
        """ Reads metadata files from json files and stores into roles caches"""

        md = None
        PRETTY = JSONDeserializer()
        _file_path = Path(self.metadata_dir).joinpath(f"{role}.json")
        try:
            self.roles[role] = Metadata[role].from_file(_file_path, deserializer = PRETTY)
        except Exception as e:
            exit_with_error(f"{type(e).__name__}–{e}")

        if self.roles[role]:
            self.roles_last[role] = deepcopy(self.roles[role])

    def _verify_root_signature(self):
        ''' TBD: experimental method for testing. Remove from the production code'''
        previous = self.roles_last["root"] if self.roles_last["root"] else self.roles["root"]
        current = self.roles["root"]
        return RootVerificationResult(
            previous.signed.get_verification_result("root", current.signed_bytes, current.signatures),
            current.signed.get_verification_result("root", current.signed_bytes, current.signatures),
        )
    def out_of_band_root_sign(self, sig: CryptoSigner, repo_path: str = "./tufrepo"):
        """ Sign the additional root role out of band

            Args:
               sig : Signer object for signing the metadata
               repo_path: Path to the repository. Defaults to "./tufrepo"
            Returns:
               None
        """
        if not Path(repo_path).is_dir():
            exit_with_error(f"repo path is invalid:{repo_path}")
        self.repo_path = Path(repo_path).resolve()
        #self.targets_dir = Path(self.repo_path).joinpath("targets")
        self.metadata_dir = Path(self.repo_path).joinpath("metadata")

        #Read root metadata from file
        self._load_from_file("root")
        #TBD: The following line looks redundant. Verify and remove
        #self.roles["root"].signed.roles["root"].threshold = 2

        #TBD: Public key adding could happen beforehand too.
        #_public_key = sig.public_key
        #self.add_public_key(_public_key, "root")
        _public_key = sig.public_key
        if _public_key.keyid not in self.roles["root"].signed.roles["root"].keyids:
            exit_with_error(f"Key {_public_key.keyid } not found in root metadata")
        #Sign with the extra signer
        self._role_sign("root",extra_signer=sig)

        # TBD: Introduce a role verification block before writing into file
        self._store_to_file("root")

if __name__ == "__main__":
    operation = input("Enter the operation [c=create, t=add target, s = out-of-band sign, a=auto sign]:")
    r = None
    if operation in ('s','S'):
        r = MVRepo()
        key = RSAkey().get_signer(pvtkey_file="./keys/secrets/root-f609b4_private.pem")
        r.out_of_band_root_sign(key,"./tufrepo")

    elif operation in ('c','C'):
        r = MVRepo()
        r.set_signer(role='root', private_key="./keys/secrets/root-2ec8ea_private.pem", encryption="rsa")
        #r.set_signer(role='root',private_key="./keys/secrets/root-f609b4_private.pem", encryption="rsa")
        r.set_signer(role='targets', private_key="./keys/secrets/targets-cd1f1e_private.pem", encryption="rsa")
        r.set_signer(role='snapshot', private_key="./keys/secrets/snapshot-ff6286_private.pem", encryption="rsa")
        r.set_signer(role='timestamp', private_key="./keys/secrets/timestamp-761727_private.pem", encryption="rsa")
        r.set_role_threshold("root", 2)
        root2_public = RSAkey().get_public_key_from_file("./keys/root-f609b4_public.pem")
        r.set_out_of_band_publickey(root2_public, "root")
        r.create()

    elif operation in ("t","T"):
        r = MVRepo()
        r.set_signer(role='targets', private_key="./keys/secrets/targets-cd1f1e_private.pem", encryption="rsa")
        r.set_signer(role='snapshot', private_key="./keys/secrets/snapshot-ff6286_private.pem", encryption="rsa")
        r.set_signer(role='timestamp', private_key="./keys/secrets/timestamp-761727_private.pem", encryption="rsa")
        r.add_targets("./tufrepo", [
                                    "/tmp/manifest.1",
                                    "/tmp/manifest.2",
                                    "/tmp/mvl-support-1.0-1.0.0.corei7_64.rpm",
                                    "/tmp/python3-tuf-manifest-0.0.3-3.4.0.corei7_64.rpm",
                                    "/tmp/python3-tuf-manifest-client-0.0.3-3.4.0.corei7_64.rpm",
                                    "/tmp/python3-tuf-manifest-dev-0.0.3-3.4.0.corei7_64.rpm"
                                    ])

    elif operation in ("a", "A"):
        r = MVRepo()
        _r = input("Choose role (s=snapshot | t=timestamp) :")
        _role = "snapshot" if _r in ('s','S') else ("timestamp" if _r in("t","T") else exit())
        _key= input("Enter signing key full path :")
        r.set_signer(role=_role, private_key=_key, encryption="rsa")
        r.auto_sign(_role)
    else:
        pass

    v = r._verify_root_signature()
    print(v)
    print("OK") if v else print("NOT OK")
    exit()
    #
    #else:
    #    print("False")


    #exit()
    r1 = MVRepo()
    #r1.set_signer(role='root', private_key="./keys/secrets/root-2ec8ea_private.pem", encryption="rsa")
    #r1.set_signer(role='root', private_key="./keys/secrets/root-f609b4_private.pem", encryption="rsa")
    r1.set_signer(role='targets', private_key="./keys/secrets/targets-cd1f1e_private.pem", encryption="rsa")
    r1.set_signer(role='snapshot', private_key="./keys/secrets/snapshot-ff6286_private.pem", encryption="rsa")
    r1.set_signer(role='timestamp', private_key="./keys/secrets/timestamp-761727_private.pem", encryption="rsa")
    r1.add_targets("./tufrepo", ["/home/msatpathy/hello.txt"])

    #r2 = MVRepo()

#   r.set_signer(role='root', public_key="./keys/root-f609b4_public.pem",
#                 private_key= "./keys/secrets/root-f609b4_private.pem", key_type="rsa")