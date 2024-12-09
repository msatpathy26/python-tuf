#!/usr/bin/env python3
import os.path
import shutil
import sys

from key.rsa import RSAkeyGenerator,RSAkey
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer import CryptoSigner


#Decorator to manually run or by pass excution of features
def enable_feature(message :str):
    def _enabler(func):
        def _decider():
            _input = input(f"\nPress 'y' to:{message}..'e' to exit or any other key to continue..\n")
            if _input in ('E','e'):
                sys.exit()
            elif _input in ('Y','y'):
                f = func()
            else:
                f = lambda x: None
                print("Jumping over to the next function..")
            return f
        return _decider
    return _enabler

@enable_feature(message="Run a test print")
def run_test_print():
    print("Inside test print function")

@enable_feature(message="Generate RSA root key pair")
def generate_RSA_root_keypair():
    RSAkeyGenerator(role="root").generate()

@enable_feature(message="Generate RSA targets key pair")
def generate_RSA_targets_keypair():
    RSAkeyGenerator(role="targets").generate()

@enable_feature(message="Generate RSA snapshot key pair")
def generate_RSA_snapshot_keypair():
    RSAkeyGenerator(role="snapshot").generate()

@enable_feature(message="Generate RSA timestamp key pair")
def generate_RSA_timestamp_keypair():
    RSAkeyGenerator(role="timestamp").generate()

@enable_feature(message="Generate extra RSA root key pair")
def generate_RSA_extra_root_keypair():
    RSAkeyGenerator(role="root").generate()

@enable_feature(message="Generate RSA root key signer from private key file")
def get_RSA_root_signer() -> CryptoSigner:
    pvt_key = input("Enter Private key path")
    root_key = RSAkey(privatekey_file=pvt_key)
    #private_key = root_key._import_private_key()
    #public_key = SSlibKey.from_crypto(private_key.public_key())
    root_signer = root_key.get_signer()
    return root_signer
@enable_feature(message="Generate RSA targets key signer from private key file")
def get_RSA_targets_signer() -> CryptoSigner:
    pvt_key = input("Enter Private key path")
    targets_key = RSAkey(privatekey_file=pvt_key)
    #private_key = targets_key._import_private_key()
    #public_key = SSlibKey.from_crypto(private_key.public_key())
    targets_signer = targets_key.get_signer()
    return targets_signer

@enable_feature(message="Generate RSA snapshot key signer from private key file")
def get_RSA_snapshot_signer() -> CryptoSigner:
    pvt_key = input("Enter Private key path")
    snapshot_key = RSAkey(privatekey_file=pvt_key)
    #private_key = targets_key._import_private_key()
    #public_key = SSlibKey.from_crypto(private_key.public_key())
    snapshot_signer = snapshot_key.get_signer()
    return snapshot_signer

@enable_feature(message="Generate RSA timestamp key signer from private key file")
def get_RSA_timestamp_signer() -> CryptoSigner:
    pvt_key = input("Enter Private key path")
    timestamp_key = RSAkey(privatekey_file=pvt_key)
    #private_key = targets_key._import_private_key()
    #public_key = SSlibKey.from_crypto(private_key.public_key())
    timestamp_signer = timestamp_key.get_signer()
    return timestamp_signer

# Run Tests in sequence

run_test_print()
# Generate keys
generate_RSA_root_keypair()
generate_RSA_targets_keypair()
generate_RSA_snapshot_keypair()
generate_RSA_timestamp_keypair()
generate_RSA_extra_root_keypair()

root_signer_1 = get_RSA_root_signer()
targets_signer = get_RSA_targets_signer()
snapshot_signer = get_RSA_snapshot_signer()
timestamp_signer = get_RSA_timestamp_signer()
root_signer_2 = get_RSA_root_signer()




sys.exit()

#pause("\t Generate key pair for root role..\n")
#if INPUT in ['Y','y']:
#    RSAkeyGenerator(role="root").generate()


#RSAkeyGenerator(role="targets").generate()
#RSAkeyGenerator(role="snapshot").generate()
#RSAkeyGenerator(role="timestamp").generate()

pause("\tLoad public and private keys fom file..\n")
root_key = RSAkey(privatekey_file="keys/secrets/root-96c5b9_private.pem",
                            publickey_file="keys/root-96c5b9_public.pem")
private_key = root_key._import_private_key()
#print(type(private_key))
#print(dir(private_key))
#print(type(private_key.public_key()))
pause("\tExtract public key using private key ( method -1 )\n")
public_key1 = SSlibKey.from_crypto(private_key.public_key())
print(public_key1.keyid)
print(public_key1.to_dict())
#print(type(public_key))
#print(dir(public_key))

pause("\tExtract public key directly..( method -2 )\n")
_public_key = root_key._import_public_key()
public_key2 = SSlibKey.from_crypto(_public_key)
print(public_key2.keyid)
print(public_key2.to_dict())

pause("\tGenerate signer using pvt and pub keys..")
signer = root_key.get_signer()
#print(type(signer))
#print(dir(signer))
print((signer.public_key.keyval))
pause("\tSign the string 'Hello World'..")
signature = signer.sign(b"Hello world")
print(signature.to_dict())


#### Repo creation ################

from tuf.api.metadata import (
    SPECIFICATION_VERSION
)

def _in(days: float) -> datetime:
    """Adds 'days' to now and returns datetime object w/o microseconds."""
    return datetime.now(timezone.utc).replace(microsecond=0) + timedelta(
        days=days
    )

def create_bare_repo():
SPEC_VERSION = ".".join(SPECIFICATION_VERSION)
roles: Dict[str, Metadata] = {}
signers: Dict[str, Signer] = {}

os.mkdir("repository/targets")
targets_dir = os.path.join(os.path.curdir + "repository" + "targets")
targets_path = os.path.join(targets_dir, 'test.py')
shutil.copyfile('test.py',dst=targets_path)
local_path = f"{local_path.parts[-2]}/{local_path.parts[-1]}"
target_file_info = TargetFile.from_file(targets_path, str(local_path))

roles["targets"] = Metadata(Targets(expires=_in(7)))
roles["targets"].signed.targets[target_path] = target_file_info

roles["snapshot"] = Metadata(Snapshot(expires=_in(7)))

roles["timestamp"] = Metadata(Timestamp(expires=_in(1)))

roles["root"] = Metadata(Root(expires=_in(365)))







