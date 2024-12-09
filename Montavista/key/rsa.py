#!/usr/bin/env python3
# Copyright Montavista Software LLC.

"""
RSA key generation implementation
"""

from key.key_manager import KeyGeneratorInterface, KeyImportInterface, KeyType
from securesystemslib.signer import CryptoSigner
from securesystemslib.signer._key import Key, SSlibKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    load_pem_private_key,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKey,
    RSAPrivateKey
)
from pathlib import Path

import os

from log import exit_with_error

class RSAkeyGenerator(KeyGeneratorInterface):
    '''
    This class implements RSA key generation.
    '''
    def __init__(self,
                 role: str,
                 key_size : int = 2048,
                 key_name : str = "",
                 key_dir : str = "",
                 password :bool = False):

        super().__init__(role, key_size, key_name, key_dir, password)

    def generate(self):
        """
        key generation method for RSA key pair. Generates and writes the
        keys into files according to settings specified by class parameters.

        Args: None
        Returns: None
        """

        new_key = CryptoSigner.generate_rsa(size=self.key_size)

        if not new_key:
            exit_with_error("Key generation failed")

        if not self.key_name:
            self.key_name = self.__generate_random_key_name(new_key)

        self.__write_keys_to_file(new_key)

    def __generate_random_key_name(self, key :CryptoSigner, length :int = 6):
        """
        Generate a random string, append to the role name and return
        as a key file name
        """
        key_string = str(key._public_key.keyid)[:length]
        return f"{self.role}-{key_string}"

    def __write_keys_to_file(self, key :CryptoSigner):
        """
        internal function used to write keys to files.
        """

        #write public key
        public_file = os.path.join(self.key_dir, f"{self.key_name}_public.pem")
        try:
            os.makedirs(self.key_dir, exist_ok=True)
            with open(public_file, "wb") as f:
                public_bstr = bytes(key.public_key.to_dict()['keyval']['public'],
                                                                             'utf-8')
                print(f"Writing public key to {public_file}")
                f.write(public_bstr)
        except Exception as e:
            exit_with_error(f"{type(e).__name__}:{e}")

        #write private key
        private_dir = os.path.join(self.key_dir, "secrets")
        private_file = os.path.join(private_dir, f"{self.key_name}_private.pem")
        try:
            os.makedirs(private_dir, exist_ok=True)
            with open(private_file, "wb") as f:
                print(f"Writing private key to {private_file}")
                f.write(key.private_bytes)
        except Exception as e:
            #rollback public file if private file writing fails
            os.remove(public_file)
            exit_with_error(f"{type(e).__name__}–{e}")

class RSAkey(KeyImportInterface):

    def __read_bytes_from_keyfile(self, key_type :KeyType, keyfile_path :str):
        _key = None
        try:
            if key_type == KeyType.PUBLIC:
                with open(keyfile_path, "rb") as _pubkey_file:
                    _key = serialization.load_pem_public_key(_pubkey_file.read())

            if key_type == KeyType.PRIVATE:
                #To be implemented
                _password = None
                with open(keyfile_path, "rb") as _pvtkey_file:
                    _key = load_pem_private_key(_pvtkey_file.read(), _password)
        except Exception as e:
            exit_with_error(f"{type(e).__name__}–{e}")
        return _key

    def _import_public_key(self, publickey_file: str) -> RSAPublicKey:
        #Set filepath attribute if passed as parameter
        if os.path.isfile(publickey_file):
            publickey_file = Path(publickey_file).resolve()
        #Extract public key and return the same
        public_key = self.__read_bytes_from_keyfile(KeyType.PUBLIC, publickey_file)
        return public_key

    def _import_private_key(self, privatekey_file: str) -> RSAPrivateKey:
        if not Path(privatekey_file).is_file():
            exit_with_error(f"Private key file doesn't exist at:{privatekey_file}")
        _pvt_key = self.__read_bytes_from_keyfile(KeyType.PRIVATE, privatekey_file)
        #rsa_pvt_key = cast(RSAPrivateKey, _pvt_key)
        return _pvt_key

    def get_signer(self, pvtkey_file: str, pubkey_file :str = "") -> CryptoSigner:

        if not Path(pvtkey_file).is_file():
            exit_with_error(f"Private key file not found:{pvtkey_file}")

        private_key = self._import_private_key(pvtkey_file)

        if pubkey_file:
            _public_key  = self._import_public_key(pubkey_file)
        else:
            _public_key = private_key.public_key()
        public_key = SSlibKey.from_crypto(_public_key)

        return CryptoSigner(private_key, public_key)

    def get_public_key_from_file(self, public_file: str = ""):
        _public_key = self._import_public_key(public_file)
        return SSlibKey.from_crypto(_public_key)

    def get_public_key(self, signer: CryptoSigner):
        return  signer.public_key.to_dict()