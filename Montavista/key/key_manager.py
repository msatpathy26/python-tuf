#!/usr/bin/env python3
# Copyright Montavista Software LLC.

"""
Common Interface for key generation
"""

from abc import ABCMeta, abstractmethod
from securesystemslib.signer import CryptoSigner
from log import exit_with_error
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes
)

from enum import Enum
import os

class KeyType(Enum):
    PRIVATE = 0,
    PUBLIC = 1
class KeyGeneratorInterface(metaclass=ABCMeta):
    '''

    Extend this abstract into individual implementations for generating
    various keys(RSA, ECDSA, ED25519 etc).

    The generate() method needs to be implemented as per individual
    key generation requirements.

    '''
    def __init__(self,
                 role: str,
                 key_size : int = 2048,
                 key_name : str = "",
                 key_dir : str = "",
                 password :bool = False ):

        self.key_size = key_size
        self.role = role if role in ("root", "targets", "snapshot" ,"timestamp") \
                          else _exit_with_error("Role not defined !!")
        #if keyname is empty, we can create it using role name
        self.key_name = key_name
        self.key_dir = key_dir
        self.password_option = password

    @abstractmethod
    def generate(self):
        """Method for generating and stroring key.
        Need to be implemented for different key generation process"""

        raise NotImplementedError

class KeyImportInterface(metaclass=ABCMeta):
    @abstractmethod
    def _import_public_key(self, privatekey_file: str) -> PublicKeyTypes:
        raise NotImplementedError
    @abstractmethod
    def _import_private_key(self, publickey_file: str) -> PrivateKeyTypes:
        raise NotImplementedError
    def get_signer(self):
        raise NotImplementedError
