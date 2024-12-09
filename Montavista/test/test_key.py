#!/usr/bin/env python3
import  sys
import  os
import shutil

from Montavista.key.rsa import RSAkeyGenerator

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import pytest
import key.rsa


class TestKeyGeneration:
    def setup_class(self):
        if os.path.isdir("./temp"):
            shutil.rmtree("./temp")
        os.mkdir("./temp")

    def teardown_class(self):
        if os.path.isdir("./temp"):
            shutil.rmtree("./tmp")

    @pytest.mark.parametrize("'role, key_size, key_type',
                             [('root','targets','snapshot','timestamp'),
                              (1024,2048,3072),
                              ('rsa','ecdsa','ed25519')
                             ]")
    def test_generate_key(self):
        