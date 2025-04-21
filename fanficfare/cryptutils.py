# Copyright 2013 Fanficdownloader team, 2020 FanFicFare team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import absolute_import
from .six import ensure_binary
import hashlib, base64

import logging
logger = logging.getLogger(__name__)

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util import Counter
    _CRYPTODOME_AVAILABLE = True
except ImportError as e:
    _CRYPTODOME_AVAILABLE = False

class CryptConfig(object):
    def __init__(self, key=None):
        # key (str): The user's password that the string will be encrypted with.
        if key == None:
            self.initialized = False
            logger.debug("No key specified!")
        else:
            self.initialized = _CRYPTODOME_AVAILABLE

        self.key = key
        self.nonce_lenght = 12
        self.salt_lenght = 16
        self.key_lenght = 32
        self.tag_length = 32
        self.counter_lenght = 128

    # pick the fastest bytes>int
    if hasattr(int, 'from_bytes'):
        @staticmethod
        def bytes_to_int(b):
            # Py3 int.from_bytes is implemented in C
            return int.from_bytes(b, byteorder='big')
    else:
        @staticmethod
        def bytes_to_int(b):
            # fallback for Py2
            result = 0
            for char in b:
                result = (result << 8) + (char if isinstance(char, int) else ord(char))
            return result

    def get_encrypted(self, value, default='', key=None, nonce_lenght=12, salt_lenght=16, key_lenght=32, counter_lenght=128):
        """
        Decrypts a base64-encoded string that was encrypted using AES-CTR with a derived key. (SHA-256 hash of the ciphertext for integrity verification)

        Args:
            value (str): The base64-encoded encrypted string (nonce + salt + tag + ciphertext).
            default (str, optional): The value to return if decryption fails. Defaults to an empty string.
            key (str, optional): The decryption key. If None, uses `self.key`.
            tag_length (int, optional): Length of the SHA-256 tag in bytes. Defaults to 32.
            nonce_lenght (int, optional): Length of the nonce in bytes. Defaults to 12.
            salt_lenght (int, optional): Length of the salt in bytes. Defaults to 16.
            key_lenght (int, optional): Length of the derived key in bytes. Defaults to 32.
            counter_lenght (int, optional): Bit length of the AES CTR counter. Defaults to 128.

        Returns:
            str: The decrypted plaintext string if successful; otherwise, returns the `default` value.
        """
        if not self.initialized:
            logger.debug("Not initialized, unable to proceed with encryption.")
            return default
        if key is None:
            key = self.key
        try:
            nonce = get_random_bytes(nonce_lenght)
            salt = get_random_bytes(salt_lenght)
            init_counter = self.bytes_to_int(nonce)

            ctr = Counter.new(counter_lenght, prefix=b'', initial_value=init_counter)
            encr_key = hashlib.pbkdf2_hmac('sha512', ensure_binary(key), salt, 210000, dklen=key_lenght)
            # PBKDF2(self.key, salt, dkLen=self.key_lenght, count=250000) # Crypto PBKDF2 is very slow on calibre 2.85.1
            #cipher = AES.new(encr_key, AES.MODE_GCM, nonce=nonce) # MODE_GCM is not supported on calibre 2.85.1
            #ciphertext, tag = cipher.encrypt_and_digest(pad(value.encode('utf-8'), AES.block_size)) # GCM tag length is 16 bytes
            cipher = AES.new(encr_key, AES.MODE_CTR, counter=ctr)
            ciphertext = cipher.encrypt(value.encode('utf-8'))

            tag = hashlib.sha256(ciphertext).digest()

            encrypted_blob = nonce + salt + tag + ciphertext
            default = base64.b64encode(encrypted_blob).decode('utf-8') # Return the nonce, salt, tag and ciphertext, all base64 encoded
        except Exception as e:
            logger.debug("Failed to encrypt credential: "+str(e))

        return default

    def get_decrypted(self, value, default='', key=None, tag_length=32, nonce_lenght=12, salt_lenght=16, key_lenght=32, counter_lenght=128):
        """
        Decrypts a base64-encoded encrypted string (which contains salt + nonce + tag + ciphertext).
        Args:
            value (str): The encrypted string encoded in base64.
            default (str, optional): The value to return if decryption fails. Defaults to an empty string.
            key (str, optional): The decryption key to use. If None, uses self.key.
        Returns:
            str: The decrypted string if successful; otherwise, returns the default value.
        """
        if not self.initialized:
            logger.debug("Not initialized, unable to proceed with decryption")
            return default
        if key is None:
            key = self.key
        try:
            enc = base64.b64decode(value)

            # Extract components: salt | nonce | tag | ciphertext
            #nonce = enc_credential[:self.nonce_lenght]
            #salt = enc_credential[self.nonce_lenght:(self.nonce_lenght+self.salt_lenght)]
            #tag = enc_credential[(self.nonce_lenght+self.salt_lenght):(self.nonce_lenght+self.salt_lenght+self.tag_length)]
            #ciphertext = enc_credential[(self.nonce_lenght+self.salt_lenght+self.tag_length):]
            nl, sl, tl = nonce_lenght, salt_lenght, tag_length
            nonce = enc[0:nl]
            salt = enc[nl:nl+sl]
            tag  = enc[nl+sl:nl+sl+tl]
            ciphertext = enc[nl+sl+tl:]

            if hashlib.sha256(ciphertext).digest() != tag:
                raise ValueError("Integrity check failed: tag does not match.")

            init_counter = self.bytes_to_int(nonce)
            ctr = Counter.new(counter_lenght, prefix=b'', initial_value=init_counter)
            dec_key = hashlib.pbkdf2_hmac('sha512', ensure_binary(key), salt, 210000, dklen=key_lenght)
            # PBKDF2(self.key, salt, dkLen=self.key_lenght, count=250000)
            #cipher = AES.new(dec_key, AES.MODE_GCM, nonce=nonce)
            #plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size) # Decrypt and verify the message. If verification fails, a ValueError will be raised.
            plaintext = AES.new(dec_key, AES.MODE_CTR, counter=ctr).decrypt(ciphertext)
            default = plaintext.decode('utf-8')
        except Exception as e:
            logger.debug("Failed to decrypt credential: %s"%str(e))

        return default