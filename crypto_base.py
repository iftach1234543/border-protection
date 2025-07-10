"""
Author: Nir Dweck
Date: 24/10/24
Description: an interface for encryption and decryption
"""

import abc


class CryptoBase:
    """
    a base class for the cryptography module
    """
    @abc.abstractmethod
    def encrypt(self, message: bytes) -> bytes:
        pass

    @abc.abstractmethod
    def decrypt(self, cipher_text: bytes) -> bytes:
        pass
