"""
Author: Iftach Kasorla
Date: 3/6/25
Description: a simple AES encryption/decryption class
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from crypto_base import CryptoBase


class MyAES(CryptoBase):
    KEY_SIZE = 32

    def __init__(self, key: bytes = None):
        self.key = key
        if key is None:
            self.key = get_random_bytes(self.KEY_SIZE)
        else:
            if len(key) not in [16, 24, 32]:
                raise ValueError("AES key must be 16, 24, or 32 bytes long")

    def export_key(self):
        """
        export the encryption key as a byte string
        :return: the key as a byte string
        """
        return self.key

    def encrypt(self, text: bytes) -> bytes:
        """
        encrypt the passed message
        :param text: the message to be encrypted
        :return: the encrypted message bytes
        """
        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(text)
        return nonce + ciphertext

    def decrypt(self, cipher_text: bytes,) -> bytes:
        """
        decrypt the passed ciphertext
        :param cipher_text: the cipher to decrypt
        :return: the decrypted message bytes
        """
        nonce = cipher_text[:16]
        cipher_text = cipher_text[16:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt(cipher_text)


if __name__ == '__main__':
    aes = MyAES()
    msg = input("please input a message to be encrypted: ")
    encrypted = aes.encrypt(msg.encode())
    print("base64 encrypt: ", base64.b64encode(encrypted).decode())
    print("the decrypted message is: ", aes.decrypt(encrypted).decode())
    print('------------------------------------')
    print('now with an external key')
    aes = MyAES(get_random_bytes(16))
    msg = input("please input a message to be encrypted: ")
    encrypted = aes.encrypt(msg.encode())
    print("base64 encrypt: ", base64.b64encode(encrypted).decode())
    print("the decrypted message is: ", aes.decrypt(encrypted).decode())
