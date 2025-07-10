"""
Author: Iftach Kasorla
Date: 3/6/25
Description: a simple RSA encryption/decryption class
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from crypto_base import CryptoBase


class MyRSA(CryptoBase):
    KEY_LEN = 2048

    def __init__(self):
        """
        initialize the RSA key
        """
        self.key = RSA.generate(self.KEY_LEN)

    @staticmethod
    def encrypt_with_key(message: bytes, p_key: bytes) -> bytes:
        """
        encrypt the passed message with the passed key
        :param message: the message to be encrypted
        :param p_key: the key used to encrypt the message
        :return: the encrypted message bytes
        """
        key = RSA.import_key(p_key)
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(message)

    def encrypt(self, message: bytes) -> bytes:
        """
        encrypt the passed message
        :param message: the message to be encrypted
        :return: the encrypted message bytes
        """
        cipher = PKCS1_OAEP.new(self.key.publickey())
        return cipher.encrypt(message)

    def decrypt(self, cipher_text: bytes) -> bytes:
        """
        decrypt the passed ciphertext
        :param cipher_text: the cipher to decrypt
        :return: the decrypted message bytes
        """
        cipher = PKCS1_OAEP.new(self.key)
        return cipher.decrypt(cipher_text)

    def export_public_key(self) -> bytes:
        """
        export the public key as bytes
        :return:
        """
        return self.key.publickey().exportKey()


if __name__ == '__main__':
    rsa = MyRSA()
    msg = input("please input a message to be encrypted: ")
    encrypted = rsa.encrypt(msg.encode())
    print("base64 encrypt: ", base64.b64encode(encrypted))
    print("the decrypted message is: ", rsa.decrypt(encrypted))
