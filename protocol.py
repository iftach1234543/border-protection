"""
Author: Iftach Kasorla
Date: 3/6/25
Description: communication protocol. the protocol contains a 3 digit length (send as a string) followed by the message
"""
import socket
from crypto_base import CryptoBase

LEN_LEN = 1000


def calculate_checksum(data: bytes) -> str:
    """
    Calculates a simple checksum for a given byte string.

    Args:
        data: The byte string to calculate the checksum for.

    Returns:
        The calculated checksum as an integer.
    """
    checksum = 0
    for byte in data:
        checksum = (checksum + byte) & 0xFF  # Keep within 8 bits

    return str(checksum)


def encrypt_and_send_msg(msg: bytes, comm: socket.socket, enc_dec: CryptoBase) -> None:
    """
    send the passed message over the socket within the described protocol
    :param msg: the message to send
    :param comm: the socket to send the message over
    :param enc_dec: the rsa protocol instance
    :return: None
    """
    checksum = calculate_checksum(msg)
    msg = msg.decode()
    msg = checksum + '{' + msg
    cipher_msg = enc_dec.encrypt(msg.encode())

    return send_msg(cipher_msg, comm)


def send_msg(msg: bytes, comm: socket.socket) -> None:
    """
    send the passed message over the socket within the described protocol
    :param msg: the message to send
    :param comm: the socket to send the message over
    :return: None
    """

    msg_len = len(msg)

    actual_lmsg = str(msg_len).zfill(LEN_LEN).encode() + msg
    comm.sendall(actual_lmsg)


def recv_encrypted_msg(comm: socket.socket, dec: CryptoBase) -> bytes:
    """
    receive a message from the socket within the described protocol and decrypt it with the passed rsa_protocol
    :param comm: the socket to receive the message
    :param dec: the decrypt object to decrypt with
    :return: the received message as bytes
    """
    msg = recv_msg(comm)
    if msg != b'':
        msg = dec.decrypt(msg)
    return msg


def recv_msg(comm: socket.socket) -> bytes:
    """
    receive a message from the socket within the described protocol
    :param comm: the socket to receive the message
    :return: the received message as bytes
    """
    msg_len = ''
    while len(msg_len) < LEN_LEN:
        tmp = comm.recv(LEN_LEN - len(msg_len))
        if not tmp:
            msg_len = 0
            break
        msg_len += tmp.decode()
    msg = b''
    while len(msg) < int(msg_len):
        tmp = comm.recv(int(msg_len) - len(msg))
        if not tmp:
            msg = b''
            break
        msg += tmp
    return msg


def is_checksum(chk: str, data) -> bool:
    if isinstance(data, str):
        data = data.encode()
    if chk == calculate_checksum(data):
        return True
    else:
        return False
