#!/usr/bin/env python3
""" This module is used to encrypt passwords using bcrypt lib. """

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt with gensalt
    :param password: String representing the password to encrypt
    :return: Bytes representing the encrypted password
    """
    pwd = password.encode('utf-8')
    return bcrypt.hashpw(pwd, bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Checks whether a password matchs a hash or not
    :param hashed_password: Bytes representing the encrypted password
    :param password: String representing a password to check
    :return: True if the password matches, False otherwise
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
