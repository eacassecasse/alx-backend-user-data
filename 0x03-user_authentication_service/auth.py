#!/usr/bin/env python3
""" This module works with user authentication. """
import uuid
from typing import Union

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt with gensalt.
    :param password: The password to encrypt.
    :return: Bytes representing the encrypted password.
    """
    pwd = password.encode('utf-8')
    return bcrypt.hashpw(pwd, bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    Creates a unique UUID
    :return: a String representing the UUID
    """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """
        Initializes the authentication model.
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a new user into the database if not exists.
        :param email: String representing the user's email.
        :param password: String representing the user's raw password.
        :return: The new created user.
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        raise ValueError("User {} already exists".format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validates user credentials
        :param email: String representing user's email
        :param password: String representing user's password
        :return: True if valid, False otherwise
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                return bcrypt.checkpw(
                    password.encode('utf-8'),
                    user.hashed_password
                )
        except NoResultFound:
            return False
        return False

    def create_session(self, email: str)-> str:
        """
        Creates a new session for a user identified by an email.
        :param email: The current user email
        :return: The new session ID
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        if user is None:
            return None
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """
        Retrieves a user based on the session id
        :param session_id: The String representing a session id
        :return: A user if one is found, None otherwise
        """
        user = None
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """
        Destroys the current session of a user
        :param user_id: Integer representing the user identifier
        :return: None
        """
        if user_id is None:
            return None
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """
        Retrieves a reset token to update user's password.
        :param email: String representing the user email
        :return: The user reset token
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError()
        if user is None:
            raise ValueError()
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Updates the user password using the reset token
        :param reset_token: String representing the reset token
        :param password: String representing the raw password
        :return: None
        """
        user = None
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError()
        hashed_pwd = _hash_password(password)
        self._db.update_user(
            user.id,
            hashed_password=hashed_pwd,
            reset_token=None
        )
