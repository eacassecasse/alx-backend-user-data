#!/usr/bin/env python3
""" This module works with user authentication. """
import uuid

import bcrypt
from db import DB
from user import User
from sqlalchemy.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt with gensalt.
    :param password: The password to encrypt.
    :return: Bytes representing the encrypted password.
    """
    pwd = password.encode('utf-8')
    return bcrypt.hashpw(pwd, bcrypt.gensalt())


def _generate_uuid():
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
            if self._db.find_user_by(**{'email': email}) is not None:
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_pwd = _hash_password(password).decode('utf-8')
            return self._db.add_user(email, hashed_pwd)

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validates user credentials
        :param email: String representing user's email
        :param password: String representing user's password
        :return: True if valid, False otherwise
        """
        try:
            user = self._db.find_user_by(**{'email': email})
            if user is not None:
                return bcrypt.checkpw(
                    password.encode('utf-8'),
                    user.hashed_password
                )
        except NoResultFound:
            return False

    def create_session(self, email: str):
        """
        Creates a new session for a user identified by an email.
        :param email: The current user email
        :return: The new session ID
        """
        try:
            user = self._db.find_user_by(**{'email': email})
            session_id = _generate_uuid()
            self._db.update_user(user.id, **{'session_id': session_id})
            updated_user = self._db.find_user_by(**{'email': email})
            return updated_user.session_id
        except NoResultFound:
            return

    def get_user_from_session_id(self, session_id: str):
        """
        Retrieves a user based on the session id
        :param session_id: The String representing a session id
        :return: A user if one is found, None otherwise
        """
        try:
            return self._db.find_user_by(**{'session_id': session_id})
        except NoResultFound:
            return

    def destroy_session(self, user_id: int) -> None:
        """
        Destroys the current session of a user
        :param user_id: Integer representing the user identifier
        :return: None
        """
        try:
            user = self._db.find_user_by(**{'id': user_id})
            session_id = None
            self._db.update_user(user.id, **{'session_id': session_id})
            return
        except NoResultFound:
            return

    def get_reset_password_token(self, email: str) -> str:
        """
        Retrieves a reset token to update user's password.
        :param email: String representing the user email
        :return: The user reset token
        """
        try:
            user = self._db.find_user_by(**{'email': email})
            reset_token = _generate_uuid()
            self._db.update_user(user.id, **{'reset_token': reset_token})
            updated_user = self._db.find_user_by(**{'email': email})
            return updated_user.reset_token
        except NoResultFound:
            raise ValueError()

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Updates the user password using the reset token
        :param reset_token: String representing the reset token
        :param password: String representing the raw password
        :return: None
        """
        try:
            user = self._db.find_user_by(**{'reset_token': reset_token})
            hashed_pwd = _hash_password(password)
            self._db.update_user(
                user.id,
                **{'hashed_password': hashed_pwd, 'reset_token': None})
            return
        except NoResultFound:
            raise ValueError()
