#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine, tuple_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError

from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Adds a new user into the database
        :param email: String representing the user's email
        :param hashed_password: String representing the encrypted password.
        :return: A new user from the database
        """
        try:
            user = User(email=email, hashed_password=hashed_password)
            self._session.add(user)
            self._session.commit()
        except Exception:
            self._session.rollback()
            user = None
        return user

    def find_user_by(self, **kwargs):
        """
        Finds a user using filters
        :param kwargs: The filters to search for in the database
        :return: A user or none if not found
        """
        fields = []
        values = []

        for key, value in kwargs.items():
            if not hasattr(User, key):
                raise InvalidRequestError()
            fields.append(getattr(User, key))
            values.append(value)

        user = self._session.query(User).filter(
            tuple_(*fields).in_([tuple(values)])
        ).first()

        if user is None:
            raise NoResultFound()

        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Updates a user only if exists
        :param user_id: Integer representing the user id to update.
        :param kwargs: Dictionary containing the attributes to update.
        :return: None
        """
        try:
            user = self.find_user_by(id=user_id)
            if user is None:
                return
            source = {}
            for k, v in kwargs.items():
                if not hasattr(user, k):
                    raise ValueError()
                source[getattr(User, k)] = v
            self._session.query(User).filter(User.id == user_id).update(
                source, synchronize_session=False
            )
            self._session.commit()
        except NoResultFound:
            return
        return
