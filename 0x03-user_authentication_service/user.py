#!/usr/bin/env python3
""" This module defines a SQLAlchemy user model. """
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String

Base = declarative_base()


class User(Base):
    """
    A User model representing a table on the database.

    Attributes:
        `id`: Unique identifier for the user
        `email`: Email address of the user
        `hashed_password`: The hash representation of the password
        `session_id`: Unique id for the session associated with the user
        `reset_token`: Unique id for the reset token associated with the user
    """
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), unique=True, nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)

