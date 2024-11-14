#!/usr/bin/env python3
"""This module defines a function for filtering log data."""

import logging
import os
import re
import mysql.connector


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def filter_datum(fields, redaction, message, separator):
    """
    Obfuscates specified fields in a log message.

    :param fields: List of strings representing fields to obfuscate
    :param redaction: String representing what to replace the field value with
    :param message: String representing the log message
    :param separator: String by which fields in the message are separated
    :return: The obfuscated log message as a string
    """
    pattern = r'({})=([^{}]+)'.format(
        '|'.join(map(re.escape, fields)),
        re.escape(separator)
    )
    return re.sub(pattern, lambda m: f"{m.group(1)}={redaction}", message)


def get_logger() -> logging.Logger:
    log = logging.getLogger("user_data")
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    log.setLevel(logging.INFO)
    log.propagate = False
    log.addHandler(handler)
    return log


def get_db() -> mysql.connector.connection.MySQLConnection:
    host = os.environ.get("PERSONAL_DATA_DB_HOST", "localhost")
    db = os.environ.get("PERSONAL_DATA_DB_NAME", "")
    username = os.environ.get("PERSONAL_DATA_DB_USERNAME", "root")
    pwd = os.environ.get("PERSONAL_DATA_DB_PASSWORD", "")

    return mysql.connector.connect(
        host=host,
        port=3306,
        user=username,
        password=pwd,
        database=db,
    )


def main():
    connection = get_db()
    logger = get_logger()
    fields = 'name,email,phone,ssn,password,ip,last_login,user_agent'
    query = "SELECT {} FROM users".format(fields)
    cols = fields.split(',')
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            rec = (f"{col}={val}" for col, val in zip(cols, row))
            msg = f"{'; '.join(rec)};"
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            logger.handle(logging.LogRecord(*args))


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        msg = super(RedactingFormatter, self).format(record)
        return filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)


if __name__ == '__main__':
    main()
