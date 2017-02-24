#!/usr/bin/python
# coding: utf8
"""
List of the custom exceptions
"""

__all__ = [
    'NoRemainingHashException',
    'OutOfMemoryException',
    'RevokedTaskException',
]


class NoRemainingHashException(Exception):
    """
        All the hashes has been found
    """


class OutOfMemoryException(Exception):
    """
        Out of memory exception
    """


class RevokedTaskException(Exception):
    """
        This task has been revoked or aborted
    """
