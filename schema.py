"""
This module defines the Pydantic models used for authentication and user management.
"""

from typing import Optional
from pydantic import BaseModel


class Token(BaseModel):
    """
    Represents a JWT access token.
    
    Attributes:
        access_token (str): The JWT access token string.
        token_type (str): The type of token, typically "bearer".
    """
    access_token: str
    token_type: str


class TokenData(BaseModel):
    """
    Represents the data stored within a JWT token.
    
    Attributes:
        username (str): The username associated with the token.
        full_name (Optional[str]): The full name of the user (if available).
        email (Optional[str]): The email address of the user (if available).
        disabled (Optional[bool]): Whether the user account is disabled.
    """
    username: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    disabled: Optional[bool] = None


class User(BaseModel):
    """
    Represents a basic user model.
    
    Attributes:
        username (str): The unique username of the user.
        full_name (Optional[str]): The full name of the user (if available).
        email (Optional[str]): The email address of the user (if available).
        disabled (Optional[bool]): Whether the user account is disabled.
    """
    username: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    """
    Represents a user model stored in the database.
    
    Extends:
        User (BaseModel): Inherits basic user attributes.
    
    Attributes:
        hashed_password (str): The hashed password of the user.
    """
    hashed_password: str
