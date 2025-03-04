"""
This module handles security-related functionality including password hashing,
user authentication, and JWT token generation.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from passlib.context import CryptContext
import bcrypt
from schema import TokenData, User, UserInDB

# Ensure bcrypt.__about__ exists to avoid compatibility issues with Passlib
if not hasattr(bcrypt, "__about__"):
    try:
        setattr(
            bcrypt, "__about__", type("about", (object,), {"__version__": getattr(bcrypt, "__version__", "unknown")})
        )
    except AttributeError:
        pass  # In case bcrypt.__version__ does not exist, we skip setting __about__


# Securely storing the secret key using environment variables
# SECRET_KEY = os.getenv("SECRET_KEY", "change_this_secret_key_in_production")
SECRET_KEY = "ab01c0c532266499873abefeaa2d661aed936bc4950c1a405d1fb44b421aeb76"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


db = {
    "admin": {
        "username": "admin",
        "hashed_password": "$2b$12$iqpUOBiFZMA1DQNxbhPuCObwMeSDhJE6CHgqKuz/F6fZXT7my6P1q", # password is test
        "full_name": "Admin",
        "email": "admin@example.com",
        "disabled": False,
    }
}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain-text password against a hashed password using the configured password hashing context.

    Args:
        plain_password (str): The plain-text password to verify.
        hashed_password (str): The hashed password to compare against.

    Returns:
        bool: True if the plain-text password matches the hashed password, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Generates a hashed password using the configured password hashing context.

    Args:
        password (str): The plain-text password to hash.

    Returns:
        str: The hashed password.
    """
    return pwd_context.hash(password)


def get_user(db: dict, username: str) -> UserInDB | None:
    """
    Retrieves a user from the provided database by their username.

    Args:
        db (dict): The database containing user information.
        username (str): The username of the user to retrieve.

    Returns:
        UserInDB | None: The user object if the user is found, otherwise None.
    """
    user_dict = db.get(username)
    if user_dict:
        return UserInDB(**user_dict)
    return None


def authenticate_user(db: dict, username: str, password: str) -> User | None:
    """
    Authenticates a user by verifying their password.

    Args:
        db (dict): The database containing user information.
        username (str): The username of the user to authenticate.
        password (str): The plain-text password to verify.

    Returns:
        UserInDB | bool: The authenticated user object if credentials are correct, False otherwise.
    """
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
) -> str:
    """
    Creates a JWT access token with an expiration time.

    Args:
        data (dict): The payload data to encode into the token.
        expires_delta (timedelta, optional): The duration until the token expires. Defaults to 15 minutes.

    Returns:
        str: The encoded JWT token.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    """
    Retrieves the current user based on the provided JWT token.

    Args:
        token (str): The JWT token obtained from the request.

    Returns:
        UserInDB: The user object if the token is valid.

    Raises:
        HTTPException: If the token is invalid or the user is not found.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired, please login again.")
    except jwt.DecodeError:
        raise HTTPException(status_code=401, detail="Invalid token, could not decode.")
    except Exception as exep:
        raise credentials_exception from exep

    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    """
    Retrieves the current active user.

    Args:
        current_user (UserInDB): The current user object.
        Depends(get_current_user): A dependency to retrieve the current user.

    Returns:
        UserInDB: The current active user.

    Raises:
        HTTPException: If the user is disabled.
    """
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
