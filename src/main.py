import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import httpx
import jwt
from fastapi import FastAPI, HTTPException
from fastapi.params import Depends, Security
from fastapi.security import HTTPBearer
from starlette import status

from src.config import PUBLIC_KEYS_URL, ALGORITHM

logger = logging.getLogger("uvicorn")
public_keys: dict[str, str]


async def fetch_public_keys() -> dict[str, str]:
    """
    Fetches public keys from the authentication server via an asynchronous HTTP request.

    Raises:
        httpx.HTTPError: If the request to the authentication server fails.
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(PUBLIC_KEYS_URL)
        return response.json()


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    global public_keys
    public_keys = await fetch_public_keys()
    yield


app = FastAPI(lifespan=lifespan)


async def jwt_auth(token: Security(HTTPBearer)) -> None:
    """
    Performs JWT authentication for incoming requests.

    This function extracts the JWT token from the request, verifies its signature using a public key,
    and checks that it is an access token. If any validation step fails, an HTTP 401 Unauthorized
    exception is raised.

    Args:
        token: The JWT token extracted from the request headers.

    Raises:
        HTTPException: If the token is expired, invalid, or does not have the correct type.
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
        key_id = unverified_header["kid"]
        public_key = await get_public_key(key_id)
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])

        if payload["type"] != "access":
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token type: expected 'access', got '{payload["type"]}'"
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except (jwt.PyJWTError, KeyError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


async def get_public_key(key_id: str) -> str:
    """
    Retrieves the public key associated with the given key_id.

    If the key_id is not found in the cached public keys, the function fetches
    the latest public keys asynchronously. If the key_id is still not found
    after updating, an HTTP 401 Unauthorized exception is raised.
    """
    global public_keys

    if key_id not in public_keys:
        public_keys = await fetch_public_keys()
    if key_id not in public_keys:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid key id")
    return public_keys[key_id]


@app.post("/protected",
          summary="Protected api",
          description="This endpoint is protected and requires authentication a valid JWT token",
          dependencies=[Depends(jwt_auth)])
async def index() -> Any:
    logger.info("Accessed protected API")
