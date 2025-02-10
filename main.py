import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import httpx
import jwt
from fastapi import FastAPI, HTTPException
from fastapi.params import Depends, Security
from fastapi.security import HTTPBearer
from starlette import status


logger = logging.getLogger("uvicorn")
ALGORITHM: str = "RS256"

async def fetch_public_keys() -> dict[str, str]:
    async with httpx.AsyncClient() as client:
        get_public_keys_url = "http://127.0.0.1:8000/public-keys"
        response = await client.post(get_public_keys_url)
        return response.json()

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    global public_keys
    public_keys = await fetch_public_keys()

    yield

app = FastAPI(lifespan=lifespan)

public_keys: dict[str, str]

async def jwt_auth(token: Security(HTTPBearer)) -> None:
    try:
        unverified_header = jwt.get_unverified_header(token)
        key_id = unverified_header["kid"]
        logger.debug(f"public key id: {key_id}")
        public_key = await get_public_key(key_id)
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])

        if payload["type"] != "access":
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token type: expected 'access', got '{payload["type"]}'"
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except KeyError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

async def get_public_key(key_id: str) -> str:
    global public_keys

    if key_id not in public_keys:
        public_keys = await fetch_public_keys()
    if key_id not in public_keys:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid key id")
    return public_keys[key_id]


@app.post("/protected",
         summary="Protected api",
         dependencies=[Depends(jwt_auth)])
async def index() -> Any:
    logger.info("Accessed protected API")
