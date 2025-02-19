import logging
import random
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import httpx
import jwt
from fastapi import FastAPI, HTTPException
from fastapi.params import Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette import status

from src.config import PUBLIC_KEYS_URL, ALGORITHM

logger = logging.getLogger("uvicorn")
public_keys: dict[str, str]

num_users = 10
num_orders_per_user = 5

fake_users: list[dict[str, Any]] = []
fake_orders: list[dict[str, Any]] = []

def generate_fake_users(num_users: int):
    first_names = ["John", "Jane", "Alice", "Bob", "Patrick", "Sandy", "Tom", "Jerry", "Chris", "Anna"]
    last_names = ["Smith", "Doe", "Johnson", "Brown", "Davis", "Miller", "Wilson", "Taylor", "Anderson", "Thomas"]

    users = []
    for user_id in range(num_users):  # ID начинается с 0
        first_name = random.choice(first_names)
        last_name = random.choice(last_names)
        username = f"{first_name.lower()}.{last_name.lower()}{random.randint(1, 100)}"  # Генерация уникального имени пользователя
        email = f"{username}@example.com"  # Формат email
        users.append({
            "id": user_id,  # Уникальный ID
            "username": username,
            "email": email
        })
    return users

def generate_fake_orders(users: list[dict[str, Any]], num_orders_per_user: int):
    products = ["Laptop", "Smartphone", "Tablet", "Headphones", "Charger"]
    orders = []

    for user in users:
        for _ in range(random.randint(1, num_orders_per_user)):  # Каждый пользователь может иметь от 1 до num_orders_per_user заказов
            order = {
                "order_id": str(uuid.uuid4()),  # Генерация уникального идентификатора заказа
                "user_id": user["id"],  # Привязка заказа к id пользователя
                "product": random.choice(products),
                "quantity": random.randint(1, 3),  # Случайное количество от 1 до 3
                "price": round(random.uniform(10.0, 500.0), 2)  # Случайная цена от 10 до 500
            }
            orders.append(order)

    return orders

async def fetch_public_keys() -> dict[str, str]:
    """
    Fetches public keys from the authentication server via an asynchronous HTTP request.

    Raises:
        httpx.HTTPError: If the request to the authentication server fails.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(PUBLIC_KEYS_URL)
            return response.json()
        except httpx.ConnectTimeout:
            logger.warning("Connection timeout while trying to reach the auth service at %s", PUBLIC_KEYS_URL)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    global public_keys
    global fake_users
    global fake_orders

    public_keys = await fetch_public_keys()
    fake_users = generate_fake_users(num_users)
    fake_orders = generate_fake_orders(fake_users, num_orders_per_user)
    yield


app = FastAPI(lifespan=lifespan)

async def jwt_auth(auth_credentials: HTTPAuthorizationCredentials = Security(HTTPBearer())) -> None:
    """
    Performs JWT authentication for incoming requests.

    This function extracts the JWT token from the request, verifies its signature using a public key,
    and checks that it is an access token. If any validation step fails, an HTTP 401 Unauthorized
    exception is raised.

    Args:
        auth_credentials: The authorization credentials containing the JWT token.

    Raises:
        HTTPException: If the token is expired, invalid, or does not have the correct type.
    """
    try:
        token = auth_credentials.credentials
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
async def protected() -> Any:
    logger.info("Accessed protected API")
    return "OK"


@app.get("/users/{user_id}",
         summary="[Fake] Get user by id")
async def users(user_id: int) -> dict[str, Any]:
    for user in fake_users:
        if user["id"] == user_id:
            return user
    raise HTTPException(status_code=404, detail=f"User with id {user_id} not found")

@app.get("/orders/{user_id}",
         summary="[Fake] Get order by user id")
async def orders(user_id: int) -> list[dict[str, Any]]:
    user_orders = []
    for order in fake_orders:
        if order["user_id"] == user_id:
            user_orders.append(order)
    return user_orders