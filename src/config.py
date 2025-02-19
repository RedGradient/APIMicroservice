import os

AUTH_HOST = os.getenv("AUTH_HOST", "localhost")
PUBLIC_KEYS_URL: str = f"http://{AUTH_HOST}:8000/public-keys"
ALGORITHM: str = "RS256"
