import json
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, TypedDict

import bcrypt
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from starlette.responses import Response

import api_integration


class ChatMessage(BaseModel):
    id: str
    message: str


app = FastAPI()
security = HTTPBasic()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str


class UserDBEntry(TypedDict):
    username: str
    hashed_password: str


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"

PATH_TO_USERS_JSON = (os.getenv('USERS_JSON'))


with open(PATH_TO_USERS_JSON, encoding="utf-8") as f:
    users_db: dict[str, UserDBEntry] = json.load(f)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def authenticate_user(username: str, password: str):
    try:
        user = users_db[username]
    except KeyError:
        return False
    correct_password = user["hashed_password"]
    is_correct_password = verify_password(password, correct_password)
    if not is_correct_password:
        return False
    return User(username=username)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise unauthorized_exception("Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise unauthorized_exception("Not authenticated")

        token_data = TokenData(username=username)
    except JWTError:
        raise unauthorized_exception("Not authenticated")
    if token_data.username is None:
        raise unauthorized_exception("Not authenticated")

    return User(username="test")


def unauthorized_exception(message) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=message,
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.post("/token", response_model=Token)
async def login_for_access_token(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise unauthorized_exception("Incorrect username or password")

    access_token_expires = timedelta(minutes=240)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/me")
async def me(_current_user: User = Depends(get_current_user)):
    return True


@app.get("/logout")
async def logout(response: Response, _current_user: User = Depends(get_current_user)):
    response.delete_cookie(key="access_token")
    return {"message": "Successfully logged out"}


@app.get("/public")
async def public_test():
    return "Public endpoint available"


@app.get("/private")
async def private_test(_current_user: User = Depends(get_current_user)):
    return "Private endpoint available"


@app.post("/send_message")
async def send_message(payload: ChatMessage, _current_user: User = Depends(get_current_user)) -> str:
    return await api_integration.send_message(payload.id, payload.message)


@app.get('/lists')
async def get_list(_current_user: User = Depends(get_current_user)):
    return await api_integration.get_list()
