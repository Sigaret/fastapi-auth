from typing import Optional
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY = "b1d4733aa6daf70e186e2131b74452ab13e847821c5cedc637336db5ee01e49c"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30



dumy_db = {
    'jon' : {
        'username' : 'jon',
        'full_name' : 'John Canada',
        'email' : 'joh@mail.com',
        'hashed_password' : '',
        'disable' : False
    }
}

class Data(BaseModel):
    name: str

class Token(BaseModel):
    access_token : str
    toke_type : str

class TokenData(BaseModel):
    username : Optional[str] = Field(default=None)

class User(BaseModel):
    username : str 
    email : Optional[str] = Field(default=None)
    full_name : Optional[str] = Field(default=None)
    disable : Optional[str] = Field(default=None)

class UserInDB(User):
    hashed_password : str

pwd_context =  CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl='token')

app = FastAPI()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)
    
def authenticate_user(db, username:str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    
    return user

@app.post('/create/')
async def create(data: Data):
    return{"data" : data}

@app.get('/test/{item_id}/')
async def test(item_id: str,query: int = 1):
    return {"hello" : item_id}