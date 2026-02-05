app/api/auth.py:

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.schemas.auth import SignUpSchema, SignInSchema, TokenSchema
from app.db.base import get_db
from app.models.user import User
from app.models.token import Token
from app.core.security import hash_password, verify_password, create_jwt
from app.core.auth_session import get_current_user

router = APIRouter()


@router.post("/signup", response_model=TokenSchema)
def signup(user: SignUpSchema, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pwd = hash_password(user.password)
    new_user = User(
        full_name=user.full_name,
        email=user.email,
        hashed_password=hashed_pwd,
        date_of_birth=user.date_of_birth,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_jwt(new_user.id)
    token_entry = Token(user_id=new_user.id, token=token)
    db.add(token_entry)
    db.commit()

    return {"access_token": token}


@router.post("/signin", response_model=TokenSchema)
def signin(user: SignInSchema, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="Email does not exist")

    if not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect password")

    token = create_jwt(db_user.id)

    # --- FIX: Delete old tokens for this user before adding a new one ---
    # This prevents the "Duplicate entry" error and ensures a clean session.
    db.query(Token).filter(Token.user_id == db_user.id).delete()

    token_entry = Token(user_id=db_user.id, token=token)
    db.add(token_entry)
    db.commit()

    return {"access_token": token}


@router.post("/logout")
def logout(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    db.query(Token).filter(Token.user_id == current_user.id).delete()
    db.commit()

    return {
        "message": "Logged out successfully"
    }

app/api/user.py:

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.schemas.user import UserSchema
from app.db.base import get_db
from app.models.user import User
from app.core.auth_session import get_current_user

router = APIRouter()

@router.get("/user", response_model=UserSchema)
def get_user(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return current_user


app/core/auth_session.py:

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.db.base import SessionLocal
from app.models.token import Token
from app.models.user import User
from app.core.security import decode_jwt

security = HTTPBearer()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(lambda: SessionLocal())
) -> User:
    token_str = credentials.credentials

    try:
        payload = decode_jwt(token_str)
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    token_in_db = db.query(Token).filter(Token.token == token_str).first()
    if not token_in_db:
        raise HTTPException(status_code=401, detail="Token revoked or invalid")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user

app/core/config.py:

import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")
JWT_SECRET = os.getenv("JWT_SECRET", "supersecretkey")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

if "JWT_ALGORITHM" not in os.environ:
    print("⚠️ Using fallback JWT_ALGORITHM")


app/core/security.py:

import jwt
from passlib.context import CryptContext
from app.core.config import JWT_SECRET, JWT_ALGORITHM

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# Password hashing
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# JWT
def create_jwt(user_id: int) -> str:
    payload = {"user_id": user_id}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_jwt(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

app/db/base.py:

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.core.config import DATABASE_URL

# FIXED: Check if we are using sqlite before adding specific args
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app/models/token.py:

from sqlalchemy import Column, Integer, String
from app.db.base import Base

class Token(Base):
    __tablename__ = "tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    # FIXED: Added (255) so unique=True works in MySQL
    token = Column(String(512), unique=True, nullable=False)

app/models/user.py:

from sqlalchemy import Column, Integer, String, Date
from app.db.base import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(255), nullable=False)  # Added length
    # FIXED: Added (255) to allow indexing
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False) # Added length
    date_of_birth = Column(Date, nullable=False)


app/schemas/auth.py:

from pydantic import BaseModel, EmailStr
from datetime import date

class SignUpSchema(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    date_of_birth: date

class SignInSchema(BaseModel):
    email: EmailStr
    password: str

class TokenSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"


app/schemas/user.py:

from pydantic import BaseModel, EmailStr

class UserSchema(BaseModel):
    id: int
    full_name: str
    email: EmailStr

    class Config:
        from_attributes = True


app/main.py:

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.db.base import Base, engine
from app.api.auth import router as auth_router
from app.api.user import router as user_router

# DEV ONLY: auto-create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="micro2move Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(user_router, prefix="/users", tags=["user"])

@app.get("/health")
def health():
    return {"status": "ok"}