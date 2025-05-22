from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Integer, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import random, string, os

# DATABASE
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./xvcoin.db")  # SQLite lokal uchun, Renderda Postgres
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# MODELS
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    unique_id = Column(String, unique=True)
    coin = Column(Integer, default=0)
    is_admin = Column(Boolean, default=False)

# INIT DATABASE
Base.metadata.create_all(bind=engine)

# APP INIT
app = FastAPI()

# DEPENDENCY
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# UTILS
def generate_unique_id(length=18):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# SCHEMAS
class RegisterRequest(BaseModel):
    username: str

class RegisterResponse(BaseModel):
    unique_id: str

class LoginRequest(BaseModel):
    unique_id: str

class LoginResponse(BaseModel):
    username: str
    coin: int
    is_admin: bool

class TransferRequest(BaseModel):
    to_unique_id: str
    amount: int
    admin_unique_id: str
    admin_password: str

# ENDPOINTS
@app.post("/register", response_model=RegisterResponse)
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, detail="Username already taken")
    unique_id = generate_unique_id()
    user = User(username=data.username, unique_id=unique_id)
    db.add(user)
    db.commit()
    return {"unique_id": unique_id}

@app.post("/login", response_model=LoginResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.unique_id == data.unique_id).first()
    if not user:
        raise HTTPException(404, detail="User not found")
    return {
        "username": user.username,
        "coin": user.coin,
        "is_admin": user.is_admin
    }

@app.post("/admin/transfer")
def transfer(data: TransferRequest, db: Session = Depends(get_db)):
    if data.admin_password != "darkslayerEXEPAROL01020100710":
        raise HTTPException(403, detail="Admin password incorrect")

    admin = db.query(User).filter(User.unique_id == data.admin_unique_id, User.is_admin == True).first()
    if not admin:
        raise HTTPException(403, detail="Not admin")

    receiver = db.query(User).filter(User.unique_id == data.to_unique_id).first()
    if not receiver:
        raise HTTPException(404, detail="Recipient not found")

    if data.amount <= 0:
        raise HTTPException(400, detail="Amount must be positive")

    receiver.coin += data.amount
    db.commit()
    return {"message": f"Transferred {data.amount} coins to {receiver.username}"}

# ADD FIRST ADMIN (if not exists)
@app.on_event("startup")
def startup_admin():
    db = SessionLocal()
    if not db.query(User).filter(User.username == "@darkslayerEXE01020100710").first():
        db.add(User(
            username="@darkslayerEXE01020100710",
            unique_id="ADMINDARK01020100710",
            coin=1000,
            is_admin=True
        ))
        db.commit()
    db.close()
