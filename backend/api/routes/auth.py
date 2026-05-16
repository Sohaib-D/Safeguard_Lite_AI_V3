from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.services.auth_service import AuthService
from backend.core.security import create_access_token
from backend.schemas.auth_schema import UserCreate, UserLogin, Token, UserResponse

router = APIRouter(tags=["Authentication"])

@router.post("/create-admin", response_model=UserResponse)
async def create_admin(payload: UserCreate, db: Session = Depends(get_db)):
    auth_svc = AuthService(db)
    if auth_svc.user_exists(payload.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")

    user = auth_svc.create_user(
        username=payload.username,
        password=payload.password,
        is_admin=True,
    )
    return user

@router.post("/login", response_model=Token)
async def login(payload: UserLogin, db: Session = Depends(get_db)):
    auth_svc = AuthService(db)
    user = auth_svc.authenticate_user(payload.username, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(subject=user.id)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username
    }
