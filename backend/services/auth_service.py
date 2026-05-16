import logging
from typing import Optional
from sqlalchemy.orm import Session
from backend.db.models import User
from backend.core.security import hash_password, verify_password
from backend.schemas.auth_schema import UserCreate

logger = logging.getLogger("safeguard.services.auth")

class AuthService:
    def __init__(self, db: Session):
        self.db = db

    def user_exists(self, username: str) -> bool:
        return self.db.query(User).filter(User.username == username).first() is not None

    def create_user(self, username: str, password: str, is_admin: bool = False) -> User:
        user = User(
            username=username,
            password_hash=hash_password(password),
            is_admin=is_admin
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        user = self.db.query(User).filter(User.username == username).first()
        if not user:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user
