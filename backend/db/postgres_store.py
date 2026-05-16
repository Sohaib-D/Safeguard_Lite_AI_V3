from typing import List, Optional, Type, TypeVar
from uuid import UUID
from sqlalchemy.orm import Session
from backend.db.database import Base

T = TypeVar("T", bound=Base)

class PostgresStore:
    """Generic repository for standardized DB operations."""
    
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, model: Type[T], id: UUID) -> Optional[T]:
        return self.db.query(model).filter(model.id == id).first()

    def get_all(self, model: Type[T], limit: int = 100, skip: int = 0) -> List[T]:
        return self.db.query(model).offset(skip).limit(limit).all()

    def create(self, obj: T) -> T:
        self.db.add(obj)
        self.db.commit()
        self.db.refresh(obj)
        return obj

    def delete(self, model: Type[T], id: UUID) -> bool:
        obj = self.get_by_id(model, id)
        if obj:
            self.db.delete(obj)
            self.db.commit()
            return True
        return False
