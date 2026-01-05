from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from src.database import get_db
from src.crud.models import User
from src.crud.schema import UserCreate, UserUpdate
from src.exceptions import ItemNotFoundException, ExistsException

crud_router = APIRouter()

@crud_router.post("/create_user")
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    ## Description:
    - Creates a new user with the provided name and age.
    """
    # Check if user already exists
    existing_user = db.query(User).filter(User.name == user.name).first()
    if existing_user:
        raise ExistsException(detail="User already exists")

    # Create a new user instance
    new_user = User(name=user.name, age=user.age)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"id": new_user.id, "name": new_user.name, "age": new_user.age}

@crud_router.get("/get_age_orm")
async def get_age_orm(name: str, db: Session = Depends(get_db)):
    """
    ## Description:
    - 이름을 넣으면 나이를 알려줍니다.
    """
    
    user = db.query(User).filter(User.name == name).first()
    if user:
        return {"age": user.age}
    else:
        raise ItemNotFoundException(detail="User not found")

@crud_router.get("/get_age_sql")
async def get_age_sql(name: str, db: Session = Depends(get_db)):
    result = db.execute(text("SELECT age FROM users WHERE name = :name"), {"name": name}).fetchone()
    if result:
        return {"age": result[0]}
    else:
        raise ItemNotFoundException(detail="User not found")

@crud_router.put("/update_user/{user_id}")
async def update_user(user_id: int, user: UserUpdate, db: Session = Depends(get_db)):
    """
    ## Description:
    - Updates a user's information with the provided data.
    """
    existing_user = db.query(User).filter(User.id == user_id).first()
    if not existing_user:
        raise ItemNotFoundException(detail="User not found")

    if user.name is not None:
        existing_user.name = user.name
    if user.age is not None:
        existing_user.age = user.age

    db.commit()
    db.refresh(existing_user)
    
    return {"id": existing_user.id, "name": existing_user.name, "age": existing_user.age}

@crud_router.delete("/delete_user/{user_id}")
async def delete_user(user_id: int, db: Session = Depends(get_db)):
    """
    ## Description:
    - Deletes a user by their ID.
    """
    existing_user = db.query(User).filter(User.id == user_id).first()
    if not existing_user:
        raise ItemNotFoundException(detail="User not found")

    db.delete(existing_user)
    db.commit()
    
    return {"detail": "User deleted successfully"}
    
