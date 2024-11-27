from datetime import timedelta, datetime, timezone
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from dotenv import load_dotenv
import os
from api.models import User
from api.deps import db_dependency, bcrypt_context, get_current_user

load_dotenv()

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

SECRET_KEY = os.getenv("AUTH_SECRET_KEY")
ALGORITHM = os.getenv("AUTH_ALGORITHM")

class UserCreateRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str  
    token_type: str
    role: str

class UpdateRoleRequest(BaseModel):
    role: str

def authenticate_user(username: str, password: str, db):
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return None  
        if not bcrypt_context.verify(password, user.hashed_password):
            return None  
        return user
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error during authentication")

def create_access_token(username: str, user_id: int, role: str, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id, 'role': role}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, create_user_request: UserCreateRequest):
    existing_user = db.query(User).filter(User.username == create_user_request.username).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")

    if create_user_request.username == "igor":
        role = "admin"
    else:
        role = "user"  

    new_user = User(
        username=create_user_request.username,
        hashed_password=bcrypt_context.hash(create_user_request.password),
        role=role 
    )

    db.add(new_user)
    db.commit()

    return {"message": "User created successfully", "username": new_user.username, "role": new_user.role}

@router.post('/token', response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                                 db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token(user.username, user.id, user.role, timedelta(minutes=20))

    return {'access_token': token, 'token_type': 'bearer', "role": user.role}

@router.put("/users/{user_id}/role", status_code=status.HTTP_200_OK)
async def update_user_role(
    user_id: int,
    update_role_request: UpdateRoleRequest,
    db: db_dependency,
    current_user: User = Depends(get_current_user)  
):
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    
    user_to_update = db.query(User).filter(User.id == user_id).first()
    if not user_to_update:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if update_role_request.role not in ["admin", "user"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role")
    
    user_to_update.role = update_role_request.role
    db.commit()
    
    return {"message": f"User role updated to {update_role_request.role}", "username": user_to_update.username, "role": user_to_update.role}