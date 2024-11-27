from pydantic import BaseModel
from typing import Optional
from fastapi import APIRouter, HTTPException, status

from api.models import Workout
from api.deps import db_dependency, user_dependency

router = APIRouter(
    prefix='/workouts',
    tags=['workouts']
)

class WorkoutBase(BaseModel):
    name: str
    description: Optional[str] = None
    
class WorkoutCreate(WorkoutBase):
    pass


@router.get('/')
def get_workouts(db: db_dependency, user: user_dependency):
    return db.query(Workout).filter(Workout.user_id == user.id).all()

@router.get('/workouts')
def get_workouts(db: db_dependency, user: user_dependency):
    return db.query(Workout).filter(Workout.user_id == user.id).all()

@router.post("/", status_code=status.HTTP_201_CREATED)
def create_workout(db: db_dependency, user: user_dependency, workout: WorkoutCreate):
    db_workout = Workout(**workout.model_dump(), user_id=user.id) 
    db.add(db_workout)
    db.commit()
    db.refresh(db_workout)
    return db_workout

@router.delete("/")
def delete_workout(db: db_dependency, user: user_dependency, workout_id: int):
    db_workout = db.query(Workout).filter(Workout.id == workout_id, Workout.user_id == user.id).first()
    if not db_workout:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workout not found")
    
    db.delete(db_workout)
    db.commit()
    return {"message": "Workout deleted successfully"}