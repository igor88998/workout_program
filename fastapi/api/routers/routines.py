from pydantic import BaseModel
from typing import List, Optional
from fastapi import APIRouter, HTTPException, status
from sqlalchemy.orm import joinedload
from api.models import Workout, Routine
from api.deps import db_dependency, user_dependency

router = APIRouter(
    prefix='/routines',
    tags=['routines']
)

class RoutineBase(BaseModel):
    name: str
    description: Optional[str] = None
    
class RoutineCreate(RoutineBase):
    workouts: List[int] = []
    
@router.get("/")
def get_routines(db: db_dependency, user: user_dependency):
    return db.query(Routine).options(joinedload(Routine.workouts)).filter(Routine.user_id == user.id).all()

@router.post("/")
def create_routine(db: db_dependency, user: user_dependency, routine: RoutineCreate):
    db_routine = Routine(name=routine.name, description=routine.description, user_id=user.id)  
    for workout_id in routine.workouts:
        workout = db.query(Workout).filter(Workout.id == workout_id, Workout.user_id == user.id).first()
        if workout:
            db_routine.workouts.append(workout)
    db.add(db_routine)
    db.commit()
    db.refresh(db_routine)
    return db_routine

@router.delete("/")
def delete_routine(db: db_dependency, user: user_dependency, routine_id: int):
    db_routine = db.query(Routine).filter(Routine.id == routine_id, Routine.user_id == user.id).first()
    if not db_routine:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Routine not found")
    
    db.delete(db_routine)
    db.commit()
    return {"message": "Routine deleted successfully"}