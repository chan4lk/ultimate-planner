from fastapi import APIRouter
from .schemas import Task

router = APIRouter()

@router.get("/", response_model=list[Task])
def list_tasks():
    return [Task(id=1, title="Sample Task", description="A sample task.")]
