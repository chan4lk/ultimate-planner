from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
import json
from typing_extensions import Annotated
from .auth import router as auth_router
from .database import create_tables

app = FastAPI()

# Include authentication router
app.include_router(auth_router)

# Create database tables on startup
@app.on_event("startup")
def startup_event():
    create_tables()

# Set up templates
templates = Jinja2Templates(directory="app/templates")

# In-memory storage for tasks
tasks: List[Dict[str, Any]] = []

# Pydantic models
class TaskCreate(BaseModel):
    text: str

class Task(TaskCreate):
    id: str
    done: bool = False

# Utility function to find task by ID
def find_task(task_id: str) -> Optional[Dict[str, Any]]:
    return next((task for task in tasks if task["id"] == task_id), None)

# Root endpoint
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Get all tasks
@app.get("/tasks", response_class=HTMLResponse)
async def list_tasks(
    request: Request, 
    hx_request: Annotated[str | None, Header()] = None
):
    if hx_request:
        return templates.TemplateResponse(
            "task_list.html",
            {"request": request, "tasks": tasks}
        )
    return templates.TemplateResponse("index.html", {"request": request, "tasks": tasks})

# Create a new task
@app.post("/tasks", response_class=HTMLResponse)
async def create_task(
    request: Request,
    hx_request: Annotated[str | None, Header()] = None
):
    form_data = await request.form()
    task_text = form_data.get("text")
    
    if not task_text:
        raise HTTPException(status_code=400, detail="Task text is required")
    
    new_task = {
        "id": str(uuid4()),
        "text": task_text,
        "done": False
    }
    tasks.append(new_task)
    
    if hx_request:
        return templates.TemplateResponse(
            "task_list.html",
            {"request": request, "tasks": [new_task]}
        )
    return templates.TemplateResponse("task_list.html", {"request": request, "tasks": tasks})

# Toggle task completion
@app.put("/tasks/{task_id}/toggle", response_class=HTMLResponse)
async def toggle_task(
    task_id: str,
    request: Request,
    hx_request: Annotated[str | None, Header()] = None
):
    task = find_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task["done"] = not task["done"]
    
    if hx_request:
        return templates.TemplateResponse(
            "task_list.html",
            {"request": request, "tasks": [task]}
        )
    return templates.TemplateResponse("task_list.html", {"request": request, "tasks": tasks})

# Delete a task
@app.delete("/tasks/{task_id}", response_class=HTMLResponse)
async def delete_task(
    task_id: str,
    request: Request,
    hx_request: Annotated[str | None, Header()] = None
):
    global tasks
    task = find_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    tasks = [t for t in tasks if t["id"] != task_id]
    
    if hx_request:
        return HTMLResponse("")
    return templates.TemplateResponse("task_list.html", {"request": request, "tasks": tasks})
