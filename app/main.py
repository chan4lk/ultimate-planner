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
from .auth.router_session import router as session_router
from .database import create_tables
from .config.redis_config import close_redis_connections, ping_redis

app = FastAPI(
    title="Ultimate Planner API",
    description="Ultimate Planner with Advanced Authentication & Session Management",
    version="1.0.0"
)

# Include routers
app.include_router(auth_router)
app.include_router(session_router, prefix="/auth")

# Create database tables and test Redis connection on startup
@app.on_event("startup")
async def startup_event():
    create_tables()
    
    # Test Redis connection
    try:
        redis_healthy = await ping_redis()
        if redis_healthy:
            print("✅ Redis connection established successfully")
        else:
            print("❌ Redis connection failed")
    except Exception as e:
        print(f"❌ Redis connection error: {e}")

# Close Redis connections on shutdown
@app.on_event("shutdown")
async def shutdown_event():
    await close_redis_connections()
    print("✅ Redis connections closed")

# Set up templates
templates = Jinja2Templates(directory="app/templates")

# In-memory storage for tasks and labels
tasks: List[Dict[str, Any]] = []
labels: List[Dict[str, Any]] = [
    {"id": "personal", "name": "Personal", "color": "#10b981"},
    {"id": "work", "name": "Work", "color": "#3b82f6"},
    {"id": "urgent", "name": "Urgent", "color": "#ef4444"},
    {"id": "ideas", "name": "Ideas", "color": "#f59e0b"},
]

# Pydantic models
class TaskCreate(BaseModel):
    text: str
    label_id: Optional[str] = None

class Task(TaskCreate):
    id: str
    done: bool = False

class LabelCreate(BaseModel):
    name: str
    color: str

class Label(LabelCreate):
    id: str

# Utility functions
def find_task(task_id: str) -> Optional[Dict[str, Any]]:
    return next((task for task in tasks if task["id"] == task_id), None)

def find_label(label_id: str) -> Optional[Dict[str, Any]]:
    return next((label for label in labels if label["id"] == label_id), None)

def group_tasks_by_label() -> Dict[str, List[Dict[str, Any]]]:
    """Group tasks by their labels, including unlabeled tasks"""
    grouped = {"unlabeled": []}
    
    # Initialize groups for each label
    for label in labels:
        grouped[label["id"]] = []
    
    # Group tasks
    for task in tasks:
        label_id = task.get("label_id")
        if label_id and label_id in grouped:
            grouped[label_id].append(task)
        else:
            grouped["unlabeled"].append(task)
    
    return grouped

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "ultimate-planner"}

# Root endpoint
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Get all labels
@app.get("/labels")
async def list_labels():
    return {"labels": labels}

# Create a new label
@app.post("/labels", response_class=HTMLResponse)
async def create_label(
    request: Request,
    hx_request: Annotated[str | None, Header()] = None
):
    form_data = await request.form()
    label_name = form_data.get("name")
    label_color = form_data.get("color", "#6366f1")
    
    if not label_name:
        raise HTTPException(status_code=400, detail="Label name is required")
    
    # Generate ID from name (lowercase, replace spaces with hyphens)
    label_id = label_name.lower().replace(" ", "-").replace("_", "-")
    
    # Check if label already exists
    if find_label(label_id):
        raise HTTPException(status_code=400, detail="Label already exists")
    
    new_label = {
        "id": label_id,
        "name": label_name,
        "color": label_color
    }
    labels.append(new_label)
    
    if hx_request:
        return templates.TemplateResponse(
            "label_options.html",
            {"request": request, "labels": labels}
        )
    return {"label": new_label}

# Get all tasks
@app.get("/tasks", response_class=HTMLResponse)
async def list_tasks(
    request: Request, 
    hx_request: Annotated[str | None, Header()] = None
):
    grouped_tasks = group_tasks_by_label()
    if hx_request:
        return templates.TemplateResponse(
            "task_list.html",
            {"request": request, "grouped_tasks": grouped_tasks, "labels": labels}
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
    label_id = form_data.get("label_id")
    
    if not task_text:
        raise HTTPException(status_code=400, detail="Task text is required")
    
    new_task = {
        "id": str(uuid4()),
        "text": task_text,
        "label_id": label_id if label_id else None,
        "done": False
    }
    tasks.append(new_task)
    
    if hx_request:
        grouped_tasks = group_tasks_by_label()
        return templates.TemplateResponse(
            "task_list.html",
            {"request": request, "grouped_tasks": grouped_tasks, "labels": labels}
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
        # Return just the updated task item
        label = find_label(task.get("label_id")) if task.get("label_id") else None
        return templates.TemplateResponse(
            "task_item.html",
            {"request": request, "task": task, "label": label}
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
