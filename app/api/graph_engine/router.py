from fastapi import APIRouter
from .schemas import GraphNode

router = APIRouter()

@router.get("/", response_model=list[GraphNode])
def list_graph_nodes():
    return [GraphNode(id=1, label="Sample Node")]
