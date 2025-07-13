from pydantic import BaseModel

class GraphNode(BaseModel):
    id: int
    label: str
