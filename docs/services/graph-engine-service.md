# Graph Engine Service

## Product Requirement Document (PRD)

**Purpose:**  
Analyze tasks and their dependencies, generate a graph structure for visualization, and compute priorities.

**Core Requirements:**  
- Accept normalized tasks as input.  
- Identify and store dependencies (e.g., task A must be done before task B).  
- Compute and assign priority scores based on rules (due date, dependencies, source, etc.).  
- Expose API to return graph data (nodes, edges, priorities) for frontend visualization.  
- Allow manual creation/editing of dependencies.

## Rule File (Acceptance Criteria)

- [ ] Graph API returns nodes (tasks) and edges (dependencies).
- [ ] Priority scores are calculated and included in the response.
- [ ] Supports adding/removing dependencies via API.
- [ ] Handles circular dependencies gracefully.
- [ ] Graph data updates in real-time as tasks change.
