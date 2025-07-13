# Task Aggregator Service

## Product Requirement Document (PRD)

**Purpose:**  
Aggregate, normalize, and deduplicate tasks from all integrations (Teams, Planner, Notion, Excel, Manual) into a unified format.

**Core Requirements:**  
- Fetch tasks from all connected integrations via their respective APIs/services.  
- Normalize task data (fields: title, description, due date, status, source, etc.).  
- Deduplicate tasks (by unique IDs or content similarity).  
- Store and update unified tasks in the database.  
- Expose REST/GraphQL endpoints for the frontend to fetch all tasks, filter, and search.  
- Support real-time updates (webhooks or polling).

## Rule File (Acceptance Criteria)

- [ ] Tasks from all sources are fetched and merged into a single list.
- [ ] Each task includes a source identifier.
- [ ] Duplicate tasks are not shown in the unified list.
- [ ] API returns tasks in a consistent, documented schema.
- [ ] Handles sync failures gracefully and logs errors.
