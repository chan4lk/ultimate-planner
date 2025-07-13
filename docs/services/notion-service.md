# Notion Service

## Product Requirement Document (PRD)

**Purpose:**  
Sync tasks from Notion databases/pages.

**Core Requirements:**  
- Authenticate with Notion API.  
- Fetch tasks from user-selected databases/pages.  
- Map Notion data to the unified schema.  
- Support real-time updates (if possible) or scheduled polling.  
- Handle authentication and error states.

## Rule File (Acceptance Criteria)

- [ ] Auth flow with Notion API is secure and reliable.
- [ ] Notion tasks are fetched and mapped correctly.
- [ ] Sync is incremental and efficient.
- [ ] Handles token expiration and API errors.
- [ ] Logs all sync operations.
