# MS Planner Service

## Product Requirement Document (PRD)

**Purpose:**  
Sync tasks from Microsoft Planner boards.

**Core Requirements:**  
- Authenticate with Microsoft Graph API.  
- Fetch tasks from all user-accessible Planner boards.  
- Map Planner tasks to the unified schema.  
- Support real-time updates via webhooks or polling.  
- Handle authentication and error states.

## Rule File (Acceptance Criteria)

- [ ] Auth flow with Microsoft Graph API is secure and reliable.
- [ ] Planner tasks are fetched and mapped correctly.
- [ ] Sync is incremental and efficient.
- [ ] Handles token expiration and API errors.
- [ ] Logs all sync operations.
