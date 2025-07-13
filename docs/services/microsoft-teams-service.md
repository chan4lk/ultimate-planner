# Microsoft Teams Service

## Product Requirement Document (PRD)

**Purpose:**  
Sync tasks and messages from Microsoft Teams channels relevant to the user.

**Core Requirements:**  
- Authenticate with Microsoft Graph API.  
- Fetch tasks, messages, and relevant events from Teams.  
- Map Teams data to the unified task schema.  
- Support incremental sync and webhooks for real-time updates.  
- Handle authentication refresh and error states.

## Rule File (Acceptance Criteria)

- [ ] Auth flow with Microsoft Graph API is secure and reliable.
- [ ] Tasks/messages are fetched and mapped correctly.
- [ ] Sync is incremental and efficient.
- [ ] Handles token expiration and API errors.
- [ ] Logs all sync operations.
