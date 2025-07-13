# Manual Task Entry Service

## Product Requirement Document (PRD)

**Purpose:**  
Allow users to create, edit, and delete tasks directly in the app.

**Core Requirements:**  
- Provide API endpoints for CRUD operations on tasks.  
- Validate input data.  
- Store tasks in the database with a “manual” source tag.  
- Support editing and deletion.  
- Sync changes to the unified task list.

## Rule File (Acceptance Criteria)

- [ ] Users can create, edit, and delete tasks via the app.
- [ ] Manual tasks are tagged as “manual” in the unified list.
- [ ] Input validation prevents bad data.
- [ ] Changes are reflected in real-time.
- [ ] Logs all manual task operations.
