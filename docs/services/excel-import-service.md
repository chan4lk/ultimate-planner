# Excel Import Service

## Product Requirement Document (PRD)

**Purpose:**  
Import tasks from Excel files uploaded by the user.

**Core Requirements:**  
- Accept Excel file uploads via frontend.  
- Parse and map rows to the unified task schema.  
- Validate data and handle errors gracefully.  
- Store imported tasks in the database.  
- Allow re-import and update of existing tasks.

## Rule File (Acceptance Criteria)

- [ ] Excel files are parsed and mapped correctly.
- [ ] Invalid rows are reported with clear errors.
- [ ] Duplicate imports are handled gracefully.
- [ ] Imported tasks are available in the unified task list.
- [ ] Logs all import operations.
