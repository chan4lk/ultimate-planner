# Sync Scheduler Service

## Product Requirement Document (PRD)

**Purpose:**  
Orchestrate and schedule sync operations for all integrations.

**Core Requirements:**  
- Schedule periodic sync jobs for each integration.  
- Trigger sync on-demand (e.g., user action).  
- Monitor sync status and retry on failure.  
- Expose API for sync status and manual triggers.

## Rule File (Acceptance Criteria)

- [ ] Sync jobs run on schedule and on-demand.
- [ ] Sync failures are retried with backoff.
- [ ] Sync status is available via API.
- [ ] Logs all sync operations and errors.
