# Garissa Digital Solutions implementation status

No PostgreSQL connection, backup, schema inspection, migration, integration test, or deployment was performed during Phase 6B. Backend tests and migration tests use isolated temporary SQLite databases.

## Access and functional behavior

- Admins can access all projects and resources, users, reports, and audit records.
- The Admin-only Roles catalog describes the four supported roles, their access levels and permissions, and current assigned-user counts. Admin role assignment is restricted to those roles; duplicate names remain blocked by the existing unique role-name constraint.
- Developers can access projects they created or that are currently assigned to them. Approvers and Viewers receive access through current project assignment. Flask scopes resource endpoints, search, approvals, and report aggregates to those projects.
- Developers can submit their own updates but cannot approve. Approvers review assigned pending submissions and cannot manage users. Viewers have read-only API permissions. Audit records have no ordinary mutation route.
- Project `created_by_id` is independent from `owner_id`. Its migration backfills only from a project-created audit event; historical creator remains `NULL` when evidence is absent.
- Logout now revokes both access and refresh JWTs through a persistent token-revocation table. Successful deployment edits reconcile linked update status and reject version/update mismatches.
- Version numbers are unique per project in application validation and in the model constraint. The migration refuses to continue when existing duplicate project/version pairs are found.
- Search and status filtering apply after access scoping. Report history tables show up to 20 records; totals are independent aggregates.

## Verification

- Backend full test discovery: 18 tests passed. This includes auth, role and project scoping, version uniqueness, workflow and deployment state transitions, report/search behavior, and migration safety.
- Migration tests ran upgrade/downgrade only on temporary SQLite. They confirmed creator backfill safety and that version uniqueness migration stops without deleting data when duplicate pairs exist.
- Frontend `npm test`: passed (both test files); lint: passed; production build: passed.
- Previous Phase 6 manual Firefox checks exercised Admin login/logout and project ownership, Developer project scoping/search, and Approver queue/approval at desktop view. They did not cover all workflows or all roles/viewports. Phase 6B browser interaction was unavailable in the current shell; no authenticated browser tests were claimed for Phase 6B changes.

## Database changes requiring review before PostgreSQL use

- `created_by_id` on `projects`, from migration `d4a6e2c183f1`.
- `revoked_tokens` table, unique JTI index, and expiration index, from migration `ab128f8d63a1`.
- Project-scoped version uniqueness constraint, from migration `f3e6a91c0d42`. The migration checks for duplicate project/version pairs and aborts if any exist; inspect PostgreSQL records and resolve duplicates before retrying.
- No migration has been applied to PostgreSQL. Apply migrations only after backup, schema/data inspection, and explicit PostgreSQL integration approval.

## Remaining work

- Back up PostgreSQL, inspect existing schema and duplicate versions, and review migration compatibility with its actual schema/data.
- Apply reviewed migrations and run PostgreSQL integration tests after connectivity is restored.
- Complete manual browser verification of all four roles, workflows, and desktop/tablet/mobile layouts.
- Prepare deployment only after database integration, browser checks, and deployment configuration review.
