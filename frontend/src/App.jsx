import { useCallback, useEffect, useState } from "react";
import { clearAuthTokens, logoutSession } from "./auth.js";
import { canAccessPage } from "./permissions.js";
import { fetchAssignableRoles, submittedRoleId } from "./roles.js";
import "./App.css";

const API_URL = (import.meta.env.VITE_API_URL || "http://localhost:5000/api/v1").replace(/\/$/, "");
const navigation = [["WORKSPACE", ["Dashboard", "Projects", "Versions", "Updates"]], ["MANAGEMENT", ["Approvals", "Deployments", "Reports"]], ["ADMINISTRATION", ["Roles", "Users", "Audit Trail", "Settings"]]];
const roles = { Project: ["Admin", "Developer"], Version: ["Admin", "Developer"], Update: ["Admin", "Developer"], Approval: ["Admin", "Approver"], Deployment: ["Admin", "Developer"], User: ["Admin"] };
const filters = { Projects: ["active", "inactive", "completed", "archived"], Versions: ["planned", "released", "deprecated"], Updates: ["draft", "pending", "approved", "rejected", "deployed"], Deployments: ["pending", "successful", "failed"], Users: ["active", "inactive"] };

async function request(path, options = {}) {
  const send = (token) => fetch(`${API_URL}${path}`, { ...options, headers: { "Content-Type": "application/json", ...(options.headers || {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) } });
  let response = await send(localStorage.getItem("gds_access_token"));
  const method = (options.method || "GET").toUpperCase();
  if (response.status === 401 && ["GET", "HEAD", "OPTIONS"].includes(method) && localStorage.getItem("gds_refresh_token")) {
    const refreshed = await fetch(`${API_URL}/auth/refresh`, { method: "POST", headers: { Authorization: `Bearer ${localStorage.getItem("gds_refresh_token")}` } });
    if (refreshed.ok) { const result = await refreshed.json(); localStorage.setItem("gds_access_token", result.access_token); response = await send(result.access_token); }
    else { clearAuthTokens(); window.dispatchEvent(new Event("gds:logout")); }
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const error = new Error(typeof body.error === "string" ? body.error : body.error?.message || `Request failed (${response.status})`);
    error.code = body.error?.code;
    error.field = body.error?.field;
    error.status = response.status;
    throw error;
  }
  return response.status === 204 ? null : response.json();
}

function App() {
  const [user, setUser] = useState(null); const [active, setActive] = useState("Dashboard");
  const [records, setRecords] = useState({}); const [projects, setProjects] = useState([]); const [versions, setVersions] = useState([]); const [updates, setUpdates] = useState([]); const [rolesList, setRolesList] = useState([]); const [roleLoadError, setRoleLoadError] = useState(""); const [projectOwners, setProjectOwners] = useState([]);
  const [loading, setLoading] = useState(false); const [error, setError] = useState(""); const [notice, setNotice] = useState(""); const [modal, setModal] = useState(null); const [search, setSearch] = useState(""); const [statusFilter, setStatusFilter] = useState("");
  const [fieldErrors, setFieldErrors] = useState({}); const [approvalDetail, setApprovalDetail] = useState(null); const [approvalDetailLoading, setApprovalDetailLoading] = useState(false); const [approvalDetailError, setApprovalDetailError] = useState("");
  const userRole = user?.role; const isAdmin = userRole === "Admin";

  const load = useCallback(async (page, query = {}) => {
    if (!localStorage.getItem("gds_access_token")) return;
    setLoading(true); setError("");
    try {
      const route = { Projects: "/projects", Versions: "/versions", Updates: "/updates", Approvals: "/approvals", Deployments: "/deployments", Reports: "/reports", Roles: "/roles", Users: "/users", "Audit Trail": "/audit-logs" }[page];
      if (page === "Dashboard") {
        const [report, projectData, updateData] = await Promise.all([request("/reports"), request("/projects"), request("/updates")]);
        setRecords((old) => ({ ...old, Dashboard: { ...report.data, recent_updates: updateData.data.slice(0, 5) } })); setProjects(projectData.data);
      } else if (route) {
        const params = new URLSearchParams();
        if (query.q) params.set("q", query.q);
        if (query.status) params.set("status", query.status);
        if (query.role) params.set("role", query.role);
        const result = await request(`${route}${params.size ? `?${params}` : ""}`); setRecords((old) => ({ ...old, [page]: result.data }));
        if (page === "Projects") setProjects(result.data);
        if (page === "Versions") { setVersions(result.data); const projectData = await request("/projects"); setProjects(projectData.data); }
        if (page === "Users") {
          try {
            const roleResult = await fetchAssignableRoles(async () => (await request("/roles")).data);
            setRolesList(roleResult.roles);
            setRoleLoadError(roleResult.error);
          } catch (roleError) { setRolesList([]); setRoleLoadError(`Roles could not be loaded: ${roleError.message}`); }
        }
        if (page === "Projects" && roles.Project.includes(userRole)) {
          const ownerData = await request("/project-owners"); setProjectOwners(ownerData.data);
        }
        if (["Updates", "Deployments"].includes(page)) {
          const [projectData, versionData] = await Promise.all([request("/projects"), request("/versions")]);
          setProjects(projectData.data); setVersions(versionData.data);
        }
        if (page === "Deployments") { const updateData = await request("/updates"); setUpdates(updateData.data); }
      } else if (page === "Settings") {
        const result = await request("/auth/me"); setUser(result.user);
      }
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  }, [userRole]);

  useEffect(() => {
    let alive = true;
    (async () => { if (!localStorage.getItem("gds_access_token")) return; try { const result = await request("/auth/me"); if (alive) { setUser(result.user); await load("Dashboard"); } } catch { clearAuthTokens(); } })();
    const logoutEvent = () => { setUser(null); setRecords({}); };
    window.addEventListener("gds:logout", logoutEvent); return () => { alive = false; window.removeEventListener("gds:logout", logoutEvent); };
  }, [load]);
  useEffect(() => { if (!user) return undefined; const timer = setTimeout(() => { void load(active, { q: search.trim(), status: statusFilter, role: active === "Users" ? records.userRoleFilter || "" : "" }); }, 250); return () => clearTimeout(timer); }, [active, user, load, search, statusFilter, records.userRoleFilter]);

  async function login(event) {
    event.preventDefault(); setError(""); const form = new FormData(event.currentTarget);
    try { const result = await request("/auth/login", { method: "POST", body: JSON.stringify({ email: form.get("email"), password: form.get("password") }) }); localStorage.setItem("gds_access_token", result.access_token); localStorage.setItem("gds_refresh_token", result.refresh_token); setUser(result.user); }
    catch (err) { setError(err.message); }
  }
  function logout() {
    void logoutSession({ apiUrl: API_URL });
    setUser(null); setRecords({}); setProjects([]); setVersions([]); setUpdates([]);
  }
  const [saving, setSaving] = useState(false); const [modalError, setModalError] = useState("");
  function openModal(page, item = null) { setFieldErrors({}); setModalError(""); setModal({ page, item }); }
  function clearFieldError(field) { setFieldErrors((old) => { if (!old[field]) return old; const next = { ...old }; delete next[field]; return next; }); }
  async function save(event) {
    event.preventDefault(); if (saving) return; setSaving(true); setModalError(""); setFieldErrors({}); const form = new FormData(event.currentTarget); const data = Object.fromEntries(form.entries());
    for (const key of ["project_id", "version_id", "update_id", "owner_id"]) if (data[key] !== undefined) data[key] = data[key] === "" ? null : Number(data[key]);
    if (data.role_id !== undefined) data.role_id = submittedRoleId(data.role_id);
    for (const key of ["is_active", "is_email_verified"]) if (data[key] !== undefined) data[key] = data[key] === "true";
    const { page, item } = modal; const cfg = config[page]; const path = page === "Settings" ? cfg.endpoint : item ? `${cfg.endpoint}/${item.id}` : cfg.endpoint;
    try { const result = await request(path, { method: item || page === "Settings" ? "PATCH" : "POST", body: JSON.stringify(data) }); if (page === "Settings") setUser(result.user); setModal(null); setNotice(`${page === "Settings" ? "Profile" : cfg.singular} saved.`); await load(page, { q: search.trim(), status: statusFilter }); }
    catch (err) { if (err.field) setFieldErrors({ [err.field]: err.message }); else setModalError(err.message); }
    finally { setSaving(false); }
  }
  async function remove(page, row) {
    if (!window.confirm(`Delete “${row.name || row.title || row.version_number || row.environment}”?`)) return;
    try { await request(`${config[page].endpoint}/${row.id}`, { method: "DELETE" }); setNotice("Record deleted."); await load(page, { q: search.trim(), status: statusFilter }); } catch (err) { setError(err.message); }
  }
  async function workflow(path, body, message, method = "POST", page = active) { try { await request(path, { method, body: JSON.stringify(body) }); setNotice(message); await load(page, { q: search.trim(), status: statusFilter }); } catch (err) { setError(err.message); } }
  async function reviewDetails(row) {
    setApprovalDetail(null); setApprovalDetailError(""); setApprovalDetailLoading(true);
    try { const result = await request(`/updates/${row.id}`); setApprovalDetail(result.data); }
    catch (err) { setApprovalDetailError(err.message); }
    finally { setApprovalDetailLoading(false); }
  }
  async function changePassword(event) {
    event.preventDefault(); const form = new FormData(event.currentTarget);
    try { await request("/auth/password", { method: "POST", body: JSON.stringify({ current_password: form.get("current_password"), new_password: form.get("new_password") }) }); event.currentTarget.reset(); setNotice("Password changed."); }
    catch (err) { setError(err.message); }
  }
  useEffect(() => { if (!notice) return undefined; const timer = setTimeout(() => setNotice(""), 4000); return () => clearTimeout(timer); }, [notice]);

  if (!user) return <Login onSubmit={login} error={error} />;
  const pageRecords = records[active] || [];
  const filtered = Array.isArray(pageRecords) ? pageRecords : [];
  const allowCreate = config[active] && roles[config[active].kind]?.includes(user.role) && !["Approvals", "Reports"].includes(active);
  const canReview = roles.Approval.includes(user.role);
  return <div className="app-shell">
    <aside className="sidebar"><div className="brand"><div className="brand-mark">G</div><div><h2>Garissa Digital</h2><span>Solutions</span></div></div><div className="workspace-label">PROJECT WORKSPACE</div>
      <nav className="navigation">{navigation.map(([heading, items]) => { const visible = items.filter((name) => canAccessPage(user.role, name)); return visible.length ? <div className="nav-group" key={heading}><p className="nav-heading">{heading}</p>{visible.map((name) => <button key={name} className={`nav-item ${active === name ? "active" : ""}`} onClick={() => { setActive(name); setSearch(""); setStatusFilter(""); }}><span className="nav-icon">{{Dashboard:"▦",Projects:"▣",Versions:"⑂",Updates:"↻",Approvals:"✓",Deployments:"⇧",Reports:"▤",Roles:"♙",Users:"♙","Audit Trail":"≋",Settings:"⚙"}[name]}</span>{name}{name === "Approvals" && records.Approvals?.length > 0 && <span className="nav-count">{records.Approvals.length}</span>}</button>)}</div> : null; })}</nav>
      <div className="sidebar-bottom"><div className="profile"><div className="avatar">{user.full_name.split(" ").map((part) => part[0]).slice(0, 2).join("").toUpperCase()}</div><div className="profile-info"><strong>{user.full_name}</strong><span>{user.role}</span></div><button className="profile-menu" onClick={logout} title="Sign out">↪</button></div></div>
    </aside>
    <main className="main-content"><header className="topbar"><div className="breadcrumb">Workspace <span>/</span> <strong>{active}</strong></div><div className="topbar-right"><span className="environment"><span /> Connected</span><button className="outline-button" onClick={logout}>Sign out</button></div></header>
      <div className="page-content"><div className="welcome-row"><div><p className="eyebrow">GARISSA DIGITAL SOLUTIONS</p><h1>{active}</h1><p className="page-description">{descriptions[active]}</p></div>{allowCreate && <button className="primary-button" onClick={() => openModal(active)}><span>＋</span> New {config[active].singular.toLowerCase()}</button>}</div>
        {error && <div className="error-banner" role="alert">{error}<button onClick={() => setError("")} aria-label="Dismiss">×</button></div>}{notice && <div className="success-banner" role="status">{notice}</div>}
        {active === "Dashboard" ? <Dashboard data={records.Dashboard} loading={loading} role={user.role} onNavigate={setActive} /> : active === "Reports" ? <Reports data={records.Reports} loading={loading} /> : active === "Roles" ? <RoleCatalog roles={filtered} loading={loading} onManageUsers={() => setActive("Users")} /> : active === "Settings" ? <Settings user={user} onProfile={() => openModal("Settings", user)} onPassword={changePassword} /> : <ResourcePage page={active} rows={filtered} loading={loading} canEdit={Boolean(allowCreate)} canAdmin={isAdmin} canReview={canReview} currentUserId={user.id} search={search} onSearch={setSearch} statusFilter={statusFilter} onStatusFilter={setStatusFilter} roleFilter={active === "Users" ? (records.userRoleFilter || "") : ""} rolesList={rolesList} onRoleFilter={(value) => setRecords((old) => ({...old, userRoleFilter:value}))} onRefresh={() => load(active, { q: search.trim(), status: statusFilter, role: active === "Users" ? records.userRoleFilter : "" })} onEdit={(row) => openModal(active, row)} onDelete={(row) => remove(active, row)} onWorkflow={workflow} onReviewDetails={reviewDetails} />}
        <footer className="page-footer"><span>© {new Date().getFullYear()} Garissa Digital Solutions</span><span>Software Update &amp; Version Management System</span></footer>
      </div>
    </main>
    {modal && <ResourceModal modal={modal} projects={projects.length ? projects : records.Projects || []} versions={versions.length ? versions : records.Versions || []} updates={updates} rolesList={rolesList} roleLoadError={roleLoadError} modalError={modalError} fieldErrors={fieldErrors} saving={saving} projectOwners={projectOwners} currentUser={user} onSubmit={save} onFieldChange={clearFieldError} onClose={() => { setModal(null); setModalError(""); setFieldErrors({}); }} />}
    {(approvalDetail || approvalDetailLoading || approvalDetailError) && <ApprovalDetailModal update={approvalDetail} loading={approvalDetailLoading} error={approvalDetailError} onClose={() => { setApprovalDetail(null); setApprovalDetailError(""); }} />}
  </div>;
}

const config = {
  Projects: { endpoint: "/projects", singular: "Project", kind: "Project", fields: [{ name: "name", label: "Project name", required: true }, { name: "owner_id", label: "Assigned owner", type: "projectOwners", required: true }, { name: "description", label: "Description", type: "textarea" }, { name: "status", label: "Status", type: "select", options: ["active", "inactive", "completed", "archived"] }] },
  Versions: { endpoint: "/versions", singular: "Version", kind: "Version", fields: [{ name: "project_id", label: "Project", type: "projects", required: true }, { name: "version_number", label: "Version number", required: true }, { name: "release_notes", label: "Release notes", type: "textarea" }, { name: "release_date", label: "Release date", type: "date" }, { name: "status", label: "Status", type: "select", options: ["planned", "released", "deprecated"] }] },
  Updates: { endpoint: "/updates", singular: "Update", kind: "Update", fields: [{ name: "version_id", label: "Version", type: "versions", required: true }, { name: "title", label: "Title", required: true }, { name: "description", label: "Description", type: "textarea", required: true }, { name: "change_type", label: "Change type", type: "select", options: ["major", "minor", "patch", "hotfix"] }] },
  Deployments: { endpoint: "/deployments", singular: "Deployment", kind: "Deployment", fields: [{ name: "version_id", label: "Version", type: "versions", required: true }, { name: "update_id", label: "Approved update (optional)", type: "updates" }, { name: "environment", label: "Environment", required: true }, { name: "status", label: "Status", type: "select", options: ["pending", "successful", "failed"] }, { name: "notes", label: "Notes", type: "textarea" }] },
  Users: { endpoint: "/users", singular: "User", kind: "User", fields: [{ name: "full_name", label: "Full name", required: true }, { name: "email", label: "Email", type: "email", required: true }, { name: "password", label: "Temporary password (12+ characters)", type: "password", required: true, createOnly: true }, { name: "role_id", label: "Role", type: "roles", required: true }, { name: "is_active", label: "Account status", type: "select", options: ["true", "false"], optionLabels: ["Active", "Inactive"], editOnly: true }, { name: "is_email_verified", label: "Email verification", type: "select", options: ["true", "false"], optionLabels: ["Verified", "Not verified"] }] },
  Settings: { endpoint: "/auth/profile", singular: "Profile", fields: [{ name: "full_name", label: "Full name", required: true }, { name: "email", label: "Email", type: "email", required: true }] },
};
const descriptions = { Dashboard: "Live overview of your software projects.", Projects: "Manage project records, creators and assigned owners.", Versions: "Track releases and version history.", Updates: "Create changes and submit them for review.", Approvals: "Review updates awaiting authorization.", Deployments: "Track release deployments by environment.", Reports: "Current metrics and deployment history from the database.", Roles: "Review supported roles, their permissions, and assigned user counts.", Users: "Manage user accounts and roles.", "Audit Trail": "Review recorded user actions.", Settings: "Update your profile and account password." };

function RoleCatalog({ roles, loading, onManageUsers }) {
  return <section className="role-catalog-section">
    <div className="panel role-catalog-intro"><div><h2>System roles</h2><p>These four fixed roles define access in the Flask API. Admins assign roles when creating or editing user accounts; role definitions cannot be extended with unsupported roles.</p></div><button className="primary-button" onClick={onManageUsers}>Manage user assignments</button></div>
    <div className="role-catalog-grid">
      {roles.map((role) => <article className="panel role-card" key={role.name}>
        <div className="role-card-heading"><div><h2>{role.name}</h2><p>{role.description}</p></div><span className="role-user-count">{role.user_count} {role.user_count === 1 ? "user" : "users"}</span></div>
        <div className="role-access-level"><span>ACCESS LEVEL</span><strong>{role.access_level}</strong></div>
        <h3>Permissions</h3><ul>{role.permissions.map((permission) => <li key={permission}>{permission}</li>)}</ul>
        {!role.configured && <p className="role-not-configured" role="status">This role has no database record yet and cannot be assigned.</p>}
      </article>)}
      {!loading && roles.length === 0 && <div className="empty-state">Role definitions could not be loaded.</div>}
      {loading && roles.length === 0 && <div className="empty-state">Loading role definitions…</div>}
    </div>
  </section>;
}

function ResourcePage({ page, rows, loading, canEdit, canAdmin, canReview, currentUserId, search, onSearch, statusFilter, onStatusFilter, roleFilter, rolesList, onRoleFilter, onRefresh, onEdit, onDelete, onWorkflow, onReviewDetails }) {
  const columns = { Projects: [["name", "Project"], ["description", "Description"], ["created_by_name", "Created by"], ["owner_name", "Assigned owner"], ["status", "Status"]], Versions: [["version_number", "Version"], ["project_name", "Project"], ["release_date", "Release date"], ["status", "Status"], ["release_notes", "Notes"]], Updates: [["title", "Update"], ["project_name", "Project"], ["version_number", "Version"], ["change_type", "Type"], ["status", "Status"], ["created_by", "Created by"]], Approvals: [["title", "Update"], ["project_name", "Project"], ["version_number", "Version"], ["status", "Status"], ["created_by", "Submitted by"], ["created_at", "Submitted"]], Deployments: [["project_name", "Project"], ["version_number", "Version"], ["environment", "Environment"], ["status", "Status"], ["deployed_by", "Deployed by"], ["deployed_at", "Date"]], Users: [["full_name", "Name"], ["email", "Email"], ["role", "Role"], ["is_active", "Active"], ["is_email_verified", "Verified"], ["created_at", "Created"]], "Audit Trail": [["user", "User"], ["action", "Action"], ["entity_type", "Entity"], ["entity_id", "Record ID"], ["created_at", "Date"], ["details", "Details"]] }[page] || [];
  return <section className="panel activity-panel">
    <div className="panel-header"><div><h2>{page}</h2><p>{page === "Approvals" ? "Pending submissions in projects you are authorized to review." : "Saved records from the application database."}</p></div><button className="outline-button" onClick={onRefresh}>Refresh ↻</button></div>
    <div className="table-toolbar"><div className="search-box"><span>⌕</span><input type="search" aria-label={`Search ${page}`} placeholder={`Search ${page.toLowerCase()}…`} value={search} onChange={(e) => onSearch(e.target.value)} /></div>{filters[page] && <label className="filter-control">Status<select value={statusFilter} onChange={(e) => onStatusFilter(e.target.value)}><option value="">All statuses</option>{filters[page].map((status) => <option key={status} value={status}>{status}</option>)}</select></label>}{page === "Users" && <label className="filter-control">Role<select value={roleFilter} onChange={(e) => onRoleFilter(e.target.value)}><option value="">All roles</option>{rolesList.map((role) => <option key={role.id} value={role.name}>{role.name}</option>)}</select></label>}<span className="result-count">{loading ? "Loading…" : `${rows.length} records`}</span></div>
    <div className="table-scroll"><table><thead><tr>{columns.map(([key, label]) => <th key={key}>{label.toUpperCase()}</th>)}{page !== "Audit Trail" && <th>ACTIONS</th>}</tr></thead><tbody>{rows.map((row) => <tr key={row.id}>{columns.map(([key]) => <td key={key}>{key === "status" || key === "is_active" || key === "is_email_verified" ? <StatusBadge status={key === "is_active" ? row[key] ? "active" : "inactive" : key === "is_email_verified" ? row[key] ? "verified" : "unverified" : row[key]} /> : key === "details" ? JSON.stringify(row[key] || {}) : key.includes("date") || key === "created_at" ? formatDate(row[key]) : row[key] || "—"}</td>)}{page !== "Audit Trail" && <td className="project-actions">
      {page === "Approvals" && canReview && <><button className="outline-button" onClick={() => onReviewDetails(row)}>Review details</button>{row.created_by_id === currentUserId ? <span className="permission-note">You cannot review your own submission.</span> : <><button className="primary-button compact" onClick={() => { const comments = window.prompt("Approval comments (optional):"); if (comments !== null) onWorkflow(`/approvals/${row.id}`, { decision: "approved", comments }, "Update approved."); }}>Approve</button><button className="danger-button" onClick={() => { const comments = window.prompt("Reason for rejection:"); if (comments?.trim()) onWorkflow(`/approvals/${row.id}`, { decision: "rejected", comments }, "Update rejected."); }}>Reject</button></>}</>}
      {page === "Updates" && canEdit && ["draft", "rejected"].includes(row.status) && <button className="outline-button" onClick={() => onWorkflow(`/updates/${row.id}/submit`, {}, "Submitted for approval.")}>Submit</button>}
      {page === "Deployments" && canEdit && <button className="outline-button" onClick={() => { const status = window.prompt("Set status: pending, successful, or failed", row.status); if (["pending", "successful", "failed"].includes(status)) onWorkflow(`/deployments/${row.id}`, { status }, "Deployment updated.", "PATCH"); }}>Update status</button>}
      {canEdit && !["Approvals", "Users"].includes(page) && <button className="outline-button" onClick={() => onEdit(row)}>Edit</button>}{canAdmin && page === "Users" && <button className="outline-button" onClick={() => onEdit(row)}>Manage</button>}{canAdmin && page === "Deployments" && row.status !== "successful" && <button className="danger-button" onClick={() => onDelete(row)}>Delete</button>}{page === "Projects" && canEdit && row.version_count === 0 && <button className="danger-button" onClick={() => onDelete(row)}>Delete</button>}{page === "Versions" && canEdit && row.status !== "released" && row.update_count === 0 && <button className="danger-button" onClick={() => onDelete(row)}>Delete</button>}{page === "Updates" && canEdit && row.status === "draft" && <button className="danger-button" onClick={() => onDelete(row)}>Delete</button>}
    </td>}</tr>)}{!loading && rows.length === 0 && <tr><td colSpan={columns.length + (page === "Audit Trail" ? 0 : 1)} className="empty-state">No {page.toLowerCase()} records found.</td></tr>}</tbody></table></div>
  </section>;
}

function Dashboard({ data, loading, role, onNavigate }) {
  const p = data?.projects || {}; const v = data?.versions || {}; const u = data?.updates || {}; const d = data?.deployments || {};
  const actions = ["Projects", "Versions", ...(canAccessPage(role, "Approvals") ? ["Approvals"] : []), "Deployments", "Reports"];
  return <><section className="stats-grid"><StatCard title="Total Projects" value={p.total ?? "—"} icon="▣" color="blue" /><StatCard title="Software Versions" value={v.total ?? "—"} icon="⑂" color="purple" /><StatCard title="Pending Approvals" value={u.pending_approvals ?? "—"} icon="◷" color="orange" /><StatCard title="Successful Deployments" value={d.successful ?? "—"} icon="⇧" color="green" /></section><section className="overview-grid"><div className="panel activity-panel"><div className="panel-header"><div><h2>Recent Updates</h2><p>Current update records from your workspace.</p></div><button className="outline-button" onClick={() => onNavigate("Updates")}>View updates →</button></div><div className="table-scroll"><table><thead><tr><th>UPDATE</th><th>PROJECT / VERSION</th><th>STATUS</th><th>DATE</th></tr></thead><tbody>{(data?.recent_updates || []).map((r) => <tr key={r.id}><td>{r.title}</td><td>{r.project_name} / {r.version_number}</td><td><StatusBadge status={r.status} /></td><td>{formatDate(r.created_at)}</td></tr>)}{!loading && !data?.recent_updates?.length && <tr><td colSpan="4" className="empty-state">No updates recorded.</td></tr>}</tbody></table></div></div><aside className="panel quick-panel"><div className="panel-header"><div><h2>Quick Actions</h2><p>Open a workspace module.</p></div></div>{actions.map((name) => <button key={name} className="quick-action" onClick={() => onNavigate(name)}><span className="quick-copy"><strong>{name}</strong><span>View and manage {name.toLowerCase()}</span></span><span className="quick-arrow">→</span></button>)}<div className="system-status"><span className="status-dot" /><div><strong>Database-backed dashboard</strong><p>Figures are read from the API.</p></div></div></aside></section></>;
}
function Reports({ data, loading }) {
  const d = data?.deployments || {}; const u = data?.updates || {}; const p = data?.projects || {}; const v = data?.versions || {};
  return <>
    <section className="stats-grid"><StatCard title="Projects" value={p.total ?? (loading ? "…" : 0)} icon="▣" color="blue" /><StatCard title="Versions" value={v.total ?? 0} icon="⑂" color="purple" /><StatCard title="Pending approvals" value={u.pending_approvals ?? 0} icon="◷" color="orange" /><StatCard title="Approval decisions (approved / rejected)" value={`${u.approved ?? 0} / ${u.rejected ?? 0}`} icon="✓" color="green" /></section>
    <section className="stats-grid"><StatCard title="Deployments" value={d.total ?? 0} icon="⇧" color="blue" /><StatCard title="Successful" value={d.successful ?? 0} icon="✓" color="green" /><StatCard title="Failed" value={d.failed ?? 0} icon="!" color="orange" /><StatCard title="Pending" value={d.pending ?? 0} icon="◷" color="purple" /></section>
    <ReportTable title="Project report" rows={data?.project_history} columns={[["name", "Project"], ["created_by_name", "Created by"], ["owner_name", "Assigned owner"], ["status", "Status"], ["created_at", "Created"]]} loading={loading} />
    <ReportTable title="Version report" rows={data?.version_history} columns={[["version_number", "Version"], ["project_name", "Project"], ["release_date", "Release date"], ["status", "Status"]]} loading={loading} />
    <ReportTable title="Update report" rows={data?.update_history} columns={[["title", "Update"], ["project_name", "Project"], ["version_number", "Version"], ["status", "Status"]]} loading={loading} />
    <ReportTable title="Approval history" rows={data?.approval_history} columns={[["update_title", "Update"], ["project_name", "Project"], ["decision", "Decision"], ["reviewer", "Reviewed by"], ["reviewed_at", "Date"], ["comments", "Comments"]]} loading={loading} />
    <ReportTable title="Deployment history" rows={d.history} columns={[["project_name", "Project"], ["version_number", "Version"], ["environment", "Environment"], ["status", "Status"], ["deployed_by", "Deployed by"], ["deployed_at", "Date"]]} loading={loading} />
  </>;
}
function ReportTable({ title, rows = [], columns, loading }) {
  const [search, setSearch] = useState(""); const [status, setStatus] = useState("");
  const statusKey = columns.some(([key]) => key === "status") ? "status" : columns.some(([key]) => key === "decision") ? "decision" : null;
  const statuses = [...new Set(rows.map((row) => row[statusKey]).filter(Boolean))].sort();
  const visible = rows.filter((row) => JSON.stringify(row).toLowerCase().includes(search.toLowerCase()) && (!status || row[statusKey] === status));
  return <section className="panel activity-panel"><div className="panel-header"><div><h2>{title}</h2><p>Showing up to 20 recent API records; these controls filter the records currently returned.</p></div></div><div className="table-toolbar"><div className="search-box"><span>⌕</span><input type="search" aria-label={`Search ${title}`} placeholder={`Search ${title.toLowerCase()}…`} value={search} onChange={(e) => setSearch(e.target.value)} /></div>{statusKey && <label className="filter-control">{statusKey === "decision" ? "Decision" : "Status"}<select value={status} onChange={(e) => setStatus(e.target.value)}><option value="">All</option>{statuses.map((value) => <option key={value} value={value}>{value}</option>)}</select></label>}<span className="result-count">{loading ? "Loading…" : `${visible.length} records`}</span></div><div className="table-scroll"><table><thead><tr>{columns.map(([key, label]) => <th key={key}>{label.toUpperCase()}</th>)}</tr></thead><tbody>{visible.map((row) => <tr key={row.id}>{columns.map(([key]) => <td key={key}>{key === "status" || key === "decision" ? <StatusBadge status={row[key]} /> : key.endsWith("_at") || key.endsWith("_date") ? formatDate(row[key]) : row[key] || "—"}</td>)}</tr>)}{visible.length === 0 && <tr><td colSpan={columns.length} className="empty-state">{loading ? "Loading report data…" : "No matching records found."}</td></tr>}</tbody></table></div></section>;
}
function Settings({ user, onProfile, onPassword }) { return <div className="settings-grid"><section className="panel settings-card"><h2>Profile</h2><p>Manage your account details.</p><p><strong>{user.full_name}</strong><br />{user.email}<br />{user.role}</p><button className="primary-button" onClick={onProfile}>Edit profile</button></section><form className="panel settings-card" onSubmit={onPassword}><h2>Change password</h2><p>Use at least 12 characters.</p><label>Current password<input name="current_password" type="password" required autoComplete="current-password" /></label><label>New password<input name="new_password" type="password" minLength="12" required autoComplete="new-password" /></label><button className="primary-button" type="submit">Update password</button></form></div>; }
function ResourceModal({ modal, projects, versions, updates, rolesList, roleLoadError, modalError, fieldErrors, saving, projectOwners, currentUser, onSubmit, onFieldChange, onClose }) {
  const cfg = config[modal.page];
  const item = modal.item;
  const fields = cfg.fields.filter((field) => !(field.createOnly && item) && !(field.editOnly && !item));
  const roleUnavailable = modal.page === "Users" && rolesList.length === 0;

  function renderControl(field) {
    const errorId = `${field.name}-error`;
    const common = {
      id: field.name,
      name: field.name,
      required: field.required,
      "aria-invalid": Boolean(fieldErrors[field.name]),
      "aria-describedby": fieldErrors[field.name] ? errorId : undefined,
      onChange: () => onFieldChange(field.name),
    };
    if (field.type === "textarea") return <textarea {...common} rows="4" defaultValue={item?.[field.name] || ""} />;
    if (field.type === "select") {
      const initial = item ? String(item[field.name]) : field.name === "is_email_verified" ? "false" : field.options[0];
      return <select {...common} defaultValue={initial}>{field.options.map((option, index) => <option key={option} value={option}>{field.optionLabels?.[index] || option}</option>)}</select>;
    }
    if (["projects", "versions", "roles", "updates", "projectOwners"].includes(field.type)) {
      const options = field.type === "projects" ? projects : field.type === "versions" ? versions : field.type === "updates" ? updates.filter((update) => ["approved", "deployed"].includes(update.status)) : field.type === "projectOwners" ? projectOwners : rolesList;
      const initial = item?.[field.name] || (field.type === "projectOwners" ? currentUser.id : "");
      return <select {...common} disabled={field.type === "roles" && roleUnavailable} defaultValue={initial}>
        <option value="">{field.type === "roles" && roleUnavailable ? "Roles unavailable" : field.required ? "Choose…" : "None"}</option>
        {options.map((option) => <option key={option.id} value={option.id}>{field.type === "projects" ? option.name : field.type === "versions" ? `${option.project_name} — ${option.version_number}` : field.type === "updates" ? `${option.project_name} — ${option.title}` : field.type === "projectOwners" ? option.full_name : option.name}</option>)}
      </select>;
    }
    return <input {...common} type={field.type || "text"} minLength={field.type === "password" ? 12 : undefined} maxLength={field.name === "name" || field.name === "full_name" ? 120 : field.name === "email" ? 255 : 150} defaultValue={item?.[field.name] ?? ""} />;
  }

  return <div className="modal-backdrop"><form className="project-form" onSubmit={onSubmit}>
    <h2>{item ? `Edit ${cfg.singular.toLowerCase()}` : `New ${cfg.singular.toLowerCase()}`}</h2>
    {modalError && <div className="error-banner" role="alert">{modalError}</div>}
    {roleLoadError && modal.page === "Users" && <div className="error-banner" role="alert">{roleLoadError}</div>}
    {fields.map((field) => <div className="form-field" key={field.name}>
      <label htmlFor={field.name}>{field.label}</label>
      {renderControl(field)}
      {fieldErrors[field.name] && <span className="form-field-error" id={`${field.name}-error`} role="alert">{fieldErrors[field.name]}</span>}
    </div>)}
    <div className="form-actions"><button type="button" className="outline-button" disabled={saving} onClick={onClose}>Cancel</button><button className="primary-button" type="submit" disabled={saving || roleUnavailable}>{saving ? "Saving…" : "Save"}</button></div>
  </form></div>;
}

function ApprovalDetailModal({ update, loading, error, onClose }) {
  return <div className="modal-backdrop"><section className="project-form approval-detail-modal" role="dialog" aria-modal="true" aria-labelledby="approval-detail-title">
    <h2 id="approval-detail-title">Review submission</h2>
    {loading && <p role="status">Loading update details…</p>}
    {error && <div className="error-banner" role="alert">{error}</div>}
    {update && <>
      <p><strong>{update.title}</strong></p>
      <dl><dt>Project</dt><dd>{update.project_name}</dd><dt>Version</dt><dd>{update.version_number}</dd><dt>Status</dt><dd>{update.status}</dd><dt>Submitted by</dt><dd>{update.created_by || "Unknown"}</dd><dt>Submitted</dt><dd>{formatDate(update.created_at)}</dd><dt>Change type</dt><dd>{update.change_type}</dd></dl>
      <h3>Description</h3><p className="approval-description">{update.description}</p>
      {update.approvals?.length > 0 && <><h3>Previous review history</h3><ul>{update.approvals.map((approval) => <li key={approval.id}>{approval.decision} by {approval.reviewer} · {formatDate(approval.reviewed_at)}{approval.comments ? ` — ${approval.comments}` : ""}</li>)}</ul></>}
    </>}
    <div className="form-actions"><button type="button" className="outline-button" onClick={onClose}>Close</button></div>
  </section></div>;
}
function Login({ onSubmit, error }) { return <main className="login-page"><form className="login-card" onSubmit={onSubmit}><div className="brand-mark">G</div><p className="eyebrow">GARISSA DIGITAL SOLUTIONS</p><h1>Sign in</h1><p className="page-description">Use your administrator-provisioned account to continue.</p>{error && <div className="error-banner" role="alert">{error}</div>}<label>Email<input name="email" type="email" autoComplete="username" required /></label><label>Password<input name="password" type="password" autoComplete="current-password" required /></label><button className="primary-button" type="submit">Sign in</button></form></main>; }
function StatCard({ title, value, icon, color }) { return <article className="stat-card"><div className="stat-top"><span className="stat-title">{title}</span><span className={`stat-icon ${color}`}>{icon}</span></div><div className="stat-value">{value}</div></article>; }
function StatusBadge({ status }) { return <span className={`status-badge ${String(status).toLowerCase()}`}>{String(status)}</span>; }
function formatDate(value) { if (!value) return "—"; const d = new Date(value); return Number.isNaN(d.getTime()) ? value : d.toLocaleDateString(); }
export default App;
