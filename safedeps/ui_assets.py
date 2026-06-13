"""Static UI assets for the local SafeDeps dashboard."""

UI_CSS = r"""
:root {
  color-scheme: light;
  --bg:#eaf0f8;
  --bg-2:#f7fbff;
  --panel:rgba(255,255,255,0.72);
  --panel-strong:rgba(255,255,255,0.9);
  --panel-soft:rgba(255,255,255,0.48);
  --ink:#102033;
  --muted:#62708a;
  --faint:#8794ad;
  --accent:#2e8cff;
  --accent-2:#34d6d2;
  --accent-3:#8c5cff;
  --danger:#e55369;
  --warn:#f0a33a;
  --ok:#20c879;
  --border:rgba(91,118,154,0.24);
  --border-strong:rgba(91,118,154,0.38);
  --chip:rgba(46,140,255,0.11);
  --shadow:0 24px 70px rgba(28,50,85,0.16);
  --glow:0 0 26px rgba(46,140,255,0.25);
  --sidebar-width:252px;
  --sidebar-closed:82px;
}
body[data-theme="dark"] {
  color-scheme: dark;
  --bg:#050b15;
  --bg-2:#0d1728;
  --panel:rgba(14,25,43,0.7);
  --panel-strong:rgba(15,27,46,0.9);
  --panel-soft:rgba(21,35,58,0.52);
  --ink:#edf5ff;
  --muted:#a6b4cc;
  --faint:#74839f;
  --accent:#4da3ff;
  --accent-2:#3ce7df;
  --accent-3:#9267ff;
  --danger:#ff6f86;
  --warn:#ffc05a;
  --ok:#36df95;
  --border:rgba(145,170,210,0.22);
  --border-strong:rgba(145,170,210,0.36);
  --chip:rgba(77,163,255,0.14);
  --shadow:0 26px 80px rgba(0,0,0,0.42);
  --glow:0 0 32px rgba(60,231,223,0.18);
}
* { box-sizing:border-box; }
html { min-height:100%; }
body {
  min-height:100vh;
  margin:0;
  font-family:"Segoe UI","Helvetica Neue",Arial,sans-serif;
  background:
    radial-gradient(circle at 20% 0%, color-mix(in srgb, var(--accent) 24%, transparent), transparent 30%),
    radial-gradient(circle at 90% 15%, color-mix(in srgb, var(--accent-3) 18%, transparent), transparent 34%),
    linear-gradient(135deg,var(--bg),var(--bg-2));
  color:var(--ink);
  overflow-x:hidden;
}
body::before {
  content:"";
  position:fixed;
  inset:0;
  pointer-events:none;
  background:linear-gradient(115deg, transparent 0 38%, color-mix(in srgb, var(--accent-2) 7%, transparent) 45%, transparent 55% 100%);
  opacity:.8;
}
.app-shell {
  width:min(1460px, calc(100vw - 28px));
  min-height:calc(100vh - 28px);
  margin:14px auto;
  display:grid;
  grid-template-columns:var(--sidebar-width) minmax(0,1fr);
  gap:18px;
  transition:grid-template-columns .24s ease;
}
body.sidebar-collapsed .app-shell { grid-template-columns:var(--sidebar-closed) minmax(0,1fr); }
.sidebar {
  position:sticky;
  top:14px;
  height:calc(100vh - 28px);
  display:flex;
  flex-direction:column;
  gap:18px;
  padding:18px 14px;
  border:1px solid var(--border);
  border-radius:24px;
  background:linear-gradient(180deg, var(--panel-strong), var(--panel));
  box-shadow:var(--shadow), inset 0 1px 0 rgba(255,255,255,.18);
  backdrop-filter:blur(22px);
  overflow:hidden;
}
.sidebar-top { display:flex; align-items:center; justify-content:space-between; gap:10px; min-height:42px; }
.brand-mark {
  display:flex;
  align-items:center;
  gap:10px;
  min-width:0;
}
.brand-icon {
  width:42px;
  height:42px;
  display:grid;
  place-items:center;
  border-radius:0;
  background:transparent;
  color:inherit;
  font-weight:800;
  box-shadow:none;
  flex:0 0 auto;
  overflow:hidden;
}
.brand-icon img {
  width:38px;
  height:38px;
  display:block;
  object-fit:contain;
  filter:drop-shadow(0 5px 10px rgba(0,0,0,.16));
}
.brand-copy { min-width:0; }
.brand-name { font-size:15px; font-weight:800; line-height:1.1; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.brand-sub { margin-top:3px; color:var(--muted); font-size:11px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.sidebar-toggle,
.icon-button {
  width:38px;
  height:38px;
  border-radius:14px;
  padding:0;
  display:grid;
  place-items:center;
  background:var(--panel-soft);
  color:var(--ink);
  border:1px solid var(--border);
}
.sidebar-toggle:hover,
.icon-button:hover { background:var(--chip); border-color:var(--border-strong); }
.nav-list { display:flex; flex-direction:column; gap:8px; margin-top:4px; }
.nav-item {
  width:100%;
  min-height:44px;
  display:grid;
  grid-template-columns:34px minmax(0,1fr);
  align-items:center;
  gap:10px;
  padding:6px 10px;
  border:1px solid transparent;
  border-radius:16px;
  background:transparent;
  color:var(--muted);
  font-weight:700;
  text-align:left;
}
.nav-item:hover { background:var(--panel-soft); color:var(--ink); }
.nav-item.active {
  color:var(--ink);
  border-color:color-mix(in srgb, var(--accent) 42%, transparent);
  background:linear-gradient(135deg, color-mix(in srgb, var(--accent) 18%, transparent), color-mix(in srgb, var(--accent-3) 12%, transparent));
  box-shadow:inset 0 0 18px color-mix(in srgb, var(--accent) 10%, transparent);
}
.nav-icon {
  width:30px;
  height:30px;
  display:grid;
  place-items:center;
  border-radius:12px;
  background:color-mix(in srgb, var(--ink) 7%, transparent);
  color:var(--ink);
  font-size:12px;
  letter-spacing:0;
  font-weight:800;
}
.nav-label { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.sidebar-footer {
  margin-top:auto;
  padding-top:14px;
  border-top:1px solid var(--border);
  display:grid;
  gap:12px;
}
.collapse-card {
  display:flex;
  align-items:center;
  gap:10px;
  padding:10px;
  border-radius:18px;
  background:var(--panel-soft);
  border:1px solid var(--border);
}
body.sidebar-collapsed .brand-copy,
body.sidebar-collapsed .nav-label,
body.sidebar-collapsed .collapse-copy { display:none; }
body.sidebar-collapsed .sidebar { align-items:center; padding-inline:10px; }
body.sidebar-collapsed .sidebar-top,
body.sidebar-collapsed .brand-mark,
body.sidebar-collapsed .collapse-card { justify-content:center; }
body.sidebar-collapsed .nav-item { grid-template-columns:1fr; padding:6px; }
body.sidebar-collapsed .nav-icon { margin:auto; }
.main-panel {
  min-width:0;
  border:1px solid var(--border);
  border-radius:28px;
  background:linear-gradient(145deg, var(--panel), color-mix(in srgb, var(--panel-strong) 78%, transparent));
  box-shadow:var(--shadow), inset 0 1px 0 rgba(255,255,255,.16);
  backdrop-filter:blur(24px);
  overflow:hidden;
}
.topbar {
  min-height:84px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:18px;
  padding:22px 26px 10px;
}
.page-kicker {
  display:inline-flex;
  align-items:center;
  gap:8px;
  padding:5px 10px;
  border-radius:999px;
  border:1px solid var(--border);
  color:var(--accent-2);
  background:color-mix(in srgb, var(--accent-2) 9%, transparent);
  font-size:11px;
  font-weight:800;
  text-transform:uppercase;
  letter-spacing:.6px;
}
h1 { margin:8px 0 4px; font-size:34px; line-height:1.05; letter-spacing:0; }
h2 { margin:0 0 12px; font-size:20px; letter-spacing:0; }
h3 { margin:0 0 10px; }
.page-sub, .sub { margin:0; color:var(--muted); line-height:1.45; }
.top-actions { display:flex; align-items:center; gap:10px; flex-wrap:wrap; justify-content:flex-end; }
.content-area { padding:12px 26px 26px; }
.hero {
  position:relative;
  border:1px solid var(--border-strong);
  border-radius:24px;
  padding:20px;
  background:
    linear-gradient(135deg, color-mix(in srgb, var(--accent) 18%, transparent), transparent 38%),
    linear-gradient(145deg, var(--panel-strong), var(--panel-soft));
  box-shadow:var(--glow), inset 0 1px 0 rgba(255,255,255,.18);
  overflow:hidden;
}
.section-loading::after,
.row-pending td::after {
  content:"";
  position:absolute;
  inset:0;
  background:linear-gradient(105deg, transparent 0 38%, color-mix(in srgb, var(--accent-2) 22%, transparent) 48%, transparent 58% 100%);
  transform:translateX(-100%);
  animation:scanline 1.15s infinite;
  pointer-events:none;
}
.hero.section-loading {
  opacity:1;
}
.hero.section-loading .status-card,
.hero.section-loading .guard-bar {
  position:relative;
  overflow:hidden;
}
.hero.section-loading .status-card::after,
.hero.section-loading .guard-bar::after {
  content:"";
  position:absolute;
  inset:0;
  background:linear-gradient(105deg, transparent 0 34%, color-mix(in srgb, var(--accent-2) 22%, transparent) 48%, transparent 62% 100%);
  transform:translateX(-100%);
  animation:scanline 1.05s infinite;
  pointer-events:none;
}
.hero.section-loading .status-label,
.hero.section-loading .status-value,
.hero.section-loading .status-sub,
.hero.section-loading .guard-bar .hint {
  color:transparent !important;
}
.hero.section-loading .status-label::before {
  box-shadow:none;
  background:color-mix(in srgb, var(--ink) 16%, transparent);
}
.hero.section-loading .status-value,
.hero.section-loading .status-sub {
  position:relative;
  border-radius:999px;
  background:color-mix(in srgb, var(--ink) 9%, transparent);
}
.hero.section-loading .status-value {
  width:min(100%, 260px);
  min-height:18px;
}
.hero.section-loading .status-sub {
  width:min(82%, 220px);
  min-height:14px;
}
.hero.section-loading .guard-bar button,
.hero.section-loading .guard-bar .segmented {
  filter:saturate(.75);
  opacity:.58;
  box-shadow:none;
}
.hero-head { display:flex; justify-content:space-between; align-items:flex-start; gap:14px; }
.hero-title { margin:7px 0 4px; font-size:26px; letter-spacing:0; }
.hero-sub { margin:0; color:var(--muted); }
.badge { display:none; }
.status-grid {
  margin-top:18px;
  display:grid;
  grid-template-columns:repeat(4,minmax(0,1fr));
  gap:12px;
}
.status-card {
  min-width:0;
  min-height:104px;
  border:1px solid var(--border);
  border-radius:18px;
  padding:14px;
  background:linear-gradient(180deg, var(--panel-soft), color-mix(in srgb, var(--panel) 76%, transparent));
}
.status-label {
  display:flex;
  align-items:center;
  gap:8px;
  color:var(--muted);
  font-size:11px;
  font-weight:800;
  text-transform:uppercase;
  letter-spacing:.6px;
}
.status-label::before {
  content:"";
  width:9px;
  height:9px;
  border-radius:50%;
  background:var(--ok);
  box-shadow:0 0 14px var(--ok);
}
.status-card:nth-child(2) .status-label::before { background:var(--accent-2); box-shadow:0 0 14px var(--accent-2); }
.status-card:nth-child(4) .status-label::before { background:var(--warn); box-shadow:0 0 14px var(--warn); }
.status-value,
.status-sub {
  margin-top:8px;
  color:var(--ink);
  font-size:13px;
  line-height:1.35;
  font-weight:700;
  overflow-wrap:anywhere;
  word-break:break-word;
}
.status-sub { color:var(--muted); font-weight:600; font-size:12px; }
.guard-bar {
  margin-top:14px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  flex-wrap:wrap;
  padding:12px;
  border:1px solid var(--border);
  border-radius:18px;
  background:var(--panel-soft);
}
.toolbar,
.mini-actions { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
.toolbar { justify-content:space-between; margin:0; }
.mini-actions form,
.hero form { margin:0; }
.segmented {
  display:inline-flex;
  align-items:center;
  gap:4px;
  padding:4px;
  border:1px solid var(--border);
  border-radius:999px;
  background:color-mix(in srgb, var(--ink) 6%, transparent);
}
.segmented button {
  min-height:34px;
  border:0;
  border-radius:999px;
  background:transparent;
  color:var(--muted);
  padding:7px 13px;
}
.segmented button.active {
  background:linear-gradient(135deg, var(--accent), var(--accent-3));
  color:#fff;
  box-shadow:var(--glow);
}
.segmented.auto-toggle button.active.on { background:linear-gradient(135deg, var(--ok), var(--accent-2)); color:#052017; }
.segmented.auto-toggle button.active.off { background:linear-gradient(135deg, var(--danger), #ff9a6c); color:#fff; }
.section {
  position:relative;
  margin-top:18px;
  border:1px solid var(--border);
  border-radius:22px;
  padding:18px;
  background:linear-gradient(180deg, var(--panel-strong), var(--panel));
  box-shadow:0 14px 36px rgba(12,24,42,.08);
  overflow:hidden;
}
.page-section { display:none; }
.page-section.active { display:block; animation:pageIn .22s ease; }
.section-header {
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
  gap:14px;
  margin-bottom:14px;
}
details.section > summary,
details.card > summary {
  cursor:pointer;
  font-weight:800;
  color:var(--ink);
  list-style:none;
}
details.section > summary::-webkit-details-marker,
details.card > summary::-webkit-details-marker { display:none; }
details.section > summary::before,
details.card > summary::before {
  content:">";
  display:inline-block;
  margin-right:8px;
  color:var(--accent);
  transition:transform .2s ease;
}
details.section[open] > summary::before,
details.card[open] > summary::before { transform:rotate(90deg); }
.adv-tag {
  font-size:11px;
  color:var(--muted);
  margin-left:6px;
  text-transform:uppercase;
  letter-spacing:.5px;
}
.card {
  border:1px solid var(--border);
  border-radius:18px;
  padding:14px;
  background:var(--panel-soft);
}
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
form { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; margin-bottom:16px; }
.full { grid-column:1 / -1; }
#scan-form .path-row { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:8px; align-items:end; }
#scan-form .path-row label { grid-column:1 / -1; }
label { display:block; margin-bottom:5px; color:var(--muted); font-size:12px; font-weight:800; letter-spacing:.2px; }
input, select, textarea {
  width:100%;
  min-width:0;
  border:1px solid var(--border);
  border-radius:14px;
  background:color-mix(in srgb, var(--panel-strong) 82%, transparent);
  color:var(--ink);
  padding:11px 12px;
  outline:none;
}
input:focus, select:focus, textarea:focus {
  border-color:color-mix(in srgb, var(--accent) 68%, transparent);
  box-shadow:0 0 0 3px color-mix(in srgb, var(--accent) 16%, transparent);
}
textarea {
  min-height:190px;
  resize:vertical;
  font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size:12px;
}
input[type="checkbox"] {
  width:16px;
  height:16px;
  accent-color:var(--accent);
  vertical-align:middle;
  margin-right:6px;
}
button {
  min-height:40px;
  border:1px solid color-mix(in srgb, var(--accent) 34%, transparent);
  border-radius:14px;
  padding:9px 14px;
  background:linear-gradient(135deg, var(--accent), var(--accent-3));
  color:#fff;
  font-weight:800;
  cursor:pointer;
  box-shadow:0 10px 24px color-mix(in srgb, var(--accent) 18%, transparent);
}
button:hover { filter:brightness(1.06); }
button:disabled { cursor:not-allowed; opacity:.45; filter:none; box-shadow:none; }
button.button-loading {
  position:relative;
  overflow:hidden;
  pointer-events:none;
}
button.button-loading::after {
  content:"";
  position:absolute;
  inset:0;
  background:linear-gradient(105deg, transparent 0 34%, rgba(255,255,255,.38) 48%, transparent 62% 100%);
  transform:translateX(-100%);
  animation:scanline 1s infinite;
}
.ghost {
  background:var(--panel-soft);
  color:var(--ink);
  border-color:var(--border);
  box-shadow:none;
}
.danger { background:linear-gradient(135deg, var(--danger), #ff8f6a); border-color:transparent; }
.pick { background:linear-gradient(135deg, #2f72c9, var(--accent)); }
.actions { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
.quick-actions {
  display:grid;
  grid-template-columns:repeat(3,minmax(110px,1fr));
  gap:8px;
  align-items:stretch;
}
.quick-actions > button,
.quick-actions > .ghost,
.quick-actions > .pick {
  width:100%;
  min-height:34px;
  padding:6px 8px;
  font-size:12px;
  line-height:1.15;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
}
.quick-actions .action-slot { display:block; width:100%; min-height:34px; }
.status,
.notice,
.error,
.hint {
  margin-top:14px;
  padding:12px 14px;
  border-radius:16px;
  border:1px solid var(--border);
  overflow-wrap:anywhere;
}
.status { font-weight:800; }
.status.ok,
.notice { background:color-mix(in srgb, var(--ok) 13%, transparent); color:var(--ink); }
.status.fail,
.error { background:color-mix(in srgb, var(--danger) 14%, transparent); color:var(--danger); }
.hint {
  padding:10px 12px;
  color:var(--muted);
  background:var(--panel-soft);
  font-size:12px;
}
.chip {
  display:inline-flex;
  align-items:center;
  max-width:100%;
  padding:4px 8px;
  border-radius:999px;
  background:var(--chip);
  border:1px solid var(--border);
  font-size:12px;
  overflow-wrap:anywhere;
}
.console-output {
  margin:12px 0 0;
  padding:14px;
  min-height:180px;
  overflow:auto;
  white-space:pre-wrap;
  word-break:break-word;
  border:1px solid var(--border);
  border-radius:18px;
  background:color-mix(in srgb, #020814 72%, var(--panel));
  color:#dbeafe;
  font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size:12px;
  line-height:1.45;
}
table {
  width:100%;
  border-collapse:separate;
  border-spacing:0;
  margin-top:14px;
  table-layout:auto;
}
th, td {
  border-bottom:1px solid var(--border);
  text-align:left;
  padding:10px 9px;
  font-size:13px;
  vertical-align:top;
  overflow-wrap:anywhere;
}
th {
  position:sticky;
  top:0;
  z-index:1;
  background:color-mix(in srgb, var(--panel-strong) 90%, transparent);
  color:var(--muted);
  font-size:11px;
  text-transform:uppercase;
  letter-spacing:.4px;
}
tr:hover td { background:color-mix(in srgb, var(--accent) 6%, transparent); }
.dependency-table-shell {
  min-width:720px;
}
.dependency-filter-bar {
  display:grid;
  grid-template-columns:minmax(220px,420px) auto;
  align-items:end;
  justify-content:space-between;
  gap:10px 14px;
  margin:10px 0 4px;
  padding:10px;
  border:1px solid var(--border);
  border-radius:14px;
  background:var(--panel-soft);
}
.dependency-filter-label {
  grid-column:1 / -1;
  margin:0;
  color:var(--muted);
  font-size:11px;
  font-weight:800;
  text-transform:uppercase;
  letter-spacing:.45px;
}
.dependency-filter-input {
  min-height:38px;
  border-radius:12px;
}
.dependency-filter-count {
  color:var(--muted);
  font-size:12px;
  font-weight:700;
  white-space:nowrap;
}
#deps-table-wrap,
#findings-wrap,
#project-deps-wrap,
#project-runtime-deps-wrap,
#runtime-deps-wrap { overflow:auto; }
.modal-backdrop {
  position:fixed;
  inset:0;
  z-index:9998;
  display:none;
  align-items:center;
  justify-content:center;
  padding:16px;
  background:rgba(3,8,17,.62);
  backdrop-filter:blur(10px);
}
.modal-backdrop.open { display:flex; }
.modal {
  width:min(650px,96vw);
  border:1px solid var(--border);
  border-radius:22px;
  background:var(--panel-strong);
  color:var(--ink);
  box-shadow:var(--shadow);
  padding:18px;
}
.modal-head { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:8px; }
.modal-title { margin:0; font-size:18px; }
.modal-close {
  width:36px;
  height:36px;
  min-height:36px;
  padding:0;
  border-radius:14px;
  background:var(--panel-soft);
  color:var(--ink);
  border:1px solid var(--border);
  box-shadow:none;
}
.modal-body { color:var(--muted); line-height:1.45; }
.modal-body h4 { margin:10px 0 6px; color:var(--ink); font-size:14px; }
.modal-body p { margin:6px 0; }
.modal-body ul { margin:6px 0 8px 18px; padding:0; }
.modal-body li { margin:4px 0; }
.path-modal { width:min(680px,96vw); }
.modal-field-label {
  display:block;
  margin:12px 0 8px;
  color:var(--ink);
  font-size:12px;
  font-weight:800;
  text-transform:uppercase;
  letter-spacing:.45px;
}
.modal-path-input {
  width:100%;
  min-height:46px;
  border-radius:14px;
  font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size:13px;
}
.path-modal-actions {
  display:flex;
  align-items:center;
  justify-content:flex-end;
  gap:10px;
  flex-wrap:wrap;
  margin-top:14px;
}
.modal-code {
  display:block;
  margin:6px 0;
  padding:8px 10px;
  border-radius:12px;
  background:var(--chip);
  border:1px solid var(--border);
  color:var(--ink);
  font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  white-space:pre-wrap;
}
.section-loading {
  pointer-events:none;
  opacity:.82;
}
.row-pending td {
  position:relative;
  overflow:hidden;
  color:transparent !important;
}
.row-exit { opacity:0; transform:translateY(-6px); transition:opacity .28s ease, transform .28s ease; }
#deps-table-wrap tbody tr { transition:transform .28s cubic-bezier(.2,.8,.2,1), opacity .2s ease; will-change:transform; }
::-webkit-scrollbar { width:10px; height:10px; }
::-webkit-scrollbar-track { background:color-mix(in srgb, var(--ink) 5%, transparent); border-radius:999px; }
::-webkit-scrollbar-thumb {
  background:linear-gradient(180deg, var(--accent), var(--accent-2));
  border-radius:999px;
  border:2px solid color-mix(in srgb, var(--panel-strong) 80%, transparent);
}
@keyframes scanline {
  0% { transform:translateX(-100%); opacity:.25; }
  45% { opacity:1; }
  100% { transform:translateX(100%); opacity:.25; }
}
@keyframes pageIn {
  from { opacity:0; transform:translateY(8px); }
  to { opacity:1; transform:translateY(0); }
}
@media (max-width: 1100px) {
  .app-shell { grid-template-columns:var(--sidebar-closed) minmax(0,1fr); }
  body:not(.sidebar-expanded) .brand-copy,
  body:not(.sidebar-expanded) .nav-label,
  body:not(.sidebar-expanded) .collapse-copy { display:none; }
  .status-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
}
@media (max-width: 760px) {
  .app-shell {
    width:100%;
    min-height:100vh;
    margin:0;
    display:block;
  }
  .sidebar {
    position:fixed;
    z-index:30;
    left:10px;
    top:10px;
    bottom:10px;
    height:auto;
    width:var(--sidebar-closed);
  }
  body.sidebar-expanded .sidebar { width:min(var(--sidebar-width), calc(100vw - 20px)); align-items:stretch; }
  body.sidebar-expanded .brand-copy,
  body.sidebar-expanded .nav-label,
  body.sidebar-expanded .collapse-copy { display:block; }
  .main-panel {
    min-height:100vh;
    border-radius:0;
    border:0;
    padding-left:92px;
  }
  .topbar { flex-direction:column; align-items:flex-start; padding:18px 16px 8px; }
  .top-actions { width:100%; justify-content:space-between; }
  .dependency-filter-bar { grid-template-columns:1fr; }
  .dependency-filter-count { white-space:normal; }
  .content-area { padding:10px 14px 18px; }
  .hero-head,
  .section-header,
  .guard-bar { flex-direction:column; align-items:stretch; }
  .status-grid,
  form,
  .grid2 { grid-template-columns:1fr; }
  #scan-form .path-row { grid-template-columns:1fr; }
  .quick-actions { grid-template-columns:1fr; }
  h1 { font-size:27px; }
}
"""
