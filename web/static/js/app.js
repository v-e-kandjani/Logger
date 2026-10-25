// Syslog Platform Operations & Security Dashboard Controller
let liveSocket = null;
let isLivePaused = false;
let liveLogCount = 0;
const MAX_LIVE_ROWS = 15;
let lastPacketCount = 0;
let lastSampleTime = Date.now();

// Multi-tenant scoping: every same-origin API call carries the tenant chosen in the sidebar
// (X-Tenant). The server ignores it for tenant users, who are always locked to their own tenant.
(function installTenantAwareFetch() {
    if (window.__tenantFetchInstalled) return;
    window.__tenantFetchInstalled = true;
    const nativeFetch = window.fetch.bind(window);
    window.fetch = (input, init) => {
        try {
            const url = typeof input === 'string' ? input : (input && input.url) || '';
            const sameOrigin = url.startsWith('/') || url.startsWith(window.location.origin);
            if (sameOrigin && url.includes('/api/')) {
                const slug = localStorage.getItem('active_tenant_slug') || 'all';
                const opts = Object.assign({}, init || {});
                const headers = new Headers(opts.headers || (typeof input !== 'string' && input.headers) || {});
                if (!headers.has('X-Tenant')) headers.set('X-Tenant', slug);
                opts.headers = headers;
                return nativeFetch(input, opts);
            }
        } catch (e) { /* fall through to native fetch */ }
        return nativeFetch(input, init);
    };
})();

function tenantQuerySuffix(prefix = '?') {
    const slug = localStorage.getItem('active_tenant_slug') || 'all';
    return slug && slug !== 'all' ? `${prefix}tenant=${encodeURIComponent(slug)}` : '';
}

// Global translation shortcut
function t(k, fb) {
    return window.i18n ? window.i18n.t(k, fb) : (fb || k);
}
window.t = t;

// LogSeal Theme & Palette Manager (Dark / Light with System Fallback & Multi-Palette Engine)
function getAppPalette() {
    try {
        return localStorage.getItem('logseal-palette') || 'classic';
    } catch (e) {
        return 'classic';
    }
}

function setAppPalette(palette) {
    if (!['classic', 'emerald', 'nordic', 'amber', 'nebula'].includes(palette)) {
        palette = 'classic';
    }
    document.documentElement.setAttribute('data-palette', palette);
    try {
        localStorage.setItem('logseal-palette', palette);
    } catch (e) {}

    // Synchronize UI active card state
    document.querySelectorAll('.theme-card').forEach(card => {
        if (card.getAttribute('data-palette-choice') === palette) {
            card.classList.add('active');
        } else {
            card.classList.remove('active');
        }
    });
}

function selectThemePalette(palette) {
    setAppPalette(palette);
    const names = {
        classic: 'LogSeal Classic (Navy & Teal)',
        emerald: 'Obsidian Mint (Cyber Emerald)',
        nordic: 'Nordic Frost (Polar Sky)',
        amber: 'Solar Amber (Cyber Gold)',
        nebula: 'Deep Nebula (Velvet Violet)'
    };
    if (typeof showToast === 'function') {
        const msg = (window.i18n && window.i18n.currentLang === 'tr')
            ? `Tema paleti başarıyla uygulandı: ${names[palette] || palette}`
            : `Theme palette applied: ${names[palette] || palette}`;
        showToast(msg, 'success');
    }
}

function getAppModeSetting() {
    try {
        return localStorage.getItem('logseal-theme-mode') || 'dark';
    } catch (e) {
        return 'dark';
    }
}

function getAppTheme() {
    const modeSetting = getAppModeSetting();
    if (modeSetting === 'system') {
        return (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
    }
    return modeSetting === 'light' ? 'light' : 'dark';
}

function setAppTheme(theme) {
    theme = theme === 'light' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    if (document.body) {
        document.body.classList.remove('dark-theme', 'light-theme');
        document.body.classList.add(theme === 'dark' ? 'dark-theme' : 'light-theme');
    }
    const toggleBtn = document.getElementById('theme-toggle');
    if (toggleBtn) {
        toggleBtn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
        toggleBtn.setAttribute('title', theme === 'dark' ? 'Açık Temaya Geç (Light)' : 'Koyu Temaya Geç (Dark)');
    }
    try {
        localStorage.setItem('logseal-theme', theme);
    } catch (e) {}
}

function selectThemeMode(mode) {
    if (!['dark', 'light', 'system'].includes(mode)) mode = 'dark';
    try {
        localStorage.setItem('logseal-theme-mode', mode);
    } catch (e) {}

    if (mode === 'system') {
        const sysTheme = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
        setAppTheme(sysTheme);
    } else {
        setAppTheme(mode);
    }

    // Synchronize UI segmented buttons
    document.querySelectorAll('.theme-mode-btn').forEach(btn => {
        if (btn.getAttribute('data-mode-choice') === mode) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    if (typeof showToast === 'function') {
        const labels = {
            dark: (window.i18n && window.i18n.currentLang === 'tr') ? 'Karanlık Mod' : 'Dark Mode',
            light: (window.i18n && window.i18n.currentLang === 'tr') ? 'Aydınlık Mod' : 'Light Mode',
            system: (window.i18n && window.i18n.currentLang === 'tr') ? 'Sistem Otomatik Modu' : 'System Auto Mode'
        };
        const msg = (window.i18n && window.i18n.currentLang === 'tr')
            ? `Görünüm modu güncellendi: ${labels[mode]}`
            : `Appearance mode updated: ${labels[mode]}`;
        showToast(msg, 'success');
    }
}

function resetThemeDefaults() {
    selectThemePalette('classic');
    selectThemeMode('dark');
    if (typeof showToast === 'function') {
        const msg = (window.i18n && window.i18n.currentLang === 'tr')
            ? 'Tema ve görünüm ayarları varsayılana sıfırlandı.'
            : 'Theme and appearance settings reset to default.';
        showToast(msg, 'info');
    }
}

function updateThemeUI() {
    const curPalette = getAppPalette();
    document.querySelectorAll('.theme-card').forEach(card => {
        if (card.getAttribute('data-palette-choice') === curPalette) {
            card.classList.add('active');
        } else {
            card.classList.remove('active');
        }
    });

    const curMode = getAppModeSetting();
    document.querySelectorAll('.theme-mode-btn').forEach(btn => {
        if (btn.getAttribute('data-mode-choice') === curMode) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
}

function initTheme() {
    setAppPalette(getAppPalette());
    setAppTheme(getAppTheme());
    updateThemeUI();

    const toggleBtn = document.getElementById('theme-toggle');
    if (toggleBtn && !toggleBtn.dataset.themeBound) {
        toggleBtn.dataset.themeBound = 'true';
        toggleBtn.addEventListener('click', (e) => {
            e.preventDefault();
            const current = document.documentElement.getAttribute('data-theme') || 'dark';
            const next = current === 'dark' ? 'light' : 'dark';
            selectThemeMode(next);
        });
    }

    try {
        if (window.matchMedia) {
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
                const modeSetting = getAppModeSetting();
                if (modeSetting === 'system') {
                    setAppTheme(e.matches ? 'dark' : 'light');
                }
            });
        }
    } catch (e) {}
}

// Early theme and palette application to avoid FOUC
try {
    setAppPalette(getAppPalette());
    setAppTheme(getAppTheme());
} catch (e) {}

document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initAuthSession();
    initNavigation();
    initLiveStream();
    startPollingTelemetry();
    initTelemetryCharts();
    initSearch();
    initDeviceModal();
    initUserModal();
    initResetPasswordModal();
    initChangePasswordModal();
    initArchiveTrigger();
    initManualArchiveModal();
    initCustomExportModal();
    initStorageManagement();
    initUpdatesManagement();
    loadUpdateStatus();
    initSIEMManagement();
    initADAndMFAManagement();
    initHTTPSAndFQDNManagement();
    initTenantManagement();
    if (window.i18n) {
        window.i18n.setLanguage(window.i18n.currentLang);
    }
});

// Authentication & Session Guard
window.currentUser = null;

async function initAuthSession() {
    try {
        const res = await fetch('/api/v1/auth/me');
        if (!res.ok) {
            window.location.href = '/login';
            return;
        }
        const data = await res.json();
        window.currentUser = data;

        if (data.username) {
            const nameEl = document.getElementById('current-user-name');
            const roleEl = document.getElementById('current-user-role');
            if (nameEl) nameEl.textContent = data.username;
            if (roleEl) roleEl.textContent = data.role || 'Operator';
            renderUserRoleBadge(data.role || 'Operator');
        }

        // Only Super Administrators can see or manage users & system upgrades
        const usersTab = document.getElementById('nav-tab-users');
        if (usersTab) {
            usersTab.style.display = data.role === 'Super Administrator' ? '' : 'none';
        }
        // Only Super Administrator of the root tenant can perform platform upgrades
        const isRootSuperAdmin = (data.is_root !== false && (data.tenant_slug === 'default' || !data.tenant_slug)) && data.role === 'Super Administrator';
        const updatesTab = document.getElementById('nav-tab-updates');
        if (updatesTab) {
            updatesTab.style.display = isRootSuperAdmin ? '' : 'none';
        }

        // Toggle tenant upgrade restriction notice
        const updRestrictedAlert = document.getElementById('upd-tenant-restricted-alert');
        const updActions = document.querySelector('#pane-updates .section-actions');
        const updStats = document.querySelector('#pane-updates .stats-grid');
        const updDetails = document.getElementById('upd-details-panel');
        if (!isRootSuperAdmin) {
            if (updRestrictedAlert) updRestrictedAlert.style.display = 'block';
            if (updActions) updActions.style.display = 'none';
            if (updStats) updStats.style.display = 'none';
            if (updDetails) updDetails.style.display = 'none';
        } else {
            if (updRestrictedAlert) updRestrictedAlert.style.display = 'none';
            if (updActions) updActions.style.display = 'flex';
            if (updStats) updStats.style.display = 'grid';
        }

        // Only Super Administrator of the root tenant can simulate threats
        const simBtn = document.getElementById('btn-open-siem-simulate');
        if (simBtn) {
            simBtn.style.display = isRootSuperAdmin ? '' : 'none';
        }
    } catch (e) {
        window.location.href = '/login';
    }
}

// Dynamically render logo / badge for the active user's type/role
function renderUserRoleBadge(role) {
    const avatarEl = document.getElementById('current-user-avatar');
    if (!avatarEl) return;

    avatarEl.className = 'user-avatar-badge';
    let iconSvg = '';
    const r = (role || '').toLowerCase();

    if (r.includes('super') || r.includes('admin')) {
        avatarEl.classList.add('role-superadmin');
        // Star Crown icon for Super Administrator
        iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>`;
    } else if (r.includes('analyst') || r.includes('security')) {
        avatarEl.classList.add('role-analyst');
        // Threat Radar / Crosshair icon for Security Analyst
        iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/></svg>`;
    } else if (r.includes('audit')) {
        avatarEl.classList.add('role-auditor');
        // Balance scales of compliance for Auditor
        iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 3v18M3 9l9-6 9 6M6 15l-3-6h6l-3 6a3 3 0 0 1-6 0zm12 0l-3-6h6l-3 6a3 3 0 0 1-6 0z"/></svg>`;
    } else if (r.includes('operator')) {
        avatarEl.classList.add('role-operator');
        // Network server terminal icon for Operator
        iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`;
    } else {
        avatarEl.classList.add('role-readonly');
        // View-only eye icon for Read Only user
        iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
    }

    avatarEl.innerHTML = iconSvg;

    const logoutBtn = document.getElementById('btn-logout');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            try {
                await fetch('/api/v1/auth/logout', { method: 'POST' });
            } finally {
                window.location.href = '/login';
            }
        });
    }
}

let currentSettingsSection = 'setting-section-kamusm';

// Navigation Tab Switcher & Submenu Controller
function switchTab(tab, targetSectionId = null) {
    const navItems = document.querySelectorAll('.nav-item');
    const targetItem = document.querySelector(`.nav-item[data-tab="${tab}"]`);

    // Gate access to users and updates tab for non-admins
    if ((tab === 'users' || tab === 'updates') && window.currentUser && window.currentUser.role !== 'Super Administrator') {
        showToast('Erişim Reddedildi: Yalnızca Süper Yöneticiler bu bölüme erişebilir.', 'error');
        return;
    }

    navItems.forEach(i => i.classList.remove('active'));
    if (targetItem) targetItem.classList.add('active');

    // Manage settings nav group open state
    const settingsGroup = document.getElementById('nav-group-settings');
    if (settingsGroup) {
        if (tab === 'settings') {
            settingsGroup.classList.add('open');
        } else {
            settingsGroup.classList.remove('open');
        }
    }

    // Manage endpoint nav group open state
    const endpointGroup = document.getElementById('nav-group-endpoint');
    if (endpointGroup) {
        if (tab === 'endpoint') {
            endpointGroup.classList.add('open');
        } else {
            endpointGroup.classList.remove('open');
        }
    }

    // Auto-expand parent section group if user navigates to a tab inside a collapsed section
    if (typeof ensureActiveNavSectionExpanded === 'function') {
        ensureActiveNavSectionExpanded(tab);
    }

    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    const targetPane = document.getElementById(`pane-${tab}`);
    if (targetPane) targetPane.classList.add('active');

    updateViewHeader(tab);
    if (window.i18n && typeof window.i18n.applyTranslations === 'function') {
        window.i18n.applyTranslations();
    }

    // Refresh tab-specific views with exception guard
    try {
        if (tab === 'dashboard') fetchAndRenderTelemetryCharts();
        if (tab === 'search') document.getElementById('btn-search-exec')?.click();
        if (tab === 'siem') loadSIEMData();
        if (tab === 'appearance') updateThemeUI();
        if (tab === 'endpoint') {
            loadEndpointDashboard();
            loadEndpointAgents();
            loadEndpointTokens();
            switchEndpointSubSection(targetSectionId || currentEndpointSection || 'endpoint-sec-dashboard');
        }
        if (tab === 'devices') loadDevices();
        if (tab === 'unregistered') loadUnregisteredSources();
        if (tab === 'archives') loadArchives();
        if (tab === 'reports') loadReportsView();
        if (tab === 'health') loadHealthTelemetry();
        if (tab === 'settings') {
            loadSettings();
            if (typeof loadEdgeNodes === 'function') loadEdgeNodes();
            if (typeof loadTenants === 'function') loadTenants();
            displaySettingsSection(targetSectionId || currentSettingsSection || 'setting-section-kamusm');
        }
        if (tab === 'support') {
            if (typeof loadDebugBundles === 'function') loadDebugBundles();
        }
        if (tab === 'users') loadUsers();
        if (tab === 'updates') loadUpdateStatus();
    } catch (err) {
        console.error('Tab refresh error for', tab, err);
    }
}

// Display ONLY the chosen settings section without auto-scrolling
function displaySettingsSection(targetId) {
    if (!targetId) targetId = currentSettingsSection || 'setting-section-kamusm';
    currentSettingsSection = targetId;

    const panels = document.querySelectorAll('#pane-settings .panel');
    const isAll = targetId === 'all';

    panels.forEach(p => {
        if (isAll || p.id === targetId) {
            p.classList.remove('settings-panel-hidden');
            if (!isAll) {
                p.classList.add('settings-panel-single');
            } else {
                p.classList.remove('settings-panel-single');
            }
        } else {
            p.classList.add('settings-panel-hidden');
            p.classList.remove('settings-panel-single');
        }
    });

    // Sync active classes on sidebar subitems and settings pill buttons
    document.querySelectorAll('#nav-submenu-settings .nav-subitem').forEach(sub => {
        sub.classList.toggle('active', sub.getAttribute('data-target') === targetId);
    });
    document.querySelectorAll('.settings-subnav-btn').forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-target') === targetId);
    });

    // Reset scroll to top of view instantly
    window.scrollTo({ top: 0, behavior: 'instant' });

    if (targetId === 'setting-section-audit' || isAll) {
        if (typeof loadAuditLogs === 'function') loadAuditLogs();
    }
}

// Backward-compatible alias
function scrollToSettingsSection(targetId) {
    displaySettingsSection(targetId);
}

// Foldable Nav Section Groups Controller
function initSidebarFoldableSections() {
    let savedStates = {};
    try {
        const raw = localStorage.getItem('sidebar_foldable_sections');
        if (raw) savedStates = JSON.parse(raw);
    } catch (e) {
        savedStates = {};
    }

    const groups = document.querySelectorAll('.nav-section-group');
    groups.forEach(group => {
        const secId = group.getAttribute('data-section');
        const header = group.querySelector('.nav-section-header');
        const hasActiveItem = group.querySelector('.nav-item.active') !== null;
        if (savedStates[secId] === 'collapsed' && !hasActiveItem) {
            group.classList.add('collapsed');
            if (header) header.setAttribute('aria-expanded', 'false');
        } else {
            group.classList.remove('collapsed');
            if (header) header.setAttribute('aria-expanded', 'true');
        }

        if (header && !header.dataset.foldBound) {
            header.dataset.foldBound = 'true';
            header.addEventListener('click', (e) => {
                e.preventDefault();
                toggleSidebarSection(secId);
            });
            header.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    toggleSidebarSection(secId);
                }
            });
        }
    });
}

function toggleSidebarSection(secId) {
    const group = document.querySelector(`.nav-section-group[data-section="${secId}"]`);
    if (!group) return;
    const isCollapsed = group.classList.toggle('collapsed');
    const header = group.querySelector('.nav-section-header');
    if (header) {
        header.setAttribute('aria-expanded', isCollapsed ? 'false' : 'true');
    }
    try {
        let savedStates = {};
        const raw = localStorage.getItem('sidebar_foldable_sections');
        if (raw) savedStates = JSON.parse(raw);
        savedStates[secId] = isCollapsed ? 'collapsed' : 'open';
        localStorage.setItem('sidebar_foldable_sections', JSON.stringify(savedStates));
    } catch (e) {}
}

function ensureActiveNavSectionExpanded(tab) {
    const activeItem = document.querySelector(`.nav-item[data-tab="${tab}"]`);
    if (!activeItem) return;
    const parentGroup = activeItem.closest('.nav-section-group');
    if (parentGroup && parentGroup.classList.contains('collapsed')) {
        const secId = parentGroup.getAttribute('data-section');
        parentGroup.classList.remove('collapsed');
        const header = parentGroup.querySelector('.nav-section-header');
        if (header) header.setAttribute('aria-expanded', 'true');
        try {
            let savedStates = {};
            const raw = localStorage.getItem('sidebar_foldable_sections');
            if (raw) savedStates = JSON.parse(raw);
            savedStates[secId] = 'open';
            localStorage.setItem('sidebar_foldable_sections', JSON.stringify(savedStates));
        } catch (e) {}
    }
}

function initNavigation() {
    // 0. Initialize Foldable Section Groups
    initSidebarFoldableSections();

    // 1. Primary Nav Items
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const tab = item.getAttribute('data-tab');
            if (tab === 'settings') {
                const group = document.getElementById('nav-group-settings');
                if (group && item.classList.contains('active')) {
                    group.classList.toggle('open');
                    return;
                }
            }
            if (tab === 'endpoint') {
                const group = document.getElementById('nav-group-endpoint');
                if (group && item.classList.contains('active')) {
                    group.classList.toggle('open');
                    return;
                }
            }
            switchTab(tab);
        });
    });

    // 2. Sidebar Submenu Items
    const subItems = document.querySelectorAll('#nav-submenu-settings .nav-subitem');
    subItems.forEach(sub => {
        sub.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = sub.getAttribute('data-target');
            switchTab('settings', targetId);
        });
    });

    const epSubItems = document.querySelectorAll('#nav-submenu-endpoint .nav-subitem');
    epSubItems.forEach(sub => {
        sub.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = sub.getAttribute('data-endpoint-target');
            switchTab('endpoint', targetId);
        });
    });

    // 3. In-Pane Subnav Buttons
    const subnavBtns = document.querySelectorAll('.settings-subnav-btn');
    subnavBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = btn.getAttribute('data-target');
            displaySettingsSection(targetId);
        });
    });

    const epNavBtns = document.querySelectorAll('.endpoint-nav-btn');
    epNavBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = btn.getAttribute('data-target');
            switchEndpointSubSection(targetId);
        });
    });

    // 4. Universal Modal Backdrop Click Dismissal
    document.querySelectorAll('.modal-backdrop').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.remove('active');
                modal.style.display = 'none';
            }
        });
    });

    updateViewHeader('dashboard');
}

// Telemetry Polling (Every 2 seconds)
function startPollingTelemetry() {
    const poll = async () => {
        try {
            const res = await fetch('/api/v1/dashboard');
            if (res.status === 401) {
                window.location.href = '/login';
                return;
            }
            if (!res.ok) return;
            const data = await res.json();

            document.getElementById('stat-logs-today').textContent = Number(data.logs_today || 0).toLocaleString();
            document.getElementById('stat-total-inserted').textContent = Number(data.total_inserted || 0).toLocaleString();
            document.getElementById('stat-active-devices').textContent = data.active_devices || 0;
            document.getElementById('stat-total-devices').textContent = `${data.total_devices || 0} registered assets`;
            document.getElementById('stat-unknown-sources').textContent = data.unknown_sources || 0;
            document.getElementById('unknown-count-badge').textContent = data.unknown_sources || 0;
            document.getElementById('metric-queue-depth').textContent = `${data.queue_depth || 0} / 250,000`;

            // Calculate current EPS rate (tenant view uses server-side per-tenant EPS)
            const now = Date.now();
            const timeDiffSec = (now - lastSampleTime) / 1000;
            if (data.tenant_scope) {
                document.getElementById('current-eps').textContent = `${Math.round(data.tenant_eps || 0).toLocaleString()} EPS`;
            } else if (timeDiffSec > 0 && lastPacketCount > 0) {
                const rxDiff = (data.packets_rx || 0) - lastPacketCount;
                const eps = Math.max(0, Math.round(rxDiff / timeDiffSec));
                document.getElementById('current-eps').textContent = `${eps.toLocaleString()} EPS`;
            }
            lastPacketCount = data.packets_rx || 0;
            lastSampleTime = now;

            // Header DB health
            document.getElementById('sb-ch-status').textContent = data.clickhouse_healthy ? 'Online' : 'Degraded';

            // Storage telemetry
            if (data.storage) {
                updateStorageUI(data.storage);
            }
        } catch (e) {
            console.error('Telemetry error:', e);
        }
    };
    poll();
    setInterval(poll, 5000);

    pollGovernorStatus();
    setInterval(pollGovernorStatus, 3000);
}

async function pollGovernorStatus() {
    try {
        const res = await fetch('/api/v1/governor/status');
        if (!res.ok) return;
        const data = await res.json();

        const badge = document.getElementById('gov-badge-state');
        const reason = document.getElementById('gov-state-reason');
        const ctrlCpus = document.getElementById('gov-control-cpus');
        const wrkCpus = document.getElementById('gov-worker-cpus');
        const admission = document.getElementById('gov-admission-status');
        const psi = document.getElementById('gov-mem-psi');

        if (badge) {
            badge.textContent = data.state || 'NORMAL';
            if (data.state === 'CRITICAL') {
                badge.style.background = 'rgba(239, 68, 68, 0.2)';
                badge.style.color = '#f87171';
                badge.style.borderColor = 'rgba(239, 68, 68, 0.4)';
            } else if (data.state === 'PRESSURE') {
                badge.style.background = 'rgba(245, 158, 11, 0.2)';
                badge.style.color = '#fbbf24';
                badge.style.borderColor = 'rgba(245, 158, 11, 0.4)';
            } else if (data.state === 'RECOVERY') {
                badge.style.background = 'rgba(56, 189, 248, 0.2)';
                badge.style.color = '#38bdf8';
                badge.style.borderColor = 'rgba(56, 189, 248, 0.4)';
            } else {
                badge.style.background = 'rgba(34, 197, 94, 0.18)';
                badge.style.color = '#4ade80';
                badge.style.borderColor = 'rgba(34, 197, 94, 0.35)';
            }
        }
        if (reason) reason.textContent = data.state_reason || '';
        if (ctrlCpus) ctrlCpus.textContent = `CPU ${data.control_cpus || '0'}`;
        if (wrkCpus) wrkCpus.textContent = `CPUs ${data.worker_cpus || '1-7'}`;
        if (admission) admission.textContent = `${data.active_queries || 0} / ${data.max_allowed_queries || 4} Active`;
        if (psi && data.metrics) psi.textContent = `${(data.metrics.memory_psi_avg60 || 0).toFixed(1)}%`;

        // Update Memory Ledger badges
        if (data.memory_ledger) {
            const ml = data.memory_ledger;
            const lCtrl = document.getElementById('gov-ledger-ctrl');
            const lData = document.getElementById('gov-ledger-data');
            const lTokens = document.getElementById('gov-ledger-tokens');
            const lEmerg = document.getElementById('gov-ledger-emerg');
            if (lCtrl) lCtrl.textContent = `Ctrl: ${(ml.control_plane_mb / 1024).toFixed(1)} GB`;
            if (lData) lData.textContent = `Data: ${(ml.data_plane_current_mb).toFixed(0)} MB / ${(ml.data_plane_max_mb / 1024).toFixed(1)} GB`;
            if (lTokens) lTokens.textContent = `Tokens: ${(ml.query_tokens_in_use_mb).toFixed(0)} / ${(ml.query_token_pool_mb).toFixed(0)} MB`;
            if (lEmerg) lEmerg.textContent = `Emerg: ${(ml.emergency_margin_mb / 1024).toFixed(1)} GB`;
        }

        // Update Operator View badges
        if (data.operator_view) {
            const op = data.operator_view;
            const opRunway = document.getElementById('gov-op-runway');
            const opLag = document.getElementById('gov-op-lag');
            const opTsa = document.getElementById('gov-op-tsa');
            const opCache = document.getElementById('gov-op-cache');

            if (opRunway) {
                opRunway.textContent = `Runway: >${op.queue_runway_sec || 120}s`;
                if (op.queue_loss_count > 0) {
                    opRunway.textContent += ` (${op.queue_loss_count} drops)`;
                    opRunway.style.color = '#f87171';
                }
            }
            if (opLag) {
                if (op.deferred_detection) {
                    opLag.textContent = 'Detection: Deferred';
                    opLag.style.color = '#fbbf24';
                } else {
                    opLag.textContent = `Lag: <${op.detection_lag_ms || 20}ms`;
                }
            }
            if (opTsa) opTsa.textContent = `TSA: ${op.tsa_status || 'Zamane KS'}`;
            if (opCache) opCache.textContent = `Cache: ${(op.cache_hit_ratio || 0).toFixed(0)}% Hit (${(op.cache_memory_mb || 0).toFixed(0)} MB)`;
        }
    } catch (e) {
        // silent
    }
}

// Live WebSocket Stream with bounded ring buffer
function initLiveStream() {
    const container = document.getElementById('live-log-container');
    const filterInput = document.getElementById('live-filter');
    const toggleBtn = document.getElementById('btn-toggle-live');

    toggleBtn.addEventListener('click', () => {
        isLivePaused = !isLivePaused;
        toggleBtn.textContent = isLivePaused ? 'Resume Stream' : 'Pause Stream';
        toggleBtn.className = isLivePaused ? 'btn btn-outline' : 'btn btn-primary';
    });

    // Pre-populate with recent logs from ClickHouse so stream is not blank on page load (Max 15)
    const preloadRecentLogs = async () => {
        try {
            const res = await fetch('/api/v1/logs?limit=15&range=all');
            if (!res.ok) return;
            const data = await res.json();
            if (data.logs && data.logs.length > 0 && liveLogCount === 0) {
                const recent = [...data.logs].reverse().slice(-MAX_LIVE_ROWS);
                recent.forEach(log => {
                    const row = document.createElement('div');
                    row.className = 'log-row';
                    const timeStr = log.timestamp ? log.timestamp.substring(11, 23) : '';
                    const vendorBadge = (typeof renderVendorBadge === 'function' ? renderVendorBadge(log.vendor) : (log.vendor ? `[${log.vendor}]` : '')) + ' ';
                    row.innerHTML = `
                        <span class="log-time">${timeStr}</span>
                        <span class="log-src">${log.source_ip}:${log.port}</span>
                        <span class="log-dev">${vendorBadge}${escapeHtml(log.device_name || 'UNKNOWN')}</span>
                        <span class="log-sev sev-${log.severity}">${log.severity}</span>
                        <span class="log-msg">${escapeHtml(log.message)}</span>
                    `;
                    container.appendChild(row);
                    liveLogCount++;
                });
                container.scrollTop = container.scrollHeight;
                document.getElementById('live-buffer-count').textContent = `${liveLogCount} in view (Max ${MAX_LIVE_ROWS})`;
            }
        } catch (e) {
            console.error('Failed to preload live logs:', e);
        }
    };
    preloadRecentLogs();

    const connect = () => {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        liveSocket = new WebSocket(`${protocol}//${window.location.host}/api/v1/logs/live${tenantQuerySuffix()}`);

        liveSocket.onmessage = (event) => {
            if (isLivePaused) return;
            try {
                const log = JSON.parse(event.data);
                const filter = filterInput.value.trim().toLowerCase();
                if (filter && !log.message.toLowerCase().includes(filter) && !log.source_ip.includes(filter) && !(log.vendor && log.vendor.toLowerCase().includes(filter)) && !(log.device_name && log.device_name.toLowerCase().includes(filter))) {
                    return;
                }

                const row = document.createElement('div');
                row.className = 'log-row';
                const timeStr = new Date(log.event_timestamp).toISOString().substring(11, 23);
                const vendorBadge = (typeof renderVendorBadge === 'function' ? renderVendorBadge(log.vendor) : (log.vendor ? `[${log.vendor}]` : '')) + ' ';
                row.innerHTML = `
                    <span class="log-time">${timeStr}</span>
                    <span class="log-src">${log.source_ip}:${log.source_port}</span>
                    <span class="log-dev">${vendorBadge}${escapeHtml(log.device_name || 'UNKNOWN')}</span>
                    <span class="log-sev sev-${log.severity}">${log.severity}</span>
                    <span class="log-msg">${escapeHtml(log.message)}</span>
                `;

                container.appendChild(row);
                liveLogCount++;

                // Enforce Bounded Buffer (Strictly 15 items in view)
                while (liveLogCount > MAX_LIVE_ROWS) {
                    if (container.firstChild) {
                        container.removeChild(container.firstChild);
                    }
                    liveLogCount--;
                }
                container.scrollTop = container.scrollHeight;
                document.getElementById('live-buffer-count').textContent = `${liveLogCount} in view (Max ${MAX_LIVE_ROWS})`;
            } catch (err) {
                console.error('Socket message parse error:', err);
            }
        };

        liveSocket.onclose = () => {
            setTimeout(connect, 3000);
        };
    };
    connect();
}

// Log Search Engine
function initSearch() {
    const btn = document.getElementById('btn-search-exec');
    btn.addEventListener('click', async () => {
        const q = document.getElementById('search-q').value;
        const vendor = document.getElementById('search-vendor').value;
        const severity = document.getElementById('search-severity').value;
        const source = document.getElementById('search-source').value;
        const rangeEl = document.getElementById('search-range');
        const range = rangeEl ? rangeEl.value : '24h';

        btn.disabled = true;
        btn.textContent = 'Searching ClickHouse...';

        const tbody = document.getElementById('search-results-body');
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">Executing vectorized token search...</td></tr>';

        try {
            const params = new URLSearchParams();
            if (q) params.set('q', q);
            if (vendor) params.set('vendor', vendor);
            if (severity) params.set('severity', severity);
            if (source) params.set('source', source);
            if (range) params.set('range', range);

            const res = await fetch(`/api/v1/logs?${params.toString()}`);
            const data = await res.json();

            if (!data.logs || data.logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center">No logs matching query criteria.</td></tr>';
            } else {
                tbody.innerHTML = data.logs.map(l => `
                    <tr>
                        <td class="mono-code">${l.timestamp}</td>
                        <td class="text-green">${l.source_ip}:${l.port}</td>
                        <td>
                            ${typeof renderVendorBadge === 'function' ? renderVendorBadge(l.vendor) : `<span class="badge badge-secondary">${escapeHtml(l.vendor || 'Generic')}</span>`}
                            <strong>${escapeHtml(l.device_name || 'UNKNOWN')}</strong>
                        </td>
                        <td><span class="badge sev-${l.severity}">${l.severity}</span></td>
                        <td>${l.facility}</td>
                        <td>${typeof formatApplicationBadge === 'function' ? formatApplicationBadge(l.application) : escapeHtml(l.application || '-')}</td>
                        <td>${escapeHtml(l.message)}</td>
                    </tr>
                `).join('');
            }
        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-red">Search failed: ${e.message}</td></tr>`;
        } finally {
            btn.disabled = false;
            btn.textContent = 'Search ClickHouse';
        }
    });
}

// Devices Management
async function loadDevices() {
    const tbody = document.getElementById('devices-body');
    tbody.innerHTML = '<tr><td colspan="8" class="text-center">Loading registered devices...</td></tr>';
    try {
        const res = await fetch('/api/v1/devices');
        const devices = await res.json();
        if (!devices || devices.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center">No registered devices yet. Add one or convert from unknown sources.</td></tr>';
            return;
        }

        window._registeredDevices = devices;
        tbody.innerHTML = devices.map(d => `
            <tr>
                <td><strong>${escapeHtml(d.name)}</strong>${d.tenant_slug && d.tenant_slug !== 'default' ? ` <span class="tenant-chip" title="Kiracı / Tenant">🏢 ${escapeHtml(d.tenant_slug)}</span>` : ''}</td>
                <td class="mono-code">${d.ip_address}</td>
                <td>${escapeHtml(d.vendor)}</td>
                <td>${escapeHtml(d.device_type)}</td>
                <td>
                    <span class="badge ${d.syslog_status === 'HEALTHY' ? 'badge-success' : d.syslog_status === 'WARNING' ? 'badge-warning' : 'badge-secondary'}">
                        ${d.syslog_status}
                    </span>
                </td>
                <td>${d.last_seen_at ? new Date(d.last_seen_at).toLocaleString() : 'Never'}</td>
                <td><span class="badge badge-primary">${d.timestamp_policy}</span></td>
                <td>
                    <button class="btn btn-outline" style="padding: 4px 8px; margin-right: 4px;" onclick="editDevice('${d.id}')" title="Edit Device & Assign Tenant">✏️ Edit</button>
                    <button class="btn btn-outline" style="padding: 4px 8px; margin-right: 4px;" onclick="autoDetectDevice('${d.id}', '${d.ip_address}')" title="Auto-Detect Vendor & Type from Log Stream">🔍 Detect</button>
                    <button class="btn btn-outline text-red" style="padding: 4px 8px;" onclick="deleteDevice('${d.id}')">Delete</button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-red">Failed to load devices: ${e.message}</td></tr>`;
    }
}

window.editDevice = (id) => {
    const d = (window._registeredDevices || []).find(x => x.id === id);
    if (!d) return;
    const modal = document.getElementById('device-modal');
    const badge = document.getElementById('modal-auto-discovery-badge');
    if (badge) badge.style.display = 'none';

    const nameInp = document.getElementById('dev-name');
    const ipInp = document.getElementById('dev-ip');
    const vendorSel = document.getElementById('dev-vendor');
    const typeSel = document.getElementById('dev-type');
    const groupSel = document.getElementById('dev-group');
    const tenantSel = document.getElementById('dev-tenant');

    if (nameInp) nameInp.value = d.name || '';
    if (ipInp) {
        ipInp.value = d.ip_address || '';
        ipInp.disabled = true;
    }
    if (vendorSel && d.vendor) vendorSel.value = d.vendor;
    if (typeSel && d.device_type) typeSel.value = d.device_type;
    if (groupSel && d.group_name) groupSel.value = d.group_name;

    populateDeviceTenantSelect();
    if (tenantSel) tenantSel.value = d.tenant_slug || 'default';

    window._editingDeviceId = d.id;
    const title = modal.querySelector('.modal-header h3');
    if (title) title.textContent = window.i18n ? window.i18n.t('modal_edit_device_title', 'Edit Device & Assign Tenant') : 'Edit Device & Assign Tenant';
    const saveBtn = document.getElementById('btn-save-device');
    if (saveBtn) saveBtn.textContent = window.i18n ? window.i18n.t('btn_save_changes', 'Save Changes') : 'Save Changes';

    if (modal) modal.style.display = 'flex';
};

window.deleteDevice = async (id) => {
    if (!confirm('Are you sure you want to delete this registered device?')) return;
    try {
        const res = await fetch(`/api/v1/devices?id=${id}`, { method: 'DELETE' });
        if (!res.ok) throw new Error(await res.text());
        loadDevices();
    } catch (e) {
        alert('Failed deleting device: ' + e.message);
    }
};

window.autoDetectDevice = async (id, ip) => {
    try {
        const res = await fetch('/api/v1/devices/auto-detect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: id, ip_address: ip }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Auto-detect failed');
        alert(`Auto-detection result for ${ip}:\nVendor: ${data.vendor}\nDevice Type: ${data.device_type}\nConfidence: ${data.confidence}\nHostname: ${data.hostname || 'N/A'}`);
        loadDevices();
    } catch (e) {
        alert('Auto-detection error: ' + e.message);
    }
};

function getDeviceTypeBadge(type) {
    if (!type || type === 'Generic Syslog' || type === 'Unknown') {
        return `<span class="badge badge-secondary">Generic Syslog</span>`;
    }
    const t = type.toLowerCase();
    if (t.includes('firewall')) {
        return `<span class="badge" style="background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3);">🛡️ Firewall</span>`;
    }
    if (t.includes('switch')) {
        return `<span class="badge" style="background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3);">🔀 Switch</span>`;
    }
    if (t.includes('router')) {
        return `<span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3);">🌐 Router</span>`;
    }
    if (t.includes('balancer') || t.includes('adc') || t.includes('load balancer')) {
        return `<span class="badge" style="background: rgba(14, 165, 233, 0.15); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.3);">⚖️ Load Balancer</span>`;
    }
    if (t.includes('server')) {
        return `<span class="badge" style="background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3);">🖥️ Server</span>`;
    }
    if (t.includes('wireless') || t.includes('access point')) {
        return `<span class="badge" style="background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3);">📶 Wireless</span>`;
    }
    if (t.includes('vpn')) {
        return `<span class="badge" style="background: rgba(236, 72, 153, 0.15); color: #f472b6; border: 1px solid rgba(236, 72, 153, 0.3);">🔒 VPN Gateway</span>`;
    }
    return `<span class="badge badge-secondary">${escapeHtml(type)}</span>`;
}

function getConfidenceBadge(conf) {
    const c = (conf || 'LOW').toUpperCase();
    if (c === 'HIGH') return `<span class="badge badge-success">HIGH</span>`;
    if (c === 'MEDIUM') return `<span class="badge badge-warning">MED</span>`;
    return `<span class="badge badge-secondary">LOW</span>`;
}

// Auto-Discovered Sources
async function loadUnregisteredSources() {
    const tbody = document.getElementById('unreg-body');
    tbody.innerHTML = '<tr><td colspan="9" class="text-center">Loading detected sources...</td></tr>';
    try {
        const tenantParam = (currentTenantContext && currentTenantContext !== 'all' && currentTenantContext !== '*') ? `?tenant=${encodeURIComponent(currentTenantContext)}` : '';
        const res = await fetch(`/api/v1/unregistered${tenantParam}`);
        const sources = await res.json();
        if (!sources || sources.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="text-center">No unregistered syslog traffic detected.</td></tr>';
            return;
        }

        window._unregisteredSources = sources;
        tbody.innerHTML = sources.map((s, idx) => `
            <tr>
                <td class="mono-code text-yellow">${escapeHtml(s.ip_address)}</td>
                <td><span class="badge badge-outline" style="font-size: 11px;">🏢 ${escapeHtml(s.tenant_slug || 'default')}</span></td>
                <td><strong>${escapeHtml(s.hostname && s.hostname !== '-' ? s.hostname : (s.detected_vendor ? s.detected_vendor + '-Asset' : 'Unknown'))}</strong></td>
                <td>${getDeviceTypeBadge(s.detected_type)}</td>
                <td><span class="badge badge-outline">${escapeHtml(s.detected_vendor || 'Generic')}</span></td>
                <td>${getConfidenceBadge(s.confidence)}</td>
                <td>${Number(s.packet_count).toLocaleString()}</td>
                <td>${new Date(s.last_seen_at).toLocaleString()}</td>
                <td>
                    <button class="btn btn-primary btn-register-unreg" data-idx="${idx}" style="padding: 4px 10px; font-size: 12px;">+ Onboard</button>
                </td>
            </tr>
        `).join('');

        tbody.querySelectorAll('.btn-register-unreg').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const idx = parseInt(btn.getAttribute('data-idx'), 10);
                const s = window._unregisteredSources[idx];
                if (s) {
                    onboardDevice(s.ip_address, s.last_raw_sample || '', s);
                }
            });
        });
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-red">Failed: ${e.message}</td></tr>`;
    }
}

window.onboardDevice = (ip, sample = '', sourceObj = null) => {
    window._editingDeviceId = null;
    const ipInput = document.getElementById('dev-ip');
    const nameInput = document.getElementById('dev-name');
    const vendorSelect = document.getElementById('dev-vendor');
    const typeSelect = document.getElementById('dev-type');
    const groupSelect = document.getElementById('dev-group');
    const modalBadge = document.getElementById('modal-auto-discovery-badge');
    const badgeText = document.getElementById('auto-discovery-badge-text');
    const confBadge = document.getElementById('auto-discovery-confidence-badge');

    if (ipInput) {
        ipInput.value = ip;
        ipInput.disabled = false;
    }

    let detectedVendor = (sourceObj && sourceObj.detected_vendor) || '';
    let detectedType = (sourceObj && sourceObj.detected_type) || '';
    let hostname = (sourceObj && sourceObj.hostname) || '';
    let confidence = (sourceObj && sourceObj.confidence) || '';

    if (!detectedVendor && sample) {
        const sLower = sample.toLowerCase();
        if (sLower.includes('fortinet') || sLower.includes('fortigate') || sLower.includes('devid=fg') || sLower.includes('type="traffic"')) {
            detectedVendor = 'Fortinet';
            detectedType = 'Firewall';
            confidence = 'HIGH';
        } else if (sLower.includes('watchguard') || sLower.includes('firebox') || sample.includes('msg_id=')) {
            detectedVendor = 'WatchGuard';
            detectedType = 'Firewall';
            confidence = 'HIGH';
        } else if (sLower.includes('cisco') || sample.includes('%SYS-') || sample.includes('%LINK-') || sample.includes('%ASA-')) {
            detectedVendor = 'Cisco';
            detectedType = sample.includes('%ASA-') ? 'Firewall' : 'Switch';
            confidence = 'HIGH';
        } else if (sLower.includes('palo alto') || sample.includes('TRAFFIC,') || sample.includes('THREAT,')) {
            detectedVendor = 'Palo Alto';
            detectedType = 'Firewall';
            confidence = 'HIGH';
        } else if (sLower.includes('mikrotik') || sample.includes('system,info') || sample.includes('firewall,info')) {
            detectedVendor = 'MikroTik';
            detectedType = 'Router';
            confidence = 'HIGH';
        } else if (sLower.includes('huawei') || sLower.includes('cloudengine') || sLower.includes('quidway') || sample.includes('%%01')) {
            detectedVendor = 'Huawei';
            detectedType = (sLower.includes('usg') || sLower.includes('firewall')) ? 'Firewall' : 'Switch';
            confidence = 'HIGH';
        } else if (sLower.includes('tmm[') || sLower.includes('bigip') || sLower.includes('f5 networks') || sLower.includes('big-ip')) {
            detectedVendor = 'F5 Networks';
            detectedType = 'Load Balancer';
            confidence = 'HIGH';
        }
    }

    if (hostname && hostname !== '-' && hostname !== 'unknown') {
        if (nameInput) nameInput.value = hostname;
    } else if (detectedVendor && detectedType) {
        if (nameInput) nameInput.value = `${detectedVendor}-${detectedType.replace(/\s+/g, '')}-${ip.replace(/\./g, '-')}`;
    } else {
        if (nameInput) nameInput.value = `Device-${ip.replace(/\./g, '-')}`;
    }

    if (detectedVendor && vendorSelect) {
        vendorSelect.value = detectedVendor;
    }
    if (detectedType && typeSelect) {
        typeSelect.value = detectedType;
    }

    if (groupSelect) {
        if (detectedType === 'Firewall') groupSelect.value = 'Perimeter Firewalls';
        else if (detectedType === 'Switch' || detectedType === 'Router') groupSelect.value = 'Core Switches & Routers';
        else if (detectedType === 'Load Balancer') groupSelect.value = 'Application Delivery & ADC';
        else if (detectedType === 'Server') groupSelect.value = 'Identity & Auth Servers';
        else groupSelect.value = 'Default';
    }

    populateDeviceTenantSelect();
    const tenantSel = document.getElementById('dev-tenant');
    if (tenantSel) {
        if (sourceObj && sourceObj.tenant_slug) {
            tenantSel.value = sourceObj.tenant_slug;
        } else if (currentTenantContext && currentTenantContext !== 'all' && currentTenantContext !== '*') {
            tenantSel.value = currentTenantContext;
        }
    }

    if (modalBadge) {
        if (detectedVendor || detectedType) {
            modalBadge.style.display = 'block';
            if (badgeText) badgeText.textContent = `🎯 Auto-Discovered: ${detectedVendor || 'Generic'} ${detectedType || 'Device'}${hostname && hostname !== '-' ? ' (' + hostname + ')' : ''}`;
            if (confBadge) {
                confBadge.textContent = confidence || 'HIGH';
                confBadge.className = 'badge ' + (confidence === 'HIGH' ? 'badge-success' : confidence === 'MEDIUM' ? 'badge-warning' : 'badge-secondary');
            }
        } else {
            modalBadge.style.display = 'none';
        }
    }

    const modal = document.getElementById('device-modal');
    if (modal) {
        const title = modal.querySelector('.modal-header h3');
        if (title) title.textContent = window.i18n ? window.i18n.t('modal_register_source', 'Register Syslog Source') : 'Register Syslog Source';
        const saveBtn = document.getElementById('btn-save-device');
        if (saveBtn) saveBtn.textContent = window.i18n ? window.i18n.t('btn_save_asset', 'Save Asset') : 'Save Asset';
        modal.style.display = 'flex';
    }
};

// Archives & KamuSM Zaman Damgası
async function loadArchives() {
    const tbody = document.getElementById('archives-body');
    if (!tbody) return;
    const t = (k, fb) => (window.i18n ? window.i18n.t(k) : (fb || k));
    tbody.innerHTML = `<tr><td colspan="10" class="text-center">${t('archives_loading', 'Loading archives...')}</td></tr>`;
    try {
        let url = '/api/v1/archives';
        if (currentTenantContext && currentTenantContext !== 'all' && currentTenantContext !== '*') {
            url += `?tenant=${encodeURIComponent(currentTenantContext)}`;
        }
        const res = await fetch(url);
        const list = await res.json();
        if (!list || list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="10" class="text-center">${t('archives_empty', 'No archives generated yet. Click "Create Archive Now" above.')}</td></tr>`;
            return;
        }

        tbody.innerHTML = list.map(a => {
            let badgeClass = 'badge-warning';
            let badgeText = a.timestamp_status || 'PENDING';
            if (badgeText === 'VERIFIED' || badgeText === 'STAMPED' || badgeText === 'COMMITTED') {
                badgeClass = 'badge-success';
                badgeText = '🛡️ ' + badgeText;
            } else if (badgeText === 'FAILED') {
                badgeClass = 'badge-danger';
                badgeText = '❌ FAILED';
            } else if (badgeText === 'TSA_PENDING' || badgeText === 'IN_PROGRESS') {
                badgeClass = 'badge-warning';
                badgeText = '⏳ ' + badgeText;
            } else if (badgeText === 'SEALED') {
                badgeClass = 'badge-secondary';
                badgeText = '🔒 SEALED';
            }
            const isStamped = (a.timestamp_status === 'STAMPED' || a.timestamp_status === 'VERIFIED' || a.timestamp_status === 'COMMITTED');

            return `
            <tr>
                <td><strong>${escapeHtml(a.archive_name)}</strong></td>
                <td><span class="badge badge-outline" style="font-size: 0.78rem;">🏢 ${escapeHtml(a.tenant || 'default')}</span></td>
                <td>${new Date(a.start_timestamp).toISOString().substring(0, 16)}</td>
                <td>${new Date(a.end_timestamp).toISOString().substring(0, 16)}</td>
                <td>${Number(a.record_count).toLocaleString()}</td>
                <td>${(a.archive_size / 1024).toFixed(1)} KB</td>
                <td class="mono-code" title="${a.hash_value}">${a.hash_value.substring(0, 16)}...</td>
                <td>
                    <span class="badge ${badgeClass}">
                        ${badgeText}
                    </span>
                </td>
                <td class="mono-code">${a.timestamp_evidence_path ? a.timestamp_evidence_path.split('/').pop() : 'Pending'}</td>
                <td>
                    <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                        <a href="/api/v1/archives/download?id=${a.id}&type=bundle" class="btn btn-primary" style="padding: 3px 8px; font-size: 11px; text-decoration: none;" title="Download complete compliance package (.zip containing logs, .zd evidence, and .sha256 hash)" download>
                            ${t('btn_bundle_dl', '📦 Bundle (.zip)')}
                        </a>
                        <a href="/api/v1/archives/download?id=${a.id}&type=archive" class="btn btn-outline" style="padding: 3px 8px; font-size: 11px; text-decoration: none;" title="Download raw compressed logs (.jsonl.gz)" download>
                            ${t('btn_logs_dl', '📄 Logs (.gz)')}
                        </a>
                        ${isStamped && a.timestamp_evidence_path ? `
                        <a href="/api/v1/archives/download?id=${a.id}&type=evidence" class="btn btn-outline" style="padding: 3px 8px; font-size: 11px; text-decoration: none;" title="Download legal proof / KamuSM timestamp (.zd)" download>
                            ${t('btn_evidence_dl', '🛡️ Evidence (.zd)')}
                        </a>` : `
                        <button onclick="reconcileArchives('${a.id}')" class="btn btn-warning" style="padding: 3px 8px; font-size: 11px;" title="Bekleyen arşivi yeniden mühürle / Re-stamp pending archive">
                            🔄 ${t('btn_restamp', 'Mühürle')}
                        </button>`}
                    </div>
                </td>
            </tr>
        `}).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="10" class="text-center text-red">${t('archives_failed', 'Failed to load archives')}: ${e.message}</td></tr>`;
    }
}

window.reconcileArchives = async function(archiveId) {
    const isTr = (window.i18n && window.i18n.currentLang === 'tr');
    const t = (k, fb) => (window.i18n ? window.i18n.t(k) : (fb || k));
    showToast(t('reconcile_starting', isTr ? 'Bekleyen arşivler mühürleniyor...' : 'Reconciling and stamping pending archives...'), 'info');
    try {
        const url = archiveId ? `/api/v1/archives/reconcile?id=${encodeURIComponent(archiveId)}` : '/api/v1/archives/reconcile';
        const res = await fetch(url, { method: 'POST' });
        
        // Read text safely first so stream consumption never conflicts
        const rawText = await res.text();
        let data = null;
        try {
            data = JSON.parse(rawText.trim());
        } catch (e) {
            data = null;
        }

        if (!res.ok) {
            const errMsg = data ? (data.message || data.error || `HTTP ${res.status}`) : (rawText.substring(0, 150) || res.statusText);
            showToast(`${isTr ? 'Hata' : 'Error'} (${res.status}): ${errMsg}`, 'error');
            return;
        }

        // Server returned 200 OK
        if (data) {
            if (data.status === 'success' || data.reconciled !== undefined) {
                showToast(`✓ ${data.message || (isTr ? 'Arşivler başarıyla mühürlendi.' : 'Archives successfully stamped.')}`, 'success');
                if (typeof loadArchives === 'function') loadArchives();
            } else {
                showToast(`${isTr ? 'Hata' : 'Error'}: ${data.message || data.error || (isTr ? 'Mühürleme başarısız' : 'Stamping failed')}`, 'error');
            }
        } else {
            // Server returned 200 OK with plain text (e.g. from earlier backend or proxy)
            const msg = rawText.trim() || (isTr ? 'Arşiv mühürleme işlemi tamamlandı.' : 'Archive reconciliation completed.');
            showToast(`✓ ${msg}`, 'success');
            if (typeof loadArchives === 'function') loadArchives();
        }
    } catch (e) {
        showToast(`${isTr ? 'Hata' : 'Error'}: ${e.message}`, 'error');
    }
};

// Toast Notification System
function showToast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none;';
        document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    const bg = type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#3b82f6';
    toast.style.cssText = `background:${bg};color:#fff;padding:10px 16px;border-radius:6px;font-size:13px;font-weight:500;box-shadow:0 4px 12px rgba(0,0,0,0.25);pointer-events:auto;transition:all 0.3s ease;opacity:0;transform:translateY(10px);`;
    toast.textContent = message;
    container.appendChild(toast);
    requestAnimationFrame(() => {
        toast.style.opacity = '1';
        toast.style.transform = 'translateY(0)';
    });
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        setTimeout(() => toast.remove(), 300);
    }, 4500);
}

// Universal Clipboard Helper
function copyToClipboard(text, successMsg) {
    if (!text) return;

    const onCopied = () => {
        if (typeof showToast === 'function') {
            showToast(successMsg || 'Panoya kopyalandı!', 'success');
        }
    };

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(onCopied).catch(err => {
            console.warn('navigator.clipboard error, fallback to execCommand:', err);
            fallbackCopyText(text, onCopied);
        });
    } else {
        fallbackCopyText(text, onCopied);
    }
}

function fallbackCopyText(text, callback) {
    try {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        textArea.setAttribute('readonly', '');
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        const successful = document.execCommand('copy');
        document.body.removeChild(textArea);
        if (successful && typeof callback === 'function') {
            callback();
        }
    } catch (err) {
        console.error('Fallback clipboard error:', err);
        window.prompt('Kopyalayınız / Copy to clipboard:', text);
    }
}
window.copyToClipboard = copyToClipboard;

function initArchiveTrigger() {
    const btn = document.getElementById('btn-manual-archive');
    if (!btn) return;
    btn.addEventListener('click', async () => {
        if (btn.disabled) return;
        btn.blur();
        btn.disabled = true;
        btn.textContent = 'Generating & Stamping...';
        try {
            const res = await fetch('/api/v1/archives/create', { method: 'POST' });
            if (!res.ok) {
                const err = await res.text();
                showToast('Archive error: ' + err, 'error');
            } else {
                showToast('✓ Archive created and submitted to KamuSM Zaman Damgası engine!', 'success');
                loadArchives();
            }
        } catch (e) {
            showToast('Request failed: ' + e.message, 'error');
        } finally {
            // Keep button disabled for 5 seconds after response to prevent rapid re-triggering
            setTimeout(() => {
                btn.disabled = false;
                btn.textContent = 'Create Archive Now';
            }, 5000);
        }
    });
}

function initManualArchiveModal() {
    const modal = document.getElementById('modal-manual-archive');
    const openBtn = document.getElementById('btn-manual-archive-sealing');
    const closeBtn = document.getElementById('btn-close-manual-archive');
    const cancelBtn = document.getElementById('btn-cancel-manual-archive');
    const submitBtn = document.getElementById('btn-submit-manual-archive');

    const fromInp = document.getElementById('manual-archive-from');
    const toInp = document.getElementById('manual-archive-to');
    const basisInp = document.getElementById('manual-archive-basis');
    const reasonInp = document.getElementById('manual-archive-reason');
    const errBox = document.getElementById('manual-archive-error');
    const succBox = document.getElementById('manual-archive-success');

    if (!modal || !openBtn) return;

    const hideModal = () => {
        modal.style.display = 'none';
        if (errBox) errBox.style.display = 'none';
        if (succBox) succBox.style.display = 'none';
    };

    const showModal = () => {
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
        const formatLocalDT = (d) => {
            const pad = (n) => String(n).padStart(2, '0');
            return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
        };
        if (fromInp) fromInp.value = formatLocalDT(oneHourAgo);
        if (toInp) toInp.value = formatLocalDT(now);
        if (reasonInp) reasonInp.value = '';
        if (errBox) { errBox.style.display = 'none'; errBox.textContent = ''; }
        if (succBox) { succBox.style.display = 'none'; succBox.textContent = ''; }
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = window.i18n ? window.i18n.t('btn_seal_now', 'Mühürlemeyi Başlat') : 'Mühürlemeyi Başlat';
        }
        modal.style.display = 'flex';
    };

    openBtn.addEventListener('click', showModal);
    if (closeBtn) closeBtn.addEventListener('click', hideModal);
    if (cancelBtn) cancelBtn.addEventListener('click', hideModal);

    modal.addEventListener('click', (e) => {
        if (e.target === modal) hideModal();
    });

    if (submitBtn) {
        submitBtn.addEventListener('click', async () => {
            if (errBox) errBox.style.display = 'none';
            if (succBox) succBox.style.display = 'none';

            const fromVal = fromInp ? fromInp.value : '';
            const toVal = toInp ? toInp.value : '';
            const basisVal = basisInp ? basisInp.value : 'receipt_time';
            const reasonVal = reasonInp ? reasonInp.value.trim() : '';

            if (!fromVal || !toVal) {
                if (errBox) {
                    errBox.textContent = window.i18n ? window.i18n.t('err_archive_times_required', 'Başlangıç ve bitiş zamanları zorunludur.') : 'Başlangıç ve bitiş zamanları zorunludur.';
                    errBox.style.display = 'block';
                }
                return;
            }

            const fromDate = new Date(fromVal);
            const toDate = new Date(toVal);
            if (toDate <= fromDate) {
                if (errBox) {
                    errBox.textContent = window.i18n ? window.i18n.t('err_archive_time_order', 'Bitiş zamanı başlangıç zamanından sonra olmalıdır.') : 'Bitiş zamanı başlangıç zamanından sonra olmalıdır.';
                    errBox.style.display = 'block';
                }
                return;
            }

            if (!reasonVal) {
                if (errBox) {
                    errBox.textContent = window.i18n ? window.i18n.t('err_archive_reason_required', 'Lütfen talep nedeni / soruşturma referansı girin.') : 'Lütfen talep nedeni / soruşturma referansı girin.';
                    errBox.style.display = 'block';
                }
                return;
            }

            submitBtn.disabled = true;
            submitBtn.textContent = 'Mühürleniyor / Sealing...';

            try {
                const res = await fetch('/api/v1/archives/manual', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        from: fromDate.toISOString(),
                        to: toDate.toISOString(),
                        time_basis: basisVal,
                        reason: reasonVal
                    })
                });

                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.error || 'Manuel mühürleme başlatılamadı');
                }

                if (succBox) {
                    succBox.textContent = `✓ Mühürleme görevi başarıyla başlatıldı (İş No: ${data.job_id || data.id || 'OK'}). Kanıtlar hazırlanıyor.`;
                    succBox.style.display = 'block';
                }
                showToast('✓ 5651 RFC 3161 Evidence sealing job submitted!', 'success');
                setTimeout(() => {
                    hideModal();
                    if (typeof loadArchives === 'function') loadArchives();
                }, 1500);
            } catch (err) {
                if (errBox) {
                    errBox.textContent = err.message;
                    errBox.style.display = 'block';
                }
                showToast('Hata: ' + err.message, 'error');
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = window.i18n ? window.i18n.t('btn_seal_now', 'Mühürlemeyi Başlat') : 'Mühürlemeyi Başlat';
            }
        });
    }
}

function initDeviceModal() {
    const modal = document.getElementById('device-modal');
    const addBtn = document.getElementById('btn-add-device-modal');
    if (addBtn) {
        addBtn.addEventListener('click', () => {
            window._editingDeviceId = null;
            const badge = document.getElementById('modal-auto-discovery-badge');
            if (badge) badge.style.display = 'none';
            const nameInp = document.getElementById('dev-name');
            const ipInp = document.getElementById('dev-ip');
            if (nameInp) nameInp.value = '';
            if (ipInp) {
                ipInp.value = '';
                ipInp.disabled = false;
            }
            const title = modal.querySelector('.modal-header h3');
            if (title) title.textContent = window.i18n ? window.i18n.t('modal_register_source', 'Register Syslog Source') : 'Register Syslog Source';
            const saveBtn = document.getElementById('btn-save-device');
            if (saveBtn) saveBtn.textContent = window.i18n ? window.i18n.t('btn_save_asset', 'Save Asset') : 'Save Asset';
            populateDeviceTenantSelect();
            modal.style.display = 'flex';
        });
    }
    const closeBtn = document.getElementById('btn-close-modal');
    if (closeBtn) closeBtn.addEventListener('click', () => { window._editingDeviceId = null; modal.style.display = 'none'; });
    const cancelBtn = document.getElementById('btn-cancel-modal');
    if (cancelBtn) cancelBtn.addEventListener('click', () => { window._editingDeviceId = null; modal.style.display = 'none'; });

    const btnOnboardAll = document.getElementById('btn-onboard-all-unreg');
    if (btnOnboardAll) {
        btnOnboardAll.addEventListener('click', async () => {
            const targetTenant = (currentTenantContext && currentTenantContext !== 'all' && currentTenantContext !== '*') ? currentTenantContext : 'default';
            if (!confirm(`Automatically onboard and register all auto-discovered network assets into tenant '${targetTenant}'?`)) return;
            btnOnboardAll.disabled = true;
            btnOnboardAll.innerHTML = '<span>⏳</span> Onboarding Assets...';
            try {
                const res = await fetch('/api/v1/unregistered/onboard-all', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ tenant: targetTenant })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Failed onboarding assets');
                showToast(`✓ Successfully auto-onboarded ${data.onboarded || 0} discovered device(s) into '${targetTenant}'!`, 'success');
                loadUnregisteredSources();
                loadDevices();
            } catch (e) {
                showToast('Failed onboarding: ' + e.message, 'error');
            } finally {
                btnOnboardAll.disabled = false;
                btnOnboardAll.innerHTML = '<span>⚡</span> <span data-i18n="btn_onboard_all">Auto-Onboard All Discovered Assets</span>';
            }
        });
    }

    document.getElementById('btn-save-device').addEventListener('click', async () => {
        const isEdit = !!window._editingDeviceId;
        const payload = {
            name: document.getElementById('dev-name').value.trim(),
            ip_address: document.getElementById('dev-ip').value.trim(),
            vendor: document.getElementById('dev-vendor').value,
            device_type: document.getElementById('dev-type').value,
            group_name: document.getElementById('dev-group') ? document.getElementById('dev-group').value : 'Default',
        };
        if (isEdit) {
            payload.id = window._editingDeviceId;
        }
        const tenantSel = document.getElementById('dev-tenant');
        if (tenantSel && tenantSel.value) payload.tenant_slug = tenantSel.value;
        try {
            const res = await fetch('/api/v1/devices', {
                method: isEdit ? 'PUT' : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            if (!res.ok) throw new Error(await res.text());
            modal.style.display = 'none';
            window._editingDeviceId = null;
            showToast(isEdit ? '✓ Device & Tenant assignment updated successfully' : '✓ Device asset registered successfully', 'success');
            loadDevices();
            loadUnregisteredSources();
        } catch (e) {
            showToast('Failed saving asset: ' + e.message, 'error');
        }
    });
}

async function loadHealthTelemetry() {
    const body = document.getElementById('health-telemetry-body');
    if (!body) return;
    body.innerHTML = 'Loading health telemetry...';
    try {
        const res = await fetch('/api/v1/system/health');
        const h = await res.json();
        const isStrict = h.strict_device_filtering === true || h.strict_device_filtering === 'true';
        body.innerHTML = `
            <div class="status-row"><span>Node Name</span><strong>${h.node}</strong></div>
            <div class="status-row"><span>ClickHouse Storage</span><span class="badge badge-success">${h.clickhouse}</span></div>
            <div class="status-row"><span>PostgreSQL Metadata</span><span class="badge badge-success">${h.postgres}</span></div>
            <div class="status-row"><span>Ingestion Security Gate</span><span class="badge ${isStrict ? 'badge-warning' : 'badge-success'}">${isStrict ? 'Strict Zero-Trust (Authorized Only)' : 'Permissive (Auto-Discovery)'}</span></div>
            <div class="status-row"><span>Dropped Unauthorized Packets</span><span class="badge ${h.dropped_unauthorized > 0 ? 'badge-danger' : 'badge-secondary'}">${Number(h.dropped_unauthorized || 0).toLocaleString()}</span></div>
            <div class="status-row"><span>Ingestion Channel Queue Depth</span><span>${h.queue_depth}</span></div>
            <div class="status-row"><span>Packets Received</span><span>${Number(h.packets_rx).toLocaleString()}</span></div>
            <div class="status-row"><span>Events Parsed</span><span>${Number(h.events_parsed).toLocaleString()}</span></div>
            <div class="status-row"><span>Events Inserted (ClickHouse)</span><span class="text-green">${Number(h.events_inserted).toLocaleString()}</span></div>
            <div class="status-row"><span>Insert Errors</span><span>${h.insert_errors}</span></div>
        `;

        const badgeDropped = document.getElementById('badge-dropped-unauthorized');
        if (badgeDropped) {
            badgeDropped.textContent = Number(h.dropped_unauthorized || 0).toLocaleString();
        }

        if (h.version) {
            const brandVer = document.getElementById('brand-version');
            if (brandVer) brandVer.textContent = h.version;
            const updVer = document.getElementById('upd-current-version');
            if (updVer) updVer.textContent = h.version;
        }
    } catch (e) {
        body.innerHTML = `<span class="text-red">Health probe error: ${e.message}</span>`;
    }
}

// TÜBİTAK KamuSM Settings
function updateStampingUI() {
    const modeEl = document.getElementById('setting-stamping-mode');
    if (!modeEl) return;
    const mode = modeEl.value;

    const banner = document.getElementById('stamping-mode-banner');
    const title = document.getElementById('stamping-mode-title');
    const desc = document.getElementById('stamping-mode-desc');
    const credBox = document.getElementById('kamusm-credentials-box');
    const statusBadge = document.getElementById('kamusm-field-status');

    if (mode === 'internal') {
        if (banner) {
            banner.className = 'alert-box alert-info';
            title.textContent = 'Internal Cryptographic Authority Active';
            desc.textContent = 'Archives will be signed and sealed using the built-in SHA-256 HMAC cryptographic engine. No TÜBİTAK account, credentials, or network credits are required.';
        }
        if (credBox) credBox.style.opacity = '0.65';
        if (statusBadge) {
            statusBadge.className = 'badge badge-secondary';
            statusBadge.textContent = 'Optional (Internal Mode Active)';
        }
    } else if (mode === 'kamusm') {
        if (banner) {
            banner.className = 'alert-box alert-success';
            title.textContent = 'Official TÜBİTAK KamuSM Mode Active';
            desc.textContent = 'Archives will be submitted to the official TÜBİTAK KamuSM TSS server (RFC 3161 compliant). Active Customer Account Number and Password are required below.';
        }
        if (credBox) credBox.style.opacity = '1.0';
        if (statusBadge) {
            statusBadge.className = 'badge badge-primary';
            statusBadge.textContent = 'Required for KamuSM Mode';
        }
    } else if (mode === 'disabled') {
        if (banner) {
            banner.className = 'alert-box alert-warning';
            title.textContent = 'Law No. 5651 Timestamping Disabled';
            desc.textContent = 'External TÜBİTAK and internal cryptographic stamping are both disabled. Log archives will be hashed (SHA-256) and compressed without digital signature tokens.';
        }
        if (credBox) credBox.style.opacity = '0.4';
        if (statusBadge) {
            statusBadge.className = 'badge badge-danger';
            statusBadge.textContent = 'Stamping Disabled';
        }
    }
}

// Law No. 5651 & TÜBİTAK Settings Controller
function updateIngestionSecurityUI(isStrict) {
    const select = document.getElementById('setting-strict-filtering');
    if (select) select.value = isStrict ? 'true' : 'false';

    const gateStatus = document.getElementById('filter-gate-status');
    const badge = document.getElementById('strict-filter-badge');
    const banner = document.getElementById('filtering-mode-banner');
    const title = document.getElementById('filtering-mode-title');
    const desc = document.getElementById('filtering-mode-desc');

    if (isStrict) {
        if (gateStatus) {
            gateStatus.className = 'badge badge-warning';
            gateStatus.textContent = 'Strict Zero-Trust (Filtering ON)';
        }
        if (badge) {
            badge.className = 'badge badge-warning';
            badge.textContent = 'Zero-Trust Gate Active';
        }
        if (banner) {
            banner.className = 'alert-box alert-warning';
            if (title) title.textContent = 'Strict Zero-Trust Filtering Active';
            if (desc) desc.textContent = 'Packets from IP addresses NOT registered in Asset Management are silently discarded at the network boundary. Unauthorized senders cannot flood ClickHouse or inject logs.';
        }
    } else {
        if (gateStatus) {
            gateStatus.className = 'badge badge-success';
            gateStatus.textContent = 'Permissive Auto-Discovery';
        }
        if (badge) {
            badge.className = 'badge badge-info';
            badge.textContent = 'Auto-Discovery Active';
        }
        if (banner) {
            banner.className = 'alert-box alert-info';
            if (title) title.textContent = 'Permissive Auto-Discovery Active';
            if (desc) desc.textContent = 'Incoming syslog packets from any IP address are accepted. Unregistered senders are logged in "Auto-Discovered Senders" for review and 1-click onboarding.';
        }
    }
}

async function loadSettings() {
    try {
        const res = await fetch('/api/v1/settings');
        if (!res.ok) return;
        const s = await res.json();

        const modeEl = document.getElementById('setting-stamping-mode');
        if (modeEl) {
            modeEl.value = s.stamping_mode || 'internal';
        }

        const fallbackEl = document.getElementById('setting-auto-fallback');
        if (fallbackEl) {
            fallbackEl.checked = s.auto_fallback !== 'false';
        }

        if (s.kamusm_server_url && document.getElementById('setting-server-url')) {
            document.getElementById('setting-server-url').value = s.kamusm_server_url;
        }
        if (s.kamusm_server_port && document.getElementById('setting-server-port')) {
            document.getElementById('setting-server-port').value = s.kamusm_server_port;
        }
        if (s.kamusm_customer_no && document.getElementById('setting-customer-no')) {
            document.getElementById('setting-customer-no').value = s.kamusm_customer_no;
        }
        if (s.kamusm_customer_password && s.kamusm_customer_password !== '********' && document.getElementById('setting-customer-pass')) {
            document.getElementById('setting-customer-pass').value = s.kamusm_customer_password;
        }
        if (s.kamusm_digest_type && document.getElementById('setting-digest')) {
            document.getElementById('setting-digest').value = s.kamusm_digest_type;
        }
        if (s.archive_interval && document.getElementById('setting-archive-interval')) {
            document.getElementById('setting-archive-interval').value = s.archive_interval;
        }
        if (s.retention_days && document.getElementById('setting-retention-days')) {
            document.getElementById('setting-retention-days').value = s.retention_days;
        }
        if (s.storage_fifo_threshold_pct && document.getElementById('setting-fifo-threshold')) {
            document.getElementById('setting-fifo-threshold').value = s.storage_fifo_threshold_pct;
            const badge = document.getElementById('fifo-threshold-val-badge');
            if (badge) badge.textContent = s.storage_fifo_threshold_pct + '%';
            const display = document.getElementById('fifo-threshold-display');
            if (display) display.textContent = s.storage_fifo_threshold_pct;
        }
        if (s.syslog_udp_listen_addr && document.getElementById('setting-udp-listen-addr')) {
            document.getElementById('setting-udp-listen-addr').value = s.syslog_udp_listen_addr;
        }
        if (s.syslog_tcp_listen_addr && document.getElementById('setting-tcp-listen-addr')) {
            document.getElementById('setting-tcp-listen-addr').value = s.syslog_tcp_listen_addr;
        }
        if (s.syslog_tls_listen_addr && document.getElementById('setting-tls-listen-addr')) {
            document.getElementById('setting-tls-listen-addr').value = s.syslog_tls_listen_addr;
        }

        // Active Directory & LDAP Settings
        if (document.getElementById('setting-ad-enabled')) {
            document.getElementById('setting-ad-enabled').checked = s.ad_enabled === 'true' || s.ad_enabled === true;
        }
        if (s.ad_server && document.getElementById('setting-ad-server')) {
            document.getElementById('setting-ad-server').value = s.ad_server;
        }
        if (s.ad_port && document.getElementById('setting-ad-port')) {
            document.getElementById('setting-ad-port').value = s.ad_port;
        }
        if (s.ad_default_role && document.getElementById('setting-ad-default-role')) {
            document.getElementById('setting-ad-default-role').value = s.ad_default_role;
        }
        if (document.getElementById('setting-ad-use-ssl')) {
            document.getElementById('setting-ad-use-ssl').checked = s.ad_use_ssl === 'true' || s.ad_use_ssl === true;
        }
        if (document.getElementById('setting-ad-start-tls')) {
            document.getElementById('setting-ad-start-tls').checked = s.ad_start_tls === 'true' || s.ad_start_tls === true;
        }
        if (document.getElementById('setting-ad-insecure-skip-verify')) {
            document.getElementById('setting-ad-insecure-skip-verify').checked = s.ad_insecure_skip_verify !== 'false' && s.ad_insecure_skip_verify !== false;
        }
        if (s.ad_base_dn && document.getElementById('setting-ad-base-dn')) {
            document.getElementById('setting-ad-base-dn').value = s.ad_base_dn;
        }
        if (s.ad_bind_dn && document.getElementById('setting-ad-bind-dn')) {
            document.getElementById('setting-ad-bind-dn').value = s.ad_bind_dn;
        }
        if (s.ad_bind_password && s.ad_bind_password !== '********' && document.getElementById('setting-ad-bind-pass')) {
            document.getElementById('setting-ad-bind-pass').value = s.ad_bind_password;
        }
        if (s.ad_user_filter && document.getElementById('setting-ad-user-filter')) {
            document.getElementById('setting-ad-user-filter').value = s.ad_user_filter;
        }
        if (s.ad_username_attr && document.getElementById('setting-ad-username-attr')) {
            document.getElementById('setting-ad-username-attr').value = s.ad_username_attr;
        }
        if (s.ad_email_attr && document.getElementById('setting-ad-email-attr')) {
            document.getElementById('setting-ad-email-attr').value = s.ad_email_attr;
        }

        // Multi-Factor Authentication Policy
        if (s.mfa_policy && document.getElementById('setting-mfa-policy')) {
            document.getElementById('setting-mfa-policy').value = s.mfa_policy;
        }

        // SMTP Mail Delivery Settings
        if (document.getElementById('setting-smtp-enabled')) {
            document.getElementById('setting-smtp-enabled').checked = s.smtp_enabled === 'true' || s.smtp_enabled === true;
        }
        if (s.smtp_host && document.getElementById('setting-smtp-host')) {
            document.getElementById('setting-smtp-host').value = s.smtp_host;
        }
        if (s.smtp_port && document.getElementById('setting-smtp-port')) {
            document.getElementById('setting-smtp-port').value = s.smtp_port;
        }
        if (s.smtp_encryption && document.getElementById('setting-smtp-encryption')) {
            document.getElementById('setting-smtp-encryption').value = s.smtp_encryption;
        }
        if (document.getElementById('setting-smtp-insecure-skip-verify')) {
            document.getElementById('setting-smtp-insecure-skip-verify').checked = s.smtp_insecure_skip_verify === 'true' || s.smtp_insecure_skip_verify === true;
        }
        if (s.smtp_username && document.getElementById('setting-smtp-username')) {
            document.getElementById('setting-smtp-username').value = s.smtp_username;
        }
        if (s.smtp_password && s.smtp_password !== '********' && document.getElementById('setting-smtp-password')) {
            document.getElementById('setting-smtp-password').value = s.smtp_password;
        }
        if (s.smtp_from_address && document.getElementById('setting-smtp-from-address')) {
            document.getElementById('setting-smtp-from-address').value = s.smtp_from_address;
        }
        if (s.smtp_from_name && document.getElementById('setting-smtp-from-name')) {
            document.getElementById('setting-smtp-from-name').value = s.smtp_from_name;
        }
        if (document.getElementById('setting-smtp-notify-on-assignment')) {
            document.getElementById('setting-smtp-notify-on-assignment').checked = s.smtp_notify_on_assignment !== 'false';
        }
        if (document.getElementById('setting-smtp-notify-on-critical')) {
            document.getElementById('setting-smtp-notify-on-critical').checked = s.smtp_notify_on_critical !== 'false';
        }
        if (s.smtp_recipients && document.getElementById('setting-smtp-recipients')) {
            document.getElementById('setting-smtp-recipients').value = s.smtp_recipients;
        }

        const isStrict = s.strict_device_filtering === 'true' || s.strict_device_filtering === true;
        updateIngestionSecurityUI(isStrict);

        const tsStatusBadge = document.getElementById('ts-engine-status');
        if (tsStatusBadge) {
            const mode = s.stamping_mode || 'internal';
            if (mode === 'internal') {
                tsStatusBadge.className = 'badge badge-info';
                tsStatusBadge.textContent = 'Active (Internal Cryptographic Authority)';
            } else if (mode === 'kamusm') {
                tsStatusBadge.className = 'badge badge-success';
                tsStatusBadge.textContent = 'Active (TÜBİTAK KamuSM RFC 3161)';
            } else if (mode === 'disabled') {
                tsStatusBadge.className = 'badge badge-warning';
                tsStatusBadge.textContent = 'Disabled (Archival Only)';
            }
        }

        updateStampingUI();
        await loadHTTPSSettings();
        await loadFQDNSettings();
        await loadCacheStats();
    } catch (e) {
        console.error('Failed loading settings:', e);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadSettings();

    const modeEl = document.getElementById('setting-stamping-mode');
    if (modeEl) {
        modeEl.addEventListener('change', updateStampingUI);
    }

    const filterSelect = document.getElementById('setting-strict-filtering');
    if (filterSelect) {
        filterSelect.addEventListener('change', () => {
            updateIngestionSecurityUI(filterSelect.value === 'true');
        });
    }

    const btnSavePolicy = document.getElementById('btn-save-ingestion-policy');
    if (btnSavePolicy) {
        btnSavePolicy.addEventListener('click', async () => {
            btnSavePolicy.disabled = true;
            btnSavePolicy.textContent = 'Saving Policy...';
            const isStrict = document.getElementById('setting-strict-filtering').value;
            try {
                const res = await fetch('/api/v1/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        strict_device_filtering: isStrict
                    })
                });
                if (!res.ok) throw new Error(await res.text());
                alert(`Syslog Ingestion Security Policy updated! Strict Zero-Trust filtering is now ${isStrict === 'true' ? 'ENABLED' : 'DISABLED'}.`);
                updateIngestionSecurityUI(isStrict === 'true');
            } catch (e) {
                alert('Failed saving ingestion policy: ' + e.message);
            } finally {
                btnSavePolicy.disabled = false;
                btnSavePolicy.textContent = 'Save Ingestion Security Policy';
            }
        });
    }

    const btnSave = document.getElementById('btn-save-settings');
    if (btnSave) {
        btnSave.addEventListener('click', async () => {
            btnSave.disabled = true;
            btnSave.textContent = 'Saving Settings...';

            const stampingMode = document.getElementById('setting-stamping-mode') ? document.getElementById('setting-stamping-mode').value : 'internal';
            const autoFallback = document.getElementById('setting-auto-fallback') ? (document.getElementById('setting-auto-fallback').checked ? 'true' : 'false') : 'true';
            const strictFilter = document.getElementById('setting-strict-filtering') ? document.getElementById('setting-strict-filtering').value : 'false';

            const payload = {
                stamping_mode: stampingMode,
                auto_fallback: autoFallback,
                strict_device_filtering: strictFilter,
                kamusm_server_url: document.getElementById('setting-server-url') ? document.getElementById('setting-server-url').value : '',
                kamusm_server_port: document.getElementById('setting-server-port') ? document.getElementById('setting-server-port').value : '80',
                kamusm_customer_no: document.getElementById('setting-customer-no') ? document.getElementById('setting-customer-no').value.trim() : '',
                kamusm_digest_type: document.getElementById('setting-digest') ? document.getElementById('setting-digest').value : 'sha-256',
                archive_interval: document.getElementById('setting-archive-interval') ? document.getElementById('setting-archive-interval').value : 'hourly',
                retention_days: document.getElementById('setting-retention-days') ? document.getElementById('setting-retention-days').value : '365',
                storage_fifo_threshold_pct: document.getElementById('setting-fifo-threshold') ? document.getElementById('setting-fifo-threshold').value : '85',
            };

            const passInput = document.getElementById('setting-customer-pass');
            if (passInput) {
                const passVal = passInput.value.trim();
                if (passVal && passVal !== '********') {
                    payload.kamusm_customer_password = passVal;
                }
            }

            try {
                const res = await fetch('/api/v1/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                if (!res.ok) throw new Error(await res.text());
                alert('Stamping & System Settings saved successfully!');
                updateStampingUI();
                updateIngestionSecurityUI(strictFilter === 'true');
            } catch (e) {
                alert('Failed saving settings: ' + e.message);
            } finally {
                btnSave.disabled = false;
                btnSave.textContent = 'Save Stamping Settings';
            }
        });
    }

    const fifoSlider = document.getElementById('setting-fifo-threshold');
    if (fifoSlider) {
        fifoSlider.addEventListener('input', () => {
            const badge = document.getElementById('fifo-threshold-val-badge');
            if (badge) badge.textContent = fifoSlider.value + '%';
            const display = document.getElementById('fifo-threshold-display');
            if (display) display.textContent = fifoSlider.value;
        });
    }

    const btnSaveListeners = document.getElementById('btn-save-listeners');
    if (btnSaveListeners) {
        btnSaveListeners.addEventListener('click', async () => {
            btnSaveListeners.disabled = true;
            btnSaveListeners.textContent = 'Reloading Listeners...';
            const udpAddr = document.getElementById('setting-udp-listen-addr') ? document.getElementById('setting-udp-listen-addr').value.trim() : ':514';
            const tcpAddr = document.getElementById('setting-tcp-listen-addr') ? document.getElementById('setting-tcp-listen-addr').value.trim() : ':514';
            const tlsAddr = document.getElementById('setting-tls-listen-addr') ? document.getElementById('setting-tls-listen-addr').value.trim() : ':6514';

            try {
                const res = await fetch('/api/v1/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        syslog_udp_listen_addr: udpAddr,
                        syslog_tcp_listen_addr: tcpAddr,
                        syslog_tls_listen_addr: tlsAddr
                    })
                });
                if (!res.ok) throw new Error(await res.text());
                alert(`Syslog Network Listeners updated & hot-reloaded successfully!\nUDP: ${udpAddr}\nTCP: ${tcpAddr}\nTLS: ${tlsAddr}`);
            } catch (e) {
                alert('Failed saving/reloading listeners: ' + e.message);
            } finally {
                btnSaveListeners.disabled = false;
                btnSaveListeners.textContent = 'Apply & Hot-Reload Listeners';
            }
        });
    }

    const btnQuery = document.getElementById('btn-query-credit');
    if (btnQuery) {
        btnQuery.addEventListener('click', async () => {
            btnQuery.disabled = true;
            btnQuery.textContent = 'Testing Authority...';
            const resultDiv = document.getElementById('credit-query-result');
            if (resultDiv) {
                resultDiv.style.display = 'block';
                resultDiv.className = 'alert-box alert-info';
                resultDiv.textContent = 'Contacting timestamp provider authority...';
            }

            try {
                const res = await fetch('/api/v1/timestamp/credit');
                const data = await res.json();
                if (data.status === 'success') {
                    resultDiv.className = 'alert-box alert-success';
                    resultDiv.textContent = data.message;
                } else {
                    resultDiv.className = 'alert-box alert-warning';
                    resultDiv.textContent = data.message;
                }
            } catch (e) {
                resultDiv.className = 'alert-box alert-danger';
                resultDiv.textContent = 'Authority test failed: ' + e.message;
            } finally {
                btnQuery.disabled = false;
                btnQuery.textContent = 'Test Authority / Query Credits';
            }
        });
    }
});

// User Management & Security Profiles
const ROLE_DESCRIPTIONS = {
    'Super Administrator': 'Unrestricted control over system settings, user accounts, and TÜBİTAK KamuSM credentials',
    'Security Analyst': 'Threat hunting, live syslog stream inspection, and forensic ClickHouse queries',
    'Auditor': 'Verification of Law No. 5651 legal evidence, SHA-256 digests, and KamuSM .zd timestamp tokens',
    'Operator': 'Perimeter device onboarding, syslog socket monitoring, and queue telemetry',
    'Read Only': 'View-only access to dashboard statistics and health metrics'
};

function initUserModal() {
    const modal = document.getElementById('user-modal');
    const btnOpen = document.getElementById('btn-add-user-modal');
    const btnClose = document.getElementById('btn-close-user-modal');
    const btnCancel = document.getElementById('btn-cancel-user-modal');
    const btnSave = document.getElementById('btn-save-user');
    const roleSelect = document.getElementById('new-user-role');
    const roleDesc = document.getElementById('role-description-text');

    if (roleSelect && roleDesc) {
        roleSelect.addEventListener('change', () => {
            roleDesc.textContent = ROLE_DESCRIPTIONS[roleSelect.value] || 'Security role profile';
        });
    }

    const openModal = () => {
        document.getElementById('new-user-username').value = '';
        document.getElementById('new-user-fullname').value = '';
        document.getElementById('new-user-email').value = '';
        document.getElementById('new-user-password').value = '';
        document.getElementById('new-user-role').value = 'Security Analyst';
        document.getElementById('new-user-enabled').checked = true;
        if (roleDesc) roleDesc.textContent = ROLE_DESCRIPTIONS['Security Analyst'];
        modal.style.display = 'flex';
        document.getElementById('new-user-username').focus();
    };

    const closeModal = () => {
        modal.style.display = 'none';
    };

    if (btnOpen) btnOpen.addEventListener('click', openModal);
    if (btnClose) btnClose.addEventListener('click', closeModal);
    if (btnCancel) btnCancel.addEventListener('click', closeModal);

    if (btnSave) {
        btnSave.addEventListener('click', async () => {
            const username = document.getElementById('new-user-username').value.trim();
            const fullName = document.getElementById('new-user-fullname').value.trim();
            const email = document.getElementById('new-user-email').value.trim();
            const password = document.getElementById('new-user-password').value;
            const role = document.getElementById('new-user-role').value;
            const isEnabled = document.getElementById('new-user-enabled').checked;

            if (!username) {
                alert('Username is required.');
                return;
            }
            if (!password || password.length < 8) {
                alert('Password must be at least 8 characters.');
                return;
            }

            btnSave.disabled = true;
            btnSave.textContent = 'Saving...';

            try {
                const res = await fetch('/api/v1/users', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username,
                        full_name: fullName,
                        email,
                        password,
                        role,
                        is_enabled: isEnabled
                    })
                });

                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Failed creating user');

                closeModal();
                loadUsers();
            } catch (err) {
                alert('Error creating operator: ' + err.message);
            } finally {
                btnSave.disabled = false;
                btnSave.textContent = 'Create Operator';
            }
        });
    }
}

async function loadUsers() {
    const tbody = document.getElementById('users-body');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="9" class="text-center">Loading operators and security profiles...</td></tr>';

    try {
        const res = await fetch('/api/v1/users');
        if (res.status === 401) {
            window.location.href = '/login';
            return;
        }
        if (res.status === 403) {
            tbody.innerHTML = '<tr><td colspan="9" class="text-center text-red">Erişim Reddedildi: Yalnızca Süper Yöneticiler operatör hesaplarını görüntüleyebilir ve yönetebilir.</td></tr>';
            return;
        }
        const users = await res.json();
        if (!users || users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="text-center">No operator accounts found.</td></tr>';
            return;
        }

        window.activeUsersList = users;
        updateSIEMAssigneeDatalist(users);

        const roleBadges = {
            'Super Administrator': 'badge-primary',
            'Security Analyst': 'badge-info',
            'Auditor': 'badge-success',
            'Operator': 'badge-warning',
            'Read Only': 'badge-secondary'
        };

        tbody.innerHTML = users.map(u => {
            const isSelf = window.currentUser && (u.username === window.currentUser.username || u.id === window.currentUser.user_id);
            const isAD = u.auth_source === 'ad';
            const mfaOn = u.mfa_enabled === true;

            return `
            <tr>
                <td>
                    <strong>${escapeHtml(u.username)}</strong>
                    ${isSelf ? '<span class="badge badge-primary" style="font-size: 10px; margin-left: 4px;">You</span>' : ''}
                </td>
                <td>${escapeHtml(u.full_name || '-')}</td>
                <td class="mono-code">${escapeHtml(u.email || '-')}</td>
                <td>
                    <span class="badge ${roleBadges[u.role] || 'badge-secondary'}">
                        ${escapeHtml(u.role)}
                    </span>
                </td>
                <td>
                    <span class="badge ${isAD ? 'badge-info' : 'badge-secondary'}" title="${isAD ? 'Synced from Active Directory Domain Controller' : 'Local LogSeal Database'}">
                        ${isAD ? '🏢 Active Directory' : '👤 Local DB'}
                    </span>
                </td>
                <td>
                    <span class="badge ${mfaOn ? 'badge-success' : 'badge-warning'}" title="${mfaOn ? 'RFC 6238 TOTP Multi-Factor Authentication Active' : 'MFA is disabled'}">
                        ${mfaOn ? '🔐 Active (TOTP)' : 'Disabled'}
                    </span>
                </td>
                <td>
                    <span class="badge ${u.is_enabled ? 'badge-success' : 'badge-danger'}">
                        ${u.is_enabled ? 'Active' : 'Disabled'}
                    </span>
                </td>
                <td>${u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'Never'}</td>
                <td>
                    <div style="display: flex; gap: 6px; flex-wrap: wrap; align-items: center;">
                        ${!isAD ? `
                            <button class="btn btn-outline" style="padding: 3px 8px; font-size: 11px;" onclick="openResetPasswordModal('${u.id}', '${escapeHtml(u.username)}')">
                                Reset Password
                            </button>
                        ` : ''}
                        ${mfaOn ? `
                            <button class="btn btn-outline text-warning" style="padding: 3px 8px; font-size: 11px;" onclick="resetUserMFA('${u.id}', '${escapeHtml(u.username)}')">
                                Reset MFA
                            </button>
                        ` : ''}
                        ${isSelf ? `
                            <button class="btn btn-outline text-green" style="padding: 3px 8px; font-size: 11px;" onclick="openMyMFASetupModal()">
                                Setup MFA
                            </button>
                            <span class="badge badge-secondary" style="font-size: 10px;" title="Cannot deactivate or delete your own active account">Active Session</span>
                        ` : `
                            <button class="btn btn-outline" style="padding: 3px 8px; font-size: 11px;" onclick="toggleUserStatus('${u.id}')">
                                ${u.is_enabled ? 'Deactivate' : 'Activate'}
                            </button>
                            <button class="btn btn-outline text-red" style="padding: 3px 8px; font-size: 11px;" onclick="deleteUser('${u.id}', '${escapeHtml(u.username)}')">
                                Delete
                            </button>
                        `}
                    </div>
                </td>
            </tr>
            `;
        }).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-red">Failed loading users: ${e.message}</td></tr>`;
    }
}

function updateSIEMAssigneeDatalist(users) {
    let dl = document.getElementById('siem-analysts-datalist');
    if (!dl) {
        dl = document.createElement('datalist');
        dl.id = 'siem-analysts-datalist';
        document.body.appendChild(dl);
    }
    const assignedInput = document.getElementById('siem-inv-assigned-input');
    if (assignedInput) {
        assignedInput.setAttribute('list', 'siem-analysts-datalist');
    }
    dl.innerHTML = users.filter(u => u.is_enabled).map(u => 
        `<option value="${escapeHtml(u.username)}">${escapeHtml(u.full_name || u.username)} (${escapeHtml(u.role)})</option>`
    ).join('');
}

window.toggleUserStatus = async (id) => {
    if (window.currentUser && id === window.currentUser.user_id) {
        alert('İşlem Engellendi: Kendi aktif hesabınızı devre dışı bırakamazsınız.');
        return;
    }
    try {
        const res = await fetch(`/api/v1/users/toggle?id=${id}`, { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed toggling status');
        loadUsers();
    } catch (e) {
        alert('Action failed: ' + e.message);
    }
};

window.deleteUser = async (id, username) => {
    if (window.currentUser && (username === window.currentUser.username || id === window.currentUser.user_id)) {
        alert('İşlem Engellendi: Kendi hesabınızı silemezsiniz!');
        return;
    }
    if (!confirm(`Are you sure you want to delete user account "${username}"?`)) return;
    try {
        const res = await fetch(`/api/v1/users?id=${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed deleting user');
        loadUsers();
    } catch (e) {
        alert('Failed deleting user: ' + e.message);
    }
};

window.openResetPasswordModal = (id, username) => {
    document.getElementById('reset-user-id').value = id;
    document.getElementById('reset-username-display').value = username;
    document.getElementById('reset-new-password').value = '';
    document.getElementById('reset-confirm-password').value = '';
    const errBox = document.getElementById('reset-password-error');
    if (errBox) {
        errBox.style.display = 'none';
        errBox.textContent = '';
    }
    const modal = document.getElementById('reset-password-modal');
    if (modal) modal.style.display = 'flex';
};

function initResetPasswordModal() {
    const modal = document.getElementById('reset-password-modal');
    const btnClose = document.getElementById('btn-close-reset-modal');
    const btnCancel = document.getElementById('btn-cancel-reset-modal');
    const btnSave = document.getElementById('btn-save-reset-password');
    const errBox = document.getElementById('reset-password-error');

    const closeModal = () => {
        if (modal) modal.style.display = 'none';
    };

    if (btnClose) btnClose.addEventListener('click', closeModal);
    if (btnCancel) btnCancel.addEventListener('click', closeModal);

    if (btnSave) {
        btnSave.addEventListener('click', async () => {
            const userId = document.getElementById('reset-user-id').value;
            const newPass = document.getElementById('reset-new-password').value;
            const confirmPass = document.getElementById('reset-confirm-password').value;

            if (errBox) {
                errBox.style.display = 'none';
                errBox.textContent = '';
            }

            if (!newPass || newPass.length < 8) {
                if (errBox) {
                    errBox.textContent = 'Password must be at least 8 characters long.';
                    errBox.style.display = 'block';
                } else {
                    alert('Password must be at least 8 characters long.');
                }
                return;
            }

            if (newPass !== confirmPass) {
                if (errBox) {
                    errBox.textContent = 'Passwords do not match. Please verify both fields.';
                    errBox.style.display = 'block';
                } else {
                    alert('Passwords do not match.');
                }
                return;
            }

            btnSave.disabled = true;
            btnSave.textContent = 'Updating...';

            try {
                const res = await fetch('/api/v1/users/reset-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        user_id: userId,
                        new_password: newPass,
                    })
                });

                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Failed resetting password');

                alert('Operator password has been successfully updated!');
                closeModal();
            } catch (err) {
                if (errBox) {
                    errBox.textContent = err.message;
                    errBox.style.display = 'block';
                } else {
                    alert('Error: ' + err.message);
                }
            } finally {
                btnSave.textContent = 'Update Password';
            }
        });
    }
}

// ==========================================
// Active Directory, MFA & SMTP Management
// ==========================================
let currentMFASecret = '';

function initADAndMFAManagement() {
    // 1. Settings Action Listeners
    const btnSaveAD = document.getElementById('btn-save-ad-settings');
    if (btnSaveAD) {
        btnSaveAD.addEventListener('click', async () => {
            btnSaveAD.disabled = true;
            btnSaveAD.textContent = 'Saving AD Settings...';
            const payload = {
                ad_enabled: document.getElementById('setting-ad-enabled').checked ? 'true' : 'false',
                ad_server: document.getElementById('setting-ad-server').value.trim(),
                ad_port: document.getElementById('setting-ad-port').value.trim() || '389',
                ad_default_role: document.getElementById('setting-ad-default-role').value,
                ad_use_ssl: document.getElementById('setting-ad-use-ssl').checked ? 'true' : 'false',
                ad_start_tls: document.getElementById('setting-ad-start-tls').checked ? 'true' : 'false',
                ad_insecure_skip_verify: document.getElementById('setting-ad-insecure-skip-verify').checked ? 'true' : 'false',
                ad_base_dn: document.getElementById('setting-ad-base-dn').value.trim(),
                ad_bind_dn: document.getElementById('setting-ad-bind-dn').value.trim(),
                ad_user_filter: document.getElementById('setting-ad-user-filter').value.trim(),
                ad_username_attr: document.getElementById('setting-ad-username-attr').value.trim() || 'sAMAccountName',
                ad_email_attr: document.getElementById('setting-ad-email-attr').value.trim() || 'mail',
            };
            const passVal = document.getElementById('setting-ad-bind-pass').value.trim();
            if (passVal && passVal !== '********') {
                payload.ad_bind_password = passVal;
            }
            try {
                const res = await fetch('/api/v1/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                if (!res.ok) throw new Error(await res.text());
                alert('Active Directory & LDAP configuration saved successfully!');
            } catch (e) {
                alert('Failed saving AD configuration: ' + e.message);
            } finally {
                btnSaveAD.disabled = false;
                btnSaveAD.textContent = 'Save Active Directory Settings';
            }
        });
    }

    const btnTestAD = document.getElementById('btn-test-ad-conn');
    if (btnTestAD) {
        btnTestAD.addEventListener('click', async () => {
            btnTestAD.disabled = true;
            btnTestAD.textContent = 'Testing DC Connection...';
            const resultDiv = document.getElementById('ad-test-result');
            if (resultDiv) {
                resultDiv.style.display = 'block';
                resultDiv.className = 'alert-box alert-info';
                resultDiv.textContent = 'Connecting and binding to Domain Controller...';
            }
            try {
                const res = await fetch('/api/v1/auth/ad/test', { method: 'POST' });
                const data = await res.json();
                if (data.status === 'success') {
                    resultDiv.className = 'alert-box alert-success';
                    resultDiv.textContent = '✓ ' + data.message;
                } else {
                    resultDiv.className = 'alert-box alert-danger';
                    resultDiv.textContent = '✗ ' + (data.error || data.message || 'Connection test failed');
                }
            } catch (e) {
                if (resultDiv) {
                    resultDiv.className = 'alert-box alert-danger';
                    resultDiv.textContent = '✗ AD Test failed: ' + e.message;
                }
            } finally {
                btnTestAD.disabled = false;
                btnTestAD.textContent = '🔌 Test Connection to Domain Controller';
            }
        });
    }

    const btnSaveMFA = document.getElementById('btn-save-mfa-policy');
    if (btnSaveMFA) {
        btnSaveMFA.addEventListener('click', async () => {
            btnSaveMFA.disabled = true;
            btnSaveMFA.textContent = 'Saving MFA Policy...';
            const policy = document.getElementById('setting-mfa-policy').value;
            try {
                const res = await fetch('/api/v1/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mfa_policy: policy })
                });
                if (!res.ok) throw new Error(await res.text());
                alert(`MFA Policy updated to: ${policy === 'enforced' ? 'MANDATORY ENFORCEMENT' : 'OPTIONAL'}`);
            } catch (e) {
                alert('Failed saving MFA policy: ' + e.message);
            } finally {
                btnSaveMFA.disabled = false;
                btnSaveMFA.textContent = 'Save MFA Policy';
            }
        });
    }

    const btnSaveSMTP = document.getElementById('btn-save-smtp-settings');
    if (btnSaveSMTP) {
        btnSaveSMTP.addEventListener('click', async () => {
            btnSaveSMTP.disabled = true;
            btnSaveSMTP.textContent = 'Saving SMTP Settings...';
            const payload = {
                smtp_enabled: document.getElementById('setting-smtp-enabled').checked ? 'true' : 'false',
                smtp_host: document.getElementById('setting-smtp-host').value.trim(),
                smtp_port: document.getElementById('setting-smtp-port').value.trim() || '587',
                smtp_encryption: document.getElementById('setting-smtp-encryption').value,
                smtp_insecure_skip_verify: document.getElementById('setting-smtp-insecure-skip-verify').checked ? 'true' : 'false',
                smtp_username: document.getElementById('setting-smtp-username').value.trim(),
                smtp_from_address: document.getElementById('setting-smtp-from-address').value.trim(),
                smtp_from_name: document.getElementById('setting-smtp-from-name').value.trim() || 'Valtrivo LogSeal SIEM',
                smtp_notify_on_assignment: document.getElementById('setting-smtp-notify-on-assignment').checked ? 'true' : 'false',
                smtp_notify_on_critical: document.getElementById('setting-smtp-notify-on-critical').checked ? 'true' : 'false',
                smtp_recipients: document.getElementById('setting-smtp-recipients').value.trim(),
            };
            const passVal = document.getElementById('setting-smtp-password').value.trim();
            if (passVal && passVal !== '********') {
                payload.smtp_password = passVal;
            }
            try {
                const res = await fetch('/api/v1/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                if (!res.ok) throw new Error(await res.text());
                alert('SMTP Mail Server & Alert Notification settings saved successfully!');
            } catch (e) {
                alert('Failed saving SMTP settings: ' + e.message);
            } finally {
                btnSaveSMTP.disabled = false;
                btnSaveSMTP.textContent = 'Save SMTP Settings';
            }
        });
    }

    const btnTestSMTP = document.getElementById('btn-test-smtp');
    if (btnTestSMTP) {
        btnTestSMTP.addEventListener('click', async () => {
            const recipient = document.getElementById('setting-smtp-test-recipient').value.trim();
            if (!recipient) {
                alert('Please enter a recipient email address to receive the test email.');
                return;
            }
            btnTestSMTP.disabled = true;
            btnTestSMTP.textContent = 'Sending Test Mail...';
            const resultDiv = document.getElementById('smtp-test-result');
            if (resultDiv) {
                resultDiv.style.display = 'block';
                resultDiv.className = 'alert-box alert-info';
                resultDiv.textContent = `Connecting to SMTP host and dispatching test email to ${recipient}...`;
            }
            try {
                const res = await fetch('/api/v1/smtp/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ recipient })
                });
                const data = await res.json();
                if (data.status === 'success') {
                    resultDiv.className = 'alert-box alert-success';
                    resultDiv.textContent = '✓ ' + data.message;
                } else {
                    resultDiv.className = 'alert-box alert-danger';
                    resultDiv.textContent = '✗ ' + (data.error || data.message || 'SMTP test delivery failed');
                }
            } catch (e) {
                if (resultDiv) {
                    resultDiv.className = 'alert-box alert-danger';
                    resultDiv.textContent = '✗ SMTP Test failed: ' + e.message;
                }
            } finally {
                btnTestSMTP.disabled = false;
                btnTestSMTP.textContent = '✉️ Send Test Email';
            }
        });
    }

    // Modal triggers from Users pane
    const btnADSyncModal = document.getElementById('btn-ad-sync-modal');
    if (btnADSyncModal) {
        btnADSyncModal.addEventListener('click', openADSyncModal);
    }
    const btnMyMFAModal = document.getElementById('btn-my-mfa-modal');
    if (btnMyMFAModal) {
        btnMyMFAModal.addEventListener('click', openMyMFASetupModal);
    }
}

// ==========================================
// HTTPS, SSL/TLS, FQDN & Result Cache
// ==========================================
async function loadHTTPSSettings() {
    try {
        const res = await fetch('/api/v1/settings/https/status');
        if (!res.ok) return;
        const s = await res.json();

        const enEl = document.getElementById('setting-https-enabled');
        if (enEl) enEl.checked = !!s.enabled;

        const portEl = document.getElementById('setting-https-port');
        if (portEl && s.port) portEl.value = s.port;

        const cert = s.certificate || s.active_cert;
        const hasCert = !!(s.has_certificate || s.certificate || s.active_cert || cert);

        const redEl = document.getElementById('setting-https-redirect');
        const noteEl = document.getElementById('https-redirect-note');
        if (redEl) {
            redEl.checked = !!s.redirect_http;
            redEl.disabled = !hasCert;
            if (noteEl) {
                if (hasCert) {
                    noteEl.textContent = '✓ Active TLS certificate ready. Auto-redirect HTTP (8080) to HTTPS.';
                    noteEl.style.color = '#4ade80';
                } else {
                    noteEl.textContent = 'Requires an active TLS certificate (generate or upload below first).';
                    noteEl.style.color = 'var(--text-muted)';
                }
            }
        }

        const badge = document.getElementById('https-status-badge');
        if (badge) {
            if (s.enabled) {
                badge.className = 'badge badge-success';
                badge.textContent = `HTTPS Active (:${s.port || 8443})`;
            } else {
                badge.className = 'badge badge-secondary';
                badge.textContent = 'HTTPS Disabled';
            }
        }

        const cnEl = document.getElementById('cert-cn-display');
        const issuerEl = document.getElementById('cert-issuer-display');
        const expiryEl = document.getElementById('cert-expiry-display');
        const daysBadge = document.getElementById('cert-days-badge');
        const keyEl = document.getElementById('cert-key-display');
        const sansEl = document.getElementById('cert-sans-display');
        const fpEl = document.getElementById('cert-fp-display');
        const btnDl = document.getElementById('btn-download-cert');

        if (cert) {
            if (cnEl) cnEl.textContent = cert.subject_cn || cert.common_name || 'Configured TLS Certificate';
            if (issuerEl) issuerEl.textContent = cert.issuer || '-';
            if (expiryEl) expiryEl.textContent = cert.not_after ? cert.not_after.split('T')[0] : '-';
            if (daysBadge) {
                const days = cert.days_remaining != null ? cert.days_remaining : 0;
                daysBadge.textContent = `${days} days left`;
                daysBadge.className = days > 30 ? 'badge badge-success' : 'badge badge-warning';
            }
            if (keyEl) keyEl.textContent = cert.key_type || `${cert.key_algorithm || 'RSA'} ${cert.key_bits || 2048}-bit`;
            const allSans = [...(cert.dns_names || []), ...(cert.ip_addresses || [])].join(', ');
            if (sansEl) sansEl.textContent = allSans || 'None';
            if (fpEl) fpEl.textContent = cert.fingerprint_sha256 || '-';
            if (btnDl) btnDl.style.display = 'inline-block';
        } else {
            if (cnEl) cnEl.textContent = 'No Certificate Configured';
            if (issuerEl) issuerEl.textContent = '-';
            if (expiryEl) expiryEl.textContent = '-';
            if (daysBadge) {
                daysBadge.textContent = 'None';
                daysBadge.className = 'badge badge-secondary';
            }
            if (keyEl) keyEl.textContent = '-';
            if (sansEl) sansEl.textContent = '-';
            if (fpEl) fpEl.textContent = '-';
            if (btnDl) btnDl.style.display = 'none';
        }
    } catch (e) {
        console.error('Failed loading HTTPS settings:', e);
    }
}

async function loadFQDNSettings() {
    try {
        const res = await fetch('/api/v1/settings/fqdn');
        if (!res.ok) return;
        const s = await res.json();

        const enEl = document.getElementById('setting-fqdn-enabled');
        if (enEl) enEl.checked = !!s.enabled;

        const hostEl = document.getElementById('setting-fqdn-host');
        if (hostEl) hostEl.value = s.host || '';

        const redEl = document.getElementById('setting-fqdn-redirect');
        if (redEl) redEl.checked = !!s.redirect_raw_ip;

        const canonEl = document.getElementById('fqdn-canonical-url');
        if (canonEl) canonEl.textContent = s.canonical_url || window.location.origin;

        const badge = document.getElementById('fqdn-status-badge');
        if (badge) {
            if (s.enabled && s.host) {
                badge.className = 'badge badge-success';
                badge.textContent = `FQDN Active: ${s.host}`;
            } else {
                badge.className = 'badge badge-secondary';
                badge.textContent = 'FQDN Optional';
            }
        }
    } catch (e) {
        console.error('Failed loading FQDN settings:', e);
    }
}

async function loadCacheStats() {
    try {
        const res = await fetch('/api/v1/settings/cache/stats');
        if (!res.ok) return;
        const s = await res.json();

        const enEl = document.getElementById('setting-cache-enabled');
        if (enEl) enEl.checked = !!s.enabled;

        // Field names must match internal/cache.CacheStats JSON tags
        const totalMB = Number(s.total_system_memory_mb || 0);
        const availMB = Number(s.avail_system_memory_mb || 0);
        const maxMB = Number(s.max_memory_mb || 0);
        const curMB = Number(s.current_memory_mb || 0);
        const pct = Math.round(Number(s.target_percent || 60));
        const fmtMB = (mb) => mb >= 1024 ? `${(mb / 1024).toFixed(2)} GB` : `${mb.toFixed(1)} MB`;

        const totEl = document.getElementById('cache-total-ram');
        if (totEl) totEl.textContent = totalMB > 0 ? fmtMB(totalMB) : '-';

        const availEl = document.getElementById('cache-avail-ram');
        if (availEl) availEl.textContent = availMB > 0 ? fmtMB(availMB) : '-';

        const budgetEl = document.getElementById('cache-budget-ram');
        if (budgetEl) budgetEl.textContent = maxMB > 0 ? `${fmtMB(maxMB)} (${pct}%)` : '-';

        const usageEl = document.getElementById('cache-usage-ram');
        if (usageEl) {
            const usedPct = maxMB > 0 ? ` · ${((curMB / maxMB) * 100).toFixed(3)}%` : '';
            const usedStr = curMB >= 1 ? `${curMB.toFixed(2)} MB` : `${(Number(s.current_memory_bytes || curMB * 1048576) / 1024).toFixed(1)} KB`;
            usageEl.textContent = `${usedStr}${usedPct}`;
        }

        const itemsEl = document.getElementById('cache-items-count');
        if (itemsEl) itemsEl.textContent = Number(s.item_count || 0).toLocaleString();

        const hitRatioEl = document.getElementById('cache-hit-ratio');
        if (hitRatioEl) hitRatioEl.textContent = `${Number(s.hit_ratio_percent || 0).toFixed(1)}%`;

        const hitsEl = document.getElementById('cache-hits-count');
        if (hitsEl) hitsEl.textContent = Number(s.hit_count || 0).toLocaleString();

        const missesEl = document.getElementById('cache-misses-count');
        if (missesEl) missesEl.textContent = Number(s.miss_count || 0).toLocaleString();

        const badge = document.getElementById('cache-status-badge');
        if (badge) {
            if (s.enabled) {
                badge.className = 'badge badge-success';
                badge.textContent = `Active (Up to ${pct}% RAM)`;
            } else {
                badge.className = 'badge badge-secondary';
                badge.textContent = 'Disabled';
            }
        }
    } catch (e) {
        console.error('Failed loading cache telemetry:', e);
    }
}

function initHTTPSAndFQDNManagement() {
    // 1. HTTPS Settings Save
    const btnSaveHTTPS = document.getElementById('btn-save-https-settings');
    if (btnSaveHTTPS) {
        btnSaveHTTPS.addEventListener('click', async () => {
            btnSaveHTTPS.disabled = true;
            btnSaveHTTPS.textContent = 'Saving HTTPS...';
            try {
                const enabled = document.getElementById('setting-https-enabled').checked;
                const port = parseInt(document.getElementById('setting-https-port').value, 10) || 8443;
                const redirectHttp = document.getElementById('setting-https-redirect').checked;

                const res = await fetch('/api/v1/settings/https/toggle', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled, port, redirect: redirectHttp, redirect_http: redirectHttp })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Failed to save HTTPS settings');

                alert(`HTTPS Configuration Saved!\nStatus: ${enabled ? 'Enabled on port :' + port : 'Disabled'}\n${data.message || ''}`);
                await loadHTTPSSettings();
            } catch (e) {
                alert('Failed saving HTTPS settings: ' + e.message);
            } finally {
                btnSaveHTTPS.disabled = false;
                btnSaveHTTPS.textContent = 'Save HTTPS Settings';
            }
        });
    }

    // 2. Self-Signed Certificate Generation
    const btnGenCert = document.getElementById('btn-generate-cert');
    if (btnGenCert) {
        btnGenCert.addEventListener('click', async () => {
            const cn = document.getElementById('cert-gen-cn').value.trim();
            const sansRaw = document.getElementById('cert-gen-sans').value.trim();
            const days = parseInt(document.getElementById('cert-gen-days').value, 10) || 365;

            const sans = sansRaw ? sansRaw.split(',').map(s => s.trim()).filter(Boolean) : [];

            btnGenCert.disabled = true;
            btnGenCert.textContent = 'Generating 2048-bit RSA Certificate...';

            try {
                const res = await fetch('/api/v1/settings/https/certificate/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        common_name: cn,
                        sans: sans,
                        validity_days: days
                    })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Failed generating certificate');

                alert('✓ Cryptographic TLS certificate generated and activated successfully!');
                await loadHTTPSSettings();

                const redEl = document.getElementById('setting-https-redirect');
                if (redEl && !redEl.checked) {
                    if (confirm('TLS Certificate is active!\n\nWould you like to automatically enable Auto-Redirect from plain HTTP (8080) to HTTPS (8443) now?')) {
                        redEl.checked = true;
                        const btnSave = document.getElementById('btn-save-https-settings');
                        if (btnSave) btnSave.click();
                    }
                }
            } catch (e) {
                alert('Failed generating certificate: ' + e.message);
            } finally {
                btnGenCert.disabled = false;
                btnGenCert.textContent = '⚡ Generate & Activate Certificate';
            }
        });
    }

    // 3. Custom Certificate Upload (.pfx, .p12, .crt, .pem)
    const certTypeSelect = document.getElementById('cert-upload-type');
    const certFileInput = document.getElementById('cert-upload-file');
    const keyFileInput = document.getElementById('cert-upload-key-file');
    const pfxPassGroup = document.getElementById('cert-pfx-pass-group');
    const keyFileGroup = document.getElementById('cert-key-file-group');
    const certFileLabel = document.getElementById('cert-file-label');
    const certFileHelp = document.getElementById('cert-file-help');

    function syncCertTypeUI(type) {
        if (type === 'pfx') {
            if (certFileLabel) certFileLabel.textContent = 'PFX / P12 Arşiv Dosyası (.pfx, .p12)';
            if (certFileInput) certFileInput.accept = '.pfx,.p12';
            if (certFileHelp) certFileHelp.textContent = 'PFX veya P12 sertifika arşivinizi seçin (Sertifika ve Özel Anahtarı birlikte içerir).';
            if (pfxPassGroup) pfxPassGroup.style.display = 'block';
            if (keyFileGroup) keyFileGroup.style.display = 'none';
        } else {
            if (certFileLabel) certFileLabel.textContent = 'Sertifika Dosyası (.crt, .pem, .cer)';
            if (certFileInput) certFileInput.accept = '.crt,.pem,.cer';
            if (certFileHelp) certFileHelp.textContent = 'X.509 formatındaki sertifika dosyanızı (.crt, .pem) ve özel anahtarınızı seçin.';
            if (pfxPassGroup) pfxPassGroup.style.display = 'none';
            if (keyFileGroup) keyFileGroup.style.display = 'block';
        }
    }

    if (certTypeSelect) {
        certTypeSelect.addEventListener('change', () => {
            syncCertTypeUI(certTypeSelect.value);
        });
        // Initial sync
        syncCertTypeUI(certTypeSelect.value);
    }

    if (certFileInput) {
        certFileInput.addEventListener('change', () => {
            const file = certFileInput.files[0];
            if (file) {
                const ext = file.name.split('.').pop().toLowerCase();
                if ((ext === 'pfx' || ext === 'p12') && certTypeSelect && certTypeSelect.value !== 'pfx') {
                    certTypeSelect.value = 'pfx';
                    syncCertTypeUI('pfx');
                } else if ((ext === 'crt' || ext === 'cer') && certTypeSelect && certTypeSelect.value !== 'pem') {
                    certTypeSelect.value = 'pem';
                    syncCertTypeUI('pem');
                }
            }
        });
    }

    const btnUploadCert = document.getElementById('btn-upload-cert');
    if (btnUploadCert) {
        btnUploadCert.addEventListener('click', async () => {
            const certType = certTypeSelect ? certTypeSelect.value : 'pfx';
            const certFile = certFileInput?.files[0];
            if (!certFile) {
                const reqMsg = (certType === 'pfx')
                    ? 'Lütfen yüklenecek PFX / P12 sertifika dosyasını (.pfx, .p12) seçin.'
                    : 'Lütfen yüklenecek sertifika dosyasını (.crt, .pem) seçin.';
                alert(reqMsg);
                return;
            }

            btnUploadCert.disabled = true;
            btnUploadCert.textContent = 'Installing & Hot-Swapping Certificate...';

            try {
                const formData = new FormData();
                formData.append('certificate', certFile);

                if (certType === 'pem') {
                    const keyFile = keyFileInput?.files[0];
                    if (keyFile) {
                        formData.append('private_key', keyFile);
                    }
                }

                if (certType === 'pfx') {
                    const pfxPass = document.getElementById('cert-upload-pfx-pass')?.value || '';
                    if (pfxPass) {
                        formData.append('pfx_password', pfxPass);
                    }
                }

                const res = await fetch('/api/v1/settings/https/certificate/upload', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Failed uploading certificate');

                alert('✓ Enterprise TLS certificate uploaded, validated, and hot-swapped successfully!');
                if (certFileInput) certFileInput.value = '';
                if (keyFileInput) keyFileInput.value = '';
                const pfxPassEl = document.getElementById('cert-upload-pfx-pass');
                if (pfxPassEl) pfxPassEl.value = '';

                await loadHTTPSSettings();

                const redEl = document.getElementById('setting-https-redirect');
                if (redEl && !redEl.checked) {
                    if (confirm('Custom TLS Certificate is active!\n\nWould you like to automatically enable Auto-Redirect from plain HTTP (8080) to HTTPS (8443) now?')) {
                        redEl.checked = true;
                        const btnSave = document.getElementById('btn-save-https-settings');
                        if (btnSave) btnSave.click();
                    }
                }
            } catch (e) {
                alert('Failed uploading certificate: ' + e.message);
            } finally {
                btnUploadCert.disabled = false;
                btnUploadCert.textContent = '📤 Upload & Activate Certificate';
            }
        });
    }

    // 4. Download Active Certificate
    const btnDlCert = document.getElementById('btn-download-cert');
    if (btnDlCert) {
        btnDlCert.addEventListener('click', () => {
            window.location.href = '/api/v1/settings/https/certificate/download';
        });
    }

    // 5. FQDN Settings Save
    const btnSaveFQDN = document.getElementById('btn-save-fqdn-settings');
    if (btnSaveFQDN) {
        btnSaveFQDN.addEventListener('click', async () => {
            btnSaveFQDN.disabled = true;
            btnSaveFQDN.textContent = 'Saving FQDN...';
            try {
                const enabled = document.getElementById('setting-fqdn-enabled').checked;
                const host = document.getElementById('setting-fqdn-host').value.trim();
                const redirectRawIp = document.getElementById('setting-fqdn-redirect').checked;

                const res = await fetch('/api/v1/settings/fqdn', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled, host, redirect_raw_ip: redirectRawIp })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Failed saving FQDN');

                alert(`FQDN Settings Saved!\n${data.message || ''}`);
                await loadFQDNSettings();
            } catch (e) {
                alert('Failed saving FQDN settings: ' + e.message);
            } finally {
                btnSaveFQDN.disabled = false;
                btnSaveFQDN.textContent = 'Save FQDN Settings';
            }
        });
    }

    // 6. Cache Flush & Toggle
    const btnClearCache = document.getElementById('btn-clear-cache');
    if (btnClearCache) {
        btnClearCache.addEventListener('click', async () => {
            btnClearCache.disabled = true;
            try {
                const res = await fetch('/api/v1/settings/cache/clear', { method: 'POST' });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Failed flushing cache');
                alert('✓ In-memory query result cache flushed successfully.');
                await loadCacheStats();
            } catch (e) {
                alert('Failed flushing cache: ' + e.message);
            } finally {
                btnClearCache.disabled = false;
            }
        });
    }

    const toggleCacheEl = document.getElementById('setting-cache-enabled');
    if (toggleCacheEl) {
        toggleCacheEl.addEventListener('change', async () => {
            try {
                const res = await fetch('/api/v1/settings/cache/toggle', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled: toggleCacheEl.checked })
                });
                if (!res.ok) throw new Error('Failed to toggle cache');
                await loadCacheStats();
            } catch (e) {
                console.error('Failed toggling cache:', e);
            }
        });
    }
}

// Active Directory Sync Modal Handlers
window.openADSyncModal = async () => {
    const modal = document.getElementById('ad-sync-modal');
    if (!modal) return;
    modal.style.display = 'flex';
    const serverVal = document.getElementById('setting-ad-server') ? document.getElementById('setting-ad-server').value : '';
    const baseDNVal = document.getElementById('setting-ad-base-dn') ? document.getElementById('setting-ad-base-dn').value : '';
    const infoEl = document.getElementById('ad-sync-dc-info');
    if (infoEl) {
        infoEl.textContent = serverVal ? `${serverVal} (${baseDNVal || 'Default Base DN'})` : 'Domain Controller configured in Settings';
    }
    const statusBox = document.getElementById('ad-sync-status-box');
    if (statusBox) statusBox.style.display = 'none';
    await loadADPreviewUsers();
};

window.closeADSyncModal = () => {
    const modal = document.getElementById('ad-sync-modal');
    if (modal) modal.style.display = 'none';
};

window.loadADPreviewUsers = async () => {
    const tbody = document.getElementById('ad-preview-body');
    const btnScan = document.getElementById('btn-ad-preview-users');
    if (btnScan) {
        btnScan.disabled = true;
        btnScan.textContent = 'Scanning Directory...';
    }
    if (tbody) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center" style="padding: 20px;">Querying Active Directory Domain Controller...</td></tr>';
    }
    try {
        const res = await fetch('/api/v1/auth/ad/preview');
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed previewing domain users');
        const users = data.users || [];
        if (users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-warning" style="padding: 20px;">No users found matching filter or Active Directory is not reachable.</td></tr>';
            return;
        }
        tbody.innerHTML = users.map(u => `
            <tr>
                <td><strong>${escapeHtml(u.username)}</strong></td>
                <td>${escapeHtml(u.full_name || '-')}</td>
                <td class="mono-code">${escapeHtml(u.email || '-')}</td>
                <td style="font-size: 11px; color: var(--text-muted); max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(u.dn || '')}">
                    ${escapeHtml(u.dn || '-')}
                </td>
                <td>
                    <span class="badge ${u.is_enabled ? 'badge-success' : 'badge-danger'}">
                        ${u.is_enabled ? 'Active / Enabled' : 'Disabled in AD'}
                    </span>
                </td>
                <td>
                    <span class="badge badge-info">${escapeHtml(u.role || 'Security Analyst')}</span>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center text-red" style="padding: 20px;">Active Directory query failed: ${escapeHtml(e.message)}</td></tr>`;
        }
    } finally {
        if (btnScan) {
            btnScan.disabled = false;
            btnScan.textContent = '🔍 Scan / Preview Users';
        }
    }
};

window.executeADSync = async () => {
    const btnSync = document.getElementById('btn-ad-run-sync');
    const statusBox = document.getElementById('ad-sync-status-box');
    if (btnSync) {
        btnSync.disabled = true;
        btnSync.textContent = 'Synchronizing...';
    }
    if (statusBox) {
        statusBox.style.display = 'block';
        statusBox.className = 'alert-box alert-info';
        statusBox.textContent = 'Connecting to Active Directory and syncing user accounts...';
    }
    try {
        const res = await fetch('/api/v1/auth/ad/sync', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Sync failed');
        if (statusBox) {
            statusBox.className = 'alert-box alert-success';
            statusBox.innerHTML = `<strong>✓ Sync Complete:</strong> ${escapeHtml(data.message)} (${data.created_count || 0} created, ${data.updated_count || 0} updated).`;
        }
        loadUsers();
    } catch (e) {
        if (statusBox) {
            statusBox.className = 'alert-box alert-danger';
            statusBox.textContent = 'Sync failed: ' + e.message;
        }
    } finally {
        if (btnSync) {
            btnSync.disabled = false;
            btnSync.textContent = '📥 Import All to SIEM';
        }
    }
};

// MFA Enrollment & Setup Modal Handlers
let currentMFARecoveryCodes = [];

window.openMyMFASetupModal = async () => {
    const modal = document.getElementById('user-mfa-modal');
    if (!modal) return;
    const step1 = document.getElementById('mfa-setup-step1');
    const step2 = document.getElementById('mfa-setup-step2');
    const qrImg = document.getElementById('mfa-qr-img');
    const secretDisplay = document.getElementById('mfa-secret-display');
    const verifyInput = document.getElementById('mfa-verify-input');

    if (step1) step1.style.display = 'block';
    if (step2) step2.style.display = 'none';
    if (verifyInput) verifyInput.value = '';
    modal.style.display = 'flex';

    try {
        const res = await fetch('/api/v1/auth/mfa/setup', { method: 'POST' });
        const text = await res.text();
        let data = {};
        try {
            data = JSON.parse(text);
        } catch {
            throw new Error(`Server returned status ${res.status}: ${text.substring(0, 100)}`);
        }
        if (!res.ok) throw new Error(data.error || 'Failed generating MFA enrollment key');

        currentMFASecret = data.secret || '';
        currentMFARecoveryCodes = data.recovery_codes || [];
        const qrSrc = data.qr_code_base64 || data.qr_png_base64 || '';
        if (qrImg) {
            qrImg.src = qrSrc;
        }
        if (secretDisplay) secretDisplay.textContent = data.secret || '--------';
    } catch (e) {
        alert('Failed loading MFA enrollment: ' + e.message);
        modal.style.display = 'none';
    }
};

window.closeUserMFAModal = () => {
    const modal = document.getElementById('user-mfa-modal');
    if (modal) modal.style.display = 'none';
    loadUsers();
};

window.copyMFASecret = () => {
    const secret = currentMFASecret || (document.getElementById('mfa-secret-display') ? document.getElementById('mfa-secret-display').textContent.trim() : '');
    if (!secret || secret.includes('-')) return;
    navigator.clipboard.writeText(secret).then(() => {
        alert('MFA Secret Key copied to clipboard! You can paste it into MS Authenticator, Google Auth, AuthPoint, or FortiAuthenticator.');
    }).catch(() => {
        prompt('Copy your MFA Secret Key:', secret);
    });
};

window.confirmMFAActivation = async () => {
    const verifyInput = document.getElementById('mfa-verify-input');
    const code = verifyInput ? verifyInput.value.trim() : '';
    if (!code || code.length !== 6) {
        alert('Please enter a valid 6-digit verification code from your authenticator app.');
        return;
    }

    const secret = currentMFASecret || (document.getElementById('mfa-secret-display') ? document.getElementById('mfa-secret-display').textContent.trim() : '');
    if (!secret || secret.includes('-')) {
        alert('MFA secret key is missing. Please close and re-open the MFA setup window.');
        return;
    }

    const btn = document.getElementById('btn-mfa-confirm-activate');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Verifying...';
    }
    try {
        const res = await fetch('/api/v1/auth/mfa/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                secret: secret,
                code: code,
                recovery_codes: currentMFARecoveryCodes || [],
                provider: 'ms_authenticator'
            })
        });
        const text = await res.text();
        let data = {};
        try {
            data = JSON.parse(text);
        } catch {
            throw new Error(`Server returned status ${res.status}: ${text.substring(0, 100)}`);
        }
        if (!res.ok) throw new Error(data.error || 'Verification failed');

        const step1 = document.getElementById('mfa-setup-step1');
        const step2 = document.getElementById('mfa-setup-step2');
        if (step1) step1.style.display = 'none';
        if (step2) step2.style.display = 'block';

        const recoveryGrid = document.getElementById('mfa-recovery-codes-grid');
        const recoveryCodes = data.recovery_codes || currentMFARecoveryCodes || [];
        if (recoveryGrid && recoveryCodes.length > 0) {
            recoveryGrid.innerHTML = recoveryCodes.map(c => `
                <div style="padding: 4px 6px; background: rgba(255,255,255,0.06); border-radius: 4px; text-align: center;">${escapeHtml(c)}</div>
            `).join('');
        }
        loadUsers();
    } catch (e) {
        alert('MFA Verification failed: ' + e.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Activate MFA';
        }
    }
};

window.resetUserMFA = async (userId, username) => {
    if (!userId) {
        alert('Cannot reset MFA: user ID is missing.');
        return;
    }
    if (!confirm(`Are you sure you want to reset and disable Multi-Factor Authentication (MFA) for user "${username}"?\n\nThe user will be able to log in with their password and re-enroll their authenticator app.`)) {
        return;
    }
    try {
        const res = await fetch(`/api/v1/auth/mfa/admin-reset?id=${encodeURIComponent(userId)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: userId, id: userId })
        });
        const text = await res.text();
        let data = {};
        try {
            data = JSON.parse(text);
        } catch {
            throw new Error(`Server returned status ${res.status}: ${text.substring(0, 100)}`);
        }
        if (!res.ok) throw new Error(data.error || 'Reset failed');
        alert(`MFA successfully reset and disabled for ${username}.`);
        loadUsers();
    } catch (e) {
        alert('Failed resetting MFA: ' + e.message);
    }
};

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function updateViewHeader(tab) {
    const titleEl = document.getElementById('view-title');
    const subEl = document.getElementById('view-subtitle');
    if (!titleEl || !subEl) return;
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    titleEl.textContent = t(`view_title_${tab}`) || tab.toUpperCase();
    subEl.textContent = t(`view_subtitle_${tab}`) || '';
}

window.onLanguageChanged = (lang) => {
    const activeTab = document.querySelector('.nav-item.active')?.getAttribute('data-tab') || 'dashboard';
    updateViewHeader(activeTab);
    if (window.i18n) {
        window.i18n.applyTranslations();
    }
    if (typeof renderTenantSidebarMeta === 'function') {
        renderTenantSidebarMeta();
    }
    // Re-render active dynamic tab immediately upon language switch
    if (activeTab === 'settings') {
        if (typeof loadEdgeNodes === 'function') loadEdgeNodes();
        if (typeof loadTenants === 'function') loadTenants();
    } else if (activeTab === 'support') {
        if (typeof loadDebugBundles === 'function') loadDebugBundles();
    } else if (activeTab === 'archives') {
        if (typeof loadArchives === 'function') loadArchives();
    } else if (activeTab === 'dashboard') {
        if (typeof loadDashboard === 'function') loadDashboard();
    } else if (activeTab === 'siem') {
        if (typeof loadSIEMAlerts === 'function') loadSIEMAlerts();
    } else if (activeTab === 'devices') {
        if (typeof loadDevices === 'function') loadDevices();
    } else if (activeTab === 'unregistered') {
        if (typeof loadUnregisteredSources === 'function') loadUnregisteredSources();
    } else if (activeTab === 'reports') {
        if (typeof loadReportsView === 'function') loadReportsView();
    } else if (activeTab === 'endpoint') {
        loadEndpointDashboard();
        if (typeof currentEndpointSection !== 'undefined') {
            if (currentEndpointSection === 'endpoint-sec-agents') loadEndpointAgents();
            else if (currentEndpointSection === 'endpoint-sec-inventory') loadEndpointInventory();
            else if (currentEndpointSection === 'endpoint-sec-vulnerabilities') { loadCVEStatus(); loadEndpointVulnerabilities(); }
            else if (currentEndpointSection === 'endpoint-sec-patches') loadEndpointPatches();
            else if (currentEndpointSection === 'endpoint-sec-tokens') loadEndpointTokens();
            else if (currentEndpointSection === 'endpoint-sec-fim') loadEndpointFIM();
            else if (currentEndpointSection === 'endpoint-sec-usb') loadEndpointUSB();
            else if (currentEndpointSection === 'endpoint-sec-edr') loadEndpointEDR();
            else if (currentEndpointSection === 'endpoint-sec-network') loadEndpointNetwork();
        }
    } else if (activeTab === 'health') {
        if (typeof loadHealthTelemetry === 'function') loadHealthTelemetry();
    } else if (activeTab === 'users') {
        if (typeof loadUsers === 'function') loadUsers();
    } else if (activeTab === 'updates') {
        if (typeof loadUpdateStatus === 'function') loadUpdateStatus();
    }
};

function formatBytes(bytes, decimals = 2) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function updateStorageUI(storage) {
    if (!storage) return;

    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const sizeStr = formatBytes(storage.total_bytes_on_disk || 0);
    const rawStr = formatBytes(storage.uncompressed_data_bytes || 0);
    const ratio = storage.compression_ratio ? storage.compression_ratio.toFixed(1) : '1.0';
    const rows = Number(storage.total_rows || 0).toLocaleString();
    const diskUsagePct = storage.disk_usage_percent ? storage.disk_usage_percent.toFixed(1) : '0';
    const freeDiskStr = formatBytes(storage.free_disk_bytes || 0);

    const statDbSize = document.getElementById('stat-db-size');
    if (statDbSize) statDbSize.textContent = sizeStr;

    const statDbSub = document.getElementById('stat-db-sub');
    if (statDbSub) {
        statDbSub.textContent = `${ratio}x ${t('storage_compression')} • ${freeDiskStr} ${t('storage_disk_free')}`;
    }

    const metricCompressed = document.getElementById('metric-db-compressed');
    if (metricCompressed) metricCompressed.textContent = sizeStr;

    const metricUncompressed = document.getElementById('metric-db-uncompressed');
    if (metricUncompressed) metricUncompressed.textContent = rawStr;

    const metricRatio = document.getElementById('metric-db-ratio');
    if (metricRatio) metricRatio.textContent = `${ratio}x`;

    const metricRows = document.getElementById('metric-db-rows');
    if (metricRows) metricRows.textContent = rows;

    const partsBadge = document.getElementById('storage-parts-badge');
    if (partsBadge) partsBadge.textContent = `${storage.active_partitions || 0} ${t('storage_active_parts')}`;

    const diskSummary = document.getElementById('storage-disk-summary');
    if (diskSummary) diskSummary.textContent = `${t('storage_disk_usage')}: %${diskUsagePct}`;

    const freeBadge = document.getElementById('storage-free-badge');
    if (freeBadge) freeBadge.textContent = `${t('storage_disk_free')}: ${freeDiskStr}`;

    const progressBar = document.getElementById('storage-progress-bar');
    if (progressBar) {
        progressBar.style.width = Math.min(100, Math.max(3, parseFloat(diskUsagePct))) + '%';
        if (parseFloat(diskUsagePct) > 85) {
            progressBar.style.background = '#EF4444';
        } else if (parseFloat(diskUsagePct) > 70) {
            progressBar.style.background = '#F59E0B';
        } else {
            progressBar.style.background = 'linear-gradient(90deg, #10B981 0%, #3B82F6 70%, #F59E0B 90%, #EF4444 100%)';
        }
    }

    if (storage.fifo_threshold_percent) {
        const fifoDisp = document.getElementById('fifo-threshold-display');
        if (fifoDisp) fifoDisp.textContent = storage.fifo_threshold_percent;
    }

    // Storage Runway & 1st week recalculation
    if (storage.runway) {
        const lang = (window.i18n && window.i18n.currentLang) || localStorage.getItem('logseal_lang') || 'tr';
        const runwayLabel = lang === 'tr' ? (storage.runway.runway_label_tr || storage.runway.runway_label) : storage.runway.runway_label;
        const runwaySub = lang === 'tr' ? (storage.runway.runway_sub_label_tr || storage.runway.runway_sub_label) : storage.runway.runway_sub_label;

        const statRunway = document.getElementById('stat-storage-runway');
        if (statRunway) {
            statRunway.textContent = `${runwayLabel} ${runwaySub}`;
        }

        const metricRunway = document.getElementById('metric-storage-runway');
        if (metricRunway) {
            metricRunway.textContent = runwayLabel;
        }

        const metricRunwaySub = document.getElementById('metric-storage-runway-sub');
        if (metricRunwaySub) {
            metricRunwaySub.textContent = runwaySub;
        }
    }
}

function initStorageManagement() {
    const pruneBtn = document.getElementById('btn-prune-storage');
    if (pruneBtn) {
        pruneBtn.addEventListener('click', async () => {
            const msg = window.i18n ? window.i18n.t('confirm_prune') : 'En eski log bölümü kalıcı olarak silinecektir. Devam etmek istiyor musunuz?';
            if (!confirm(msg)) return;

            pruneBtn.disabled = true;
            pruneBtn.textContent = 'Pruning...';
            try {
                const res = await fetch('/api/v1/system/storage/prune', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'oldest_partition' })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Pruning failed');

                const successMsg = window.i18n ? window.i18n.t('msg_prune_success') : 'Oldest partition pruned!';
                alert(`${successMsg}\n${data.message || ''}`);
                if (data.storage) {
                    updateStorageUI(data.storage);
                }
            } catch (err) {
                alert('Storage Prune Error: ' + err.message);
            } finally {
                pruneBtn.disabled = false;
                pruneBtn.textContent = window.i18n ? window.i18n.t('btn_prune_oldest') : 'En Eski Bölümü Ez (FIFO Overwrite)';
            }
        });
    }
}

function initCustomExportModal() {
    const modal = document.getElementById('custom-export-modal');
    if (!modal) return;

    const btnClose = document.getElementById('btn-close-export-modal');
    const btnCancel = document.getElementById('btn-cancel-export-modal');
    const btnExecute = document.getElementById('btn-execute-export');
    const livePanel = document.getElementById('export-live-panel');
    const stageBadge = document.getElementById('export-stage-badge');
    const stageText = document.getElementById('export-stage-text');
    const percentEl = document.getElementById('export-progress-percent');
    const fillEl = document.getElementById('export-progress-fill');
    const msgEl = document.getElementById('export-progress-msg');
    const consoleLog = document.getElementById('export-console-log');
    const consoleStats = document.getElementById('export-console-stats');
    const successBox = document.getElementById('export-success-box');
    const successDetails = document.getElementById('export-success-details');
    const btnRedownload = document.getElementById('export-btn-redownload');
    const statusAlert = document.getElementById('export-status-alert');

    const formatBytes = (bytes) => {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    const addExportLog = (lineText, type = 'info') => {
        if (!consoleLog) return;
        const line = document.createElement('div');
        line.className = 'upd-log-line';
        if (type === 'error') line.style.color = '#ef4444';
        else if (type === 'success') line.style.color = '#10b981';
        else if (type === 'warn') line.style.color = '#f59e0b';
        line.textContent = lineText;
        consoleLog.appendChild(line);
        consoleLog.scrollTop = consoleLog.scrollHeight;
        if (consoleStats) consoleStats.textContent = `${consoleLog.children.length} log`;
    };

    const openModal = () => {
        const now = new Date();
        const start = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        const formatForInput = (d) => {
            const pad = (n) => String(n).padStart(2, '0');
            return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
        };

        const startInput = document.getElementById('export-start-time');
        const endInput = document.getElementById('export-end-time');
        if (startInput && !startInput.value) startInput.value = formatForInput(start);
        if (endInput && !endInput.value) endInput.value = formatForInput(now);

        if (statusAlert) statusAlert.style.display = 'none';
        modal.style.display = 'flex';
    };

    const closeModal = () => {
        modal.style.display = 'none';
    };

    const btnOpenTop = document.getElementById('btn-open-custom-export');
    const btnOpenSearch = document.getElementById('btn-search-custom-export');
    const btnOpenArchives = document.getElementById('btn-archives-custom-export');

    if (btnOpenTop) btnOpenTop.addEventListener('click', openModal);
    if (btnOpenSearch) btnOpenSearch.addEventListener('click', openModal);
    if (btnOpenArchives) btnOpenArchives.addEventListener('click', openModal);

    if (btnClose) btnClose.addEventListener('click', closeModal);
    if (btnCancel) btnCancel.addEventListener('click', closeModal);

    if (btnExecute) {
        btnExecute.addEventListener('click', async () => {
            const startVal = document.getElementById('export-start-time').value;
            const endVal = document.getElementById('export-end-time').value;

            if (!startVal || !endVal) {
                alert('Lütfen hem başlangıç hem de bitiş tarihini seçin.');
                return;
            }

            const timeFieldRadio = document.querySelector('input[name="export_time_field"]:checked');
            const timeField = timeFieldRadio ? timeFieldRadio.value : 'event_timestamp';

            const formatRadio = document.querySelector('input[name="export_format"]:checked');
            const format = formatRadio ? formatRadio.value : 'bundle';

            const seal = document.getElementById('export-seal-check').checked;
            const register = document.getElementById('export-register-check').checked;

            // Activate live progress panel
            if (livePanel) livePanel.style.display = 'block';
            if (successBox) successBox.style.display = 'none';
            if (fillEl) fillEl.style.width = '2%';
            if (percentEl) percentEl.textContent = '2%';
            if (stageBadge) {
                stageBadge.className = 'badge badge-info';
                stageBadge.textContent = 'BAŞLATILIYOR';
            }
            if (stageText) stageText.textContent = 'Sunucuya bağlanılıyor...';
            if (msgEl) msgEl.textContent = 'Dışa aktarma görevi başlatılıyor...';

            if (consoleLog) {
                consoleLog.innerHTML = `<div class="upd-log-line" style="color: var(--text-muted);">[${new Date().toLocaleTimeString()}] Dışa aktarma oturumu başlatıldı.</div>`;
            }
            if (consoleStats) consoleStats.textContent = '1 log';

            btnExecute.disabled = true;
            btnExecute.textContent = 'İşlem Yürütülüyor...';

            try {
                addExportLog(`[${new Date().toLocaleTimeString()}] İstek sunucuya gönderiliyor (POST /api/v1/archives/export-custom/start)...`);

                const startRes = await fetch('/api/v1/archives/export-custom/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        start: startVal,
                        end: endVal,
                        time_field: timeField,
                        format: format,
                        seal: seal,
                        register: register,
                        tenant: (currentTenantContext && currentTenantContext !== 'all' && currentTenantContext !== '*') ? currentTenantContext : ''
                    })
                });

                if (!startRes.ok) {
                    const errData = await startRes.json().catch(() => ({}));
                    throw new Error(errData.error || `Sunucu hatası: HTTP ${startRes.status}`);
                }

                const jobData = await startRes.json();
                const jobId = jobData.job_id;
                addExportLog(`[${new Date().toLocaleTimeString()}] İş kuyruğa alındı (İş ID: ${jobId}). Canlı işlem günlüğü dinleniyor...`);

                // Listen to SSE progress stream
                const streamUrl = `/api/v1/archives/export-custom/progress?job_id=${encodeURIComponent(jobId)}`;
                const progressRes = await fetch(streamUrl, {
                    headers: { 'Accept': 'text/event-stream' }
                });

                if (!progressRes.ok) {
                    throw new Error(`Canlı akışa bağlanılamadı: HTTP ${progressRes.status}`);
                }

                const seenLogs = new Set();
                let lastSnap = null;

                const handleSnapshot = (snap) => {
                    if (!snap) return;
                    lastSnap = snap;

                    // Update percentage and track
                    const pct = Math.min(100, Math.max(0, snap.percent || 0));
                    if (fillEl) fillEl.style.width = `${pct}%`;
                    if (percentEl) percentEl.textContent = `${pct}%`;

                    // Update stage badge
                    if (stageBadge && snap.stage) {
                        stageBadge.textContent = snap.stage;
                        if (snap.status === 'FAILED' || snap.stage === 'FAILED') {
                            stageBadge.className = 'badge badge-danger';
                        } else if (snap.status === 'COMPLETED' || snap.stage === 'COMPLETED') {
                            stageBadge.className = 'badge badge-success';
                        } else {
                            stageBadge.className = 'badge badge-info';
                        }
                    }

                    // Update stage text and active message
                    if (stageText && snap.stage_text) {
                        stageText.textContent = snap.stage_text;
                    }
                    if (msgEl && snap.latest_log) {
                        msgEl.textContent = snap.latest_log;
                    }

                    // Append any new log lines
                    if (snap.logs && Array.isArray(snap.logs)) {
                        snap.logs.forEach(logLine => {
                            if (!seenLogs.has(logLine)) {
                                seenLogs.add(logLine);
                                const isErr = logLine.includes('HATA') || logLine.includes('FAILED');
                                const isSuccess = logLine.includes('başarıyla') || logLine.includes('hazır') || logLine.includes('Tamamlandı');
                                addExportLog(logLine, isErr ? 'error' : isSuccess ? 'success' : 'info');
                            }
                        });
                    }
                };

                if (progressRes.body && progressRes.body.getReader) {
                    const reader = progressRes.body.getReader();
                    const decoder = new TextDecoder('utf-8');
                    let buffer = '';

                    while (true) {
                        const { done, value } = await reader.read();
                        if (done) break;

                        buffer += decoder.decode(value, { stream: true });
                        const blocks = buffer.split('\n\n');
                        buffer = blocks.pop(); // Keep unfinished tail

                        for (const block of blocks) {
                            const trimmed = block.trim();
                            if (!trimmed || trimmed.startsWith(':')) continue; // skip comments / pings

                            for (const line of trimmed.split('\n')) {
                                if (line.startsWith('data:')) {
                                    try {
                                        const snap = JSON.parse(line.substring(5).trim());
                                        handleSnapshot(snap);
                                    } catch (e) {
                                        // json parse err
                                    }
                                }
                            }
                        }

                        if (lastSnap && (lastSnap.status === 'COMPLETED' || lastSnap.status === 'FAILED')) {
                            break;
                        }
                    }
                } else {
                    // Fallback polling loop if getReader is unavailable
                    let isDone = false;
                    while (!isDone) {
                        await new Promise(r => setTimeout(r, 1500));
                        const pollRes = await fetch(`/api/v1/archives/export-custom/status?job_id=${encodeURIComponent(jobId)}`);
                        if (pollRes.ok) {
                            const snap = await pollRes.json();
                            handleSnapshot(snap);
                            if (snap.status === 'COMPLETED' || snap.status === 'FAILED') {
                                isDone = true;
                            }
                        }
                    }
                }

                // Handle completion
                if (lastSnap && lastSnap.status === 'COMPLETED') {
                    if (fillEl) fillEl.style.width = '100%';
                    if (percentEl) percentEl.textContent = '100%';
                    if (stageBadge) {
                        stageBadge.className = 'badge badge-success';
                        stageBadge.textContent = 'TAMAMLANDI';
                    }
                    if (stageText) stageText.textContent = 'Dışa aktarma ve mühürleme tamamlandı!';
                    if (msgEl) msgEl.textContent = 'Dosya indiriliyor...';

                    const downloadUrl = lastSnap.download_url || `/api/v1/archives/export-custom/download?job_id=${encodeURIComponent(jobId)}`;

                    // Trigger direct file download
                    addExportLog(`[${new Date().toLocaleTimeString()}] İndirme bağlantısı tetikleniyor: ${downloadUrl}`, 'success');
                    const downloadAnchor = document.createElement('a');
                    downloadAnchor.href = downloadUrl;
                    downloadAnchor.setAttribute('download', '');
                    document.body.appendChild(downloadAnchor);
                    downloadAnchor.click();
                    document.body.removeChild(downloadAnchor);

                    // Show success details box
                    if (successBox) {
                        successBox.style.display = 'flex';
                        if (successDetails && lastSnap.result) {
                            const r = lastSnap.result;
                            successDetails.innerHTML = `
                                <div><strong>Kayıt Adedi:</strong> ${Number(r.record_count || 0).toLocaleString()} adet</div>
                                <div><strong>Dosya Boyutu:</strong> ${formatBytes(r.archive_size)}</div>
                                <div><strong>SHA-256 Hash:</strong> <span style="font-size: 11px; word-break: break-all;">${r.hash_sha256}</span></div>
                                <div><strong>Zaman Damgası:</strong> <span class="badge ${r.timestamp_status === 'STAMPED' ? 'badge-success' : 'badge-warning'}">${r.timestamp_status}</span></div>
                            `;
                        }
                        if (btnRedownload) {
                            btnRedownload.href = downloadUrl;
                        }
                    }

                    if (typeof loadArchives === 'function') {
                        loadArchives();
                    }
                    btnExecute.textContent = 'Yeni Dışa Aktarma Yap';
                } else if (lastSnap && lastSnap.status === 'FAILED') {
                    throw new Error(lastSnap.error || 'Dışa aktarma sırasında bir hata oluştu');
                }
            } catch (err) {
                addExportLog(`[${new Date().toLocaleTimeString()}] HATA: ${err.message}`, 'error');
                if (stageBadge) {
                    stageBadge.className = 'badge badge-danger';
                    stageBadge.textContent = 'HATA';
                }
                if (stageText) stageText.textContent = 'İşlem Başarısız';
                if (msgEl) msgEl.textContent = err.message;
                alert('Dışa aktarma hatası: ' + err.message);
                btnExecute.textContent = 'Tekrar Dene';
            } finally {
                btnExecute.disabled = false;
            }
        });
    }
}

// System Updates & GitHub Synchronization
let lastUpdateData = null;

async function loadUpdateStatus() {
    try {
        const res = await fetch('/api/v1/system/update/status');
        if (!res.ok) return;
        const data = await res.json();
        
        const verEl = document.getElementById('upd-current-version');
        const commitEl = document.getElementById('upd-current-commit');
        const dateEl = document.getElementById('upd-build-date');
        const repoEl = document.getElementById('upd-repo-link');
        const branchEl = document.getElementById('upd-branch');

        const curVersion = data.current_version || 'v1.2.4';
        if (verEl) verEl.textContent = curVersion;
        const brandVer = document.getElementById('brand-version');
        if (brandVer) brandVer.textContent = curVersion;

        if (commitEl) commitEl.textContent = data.current_commit || '0a5ea80';
        if (dateEl) dateEl.textContent = `Build: ${data.build_date || '2026-10-08'}`;
        if (repoEl) {
            repoEl.textContent = data.repository || 'v-e-kandjani/Logger';
            repoEl.href = data.repo_url || 'https://github.com/v-e-kandjani/Logger';
        }
        if (branchEl) branchEl.textContent = data.branch || 'main';
    } catch (e) {
        console.error('Failed loading update status:', e);
    }
}

function initUpdatesManagement() {
    const btnCheck = document.getElementById('btn-check-updates');
    const btnApply = document.getElementById('btn-apply-updates');
    const btnCopyCli = document.getElementById('btn-copy-upgrade-cli');
    const badge = document.getElementById('upd-status-badge');
    const lastCheckedLabel = document.getElementById('upd-last-checked-label');
    const detailsPanel = document.getElementById('upd-details-panel');

    if (btnCopyCli) {
        btnCopyCli.addEventListener('click', () => {
            const code = document.getElementById('upgrade-cli-code').textContent;
            navigator.clipboard.writeText(code).then(() => {
                showToast('✓ CLI Upgrade command copied to clipboard!', 'success');
                btnCopyCli.textContent = '✓ Copied!';
                setTimeout(() => { btnCopyCli.textContent = '📋 Copy Command'; }, 2500);
            }).catch(() => {
                showToast('Could not copy automatically. Please copy the command manually.', 'info');
            });
        });
    }

    if (btnCheck) {
        btnCheck.addEventListener('click', async () => {
            btnCheck.disabled = true;
            btnCheck.textContent = 'Connecting to GitHub...';
            if (badge) {
                badge.className = 'badge badge-warning';
                badge.textContent = 'Querying GitHub...';
            }

            try {
                const res = await fetch('/api/v1/system/update/check', { method: 'POST' });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Failed checking GitHub API');

                lastUpdateData = data;
                if (lastCheckedLabel) {
                    lastCheckedLabel.textContent = `Checked: ${new Date(data.last_checked).toLocaleTimeString()}`;
                }

                if (data.has_update) {
                    if (badge) {
                        badge.className = 'badge badge-warning';
                        badge.textContent = `Update Available (${data.commits_behind} new commits)`;
                    }
                    const navBadge = document.getElementById('update-indicator-badge');
                    if (navBadge) {
                        navBadge.style.display = 'inline-block';
                        navBadge.textContent = `${data.commits_behind} New`;
                    }

                    if (btnApply) {
                        btnApply.disabled = false;
                        btnApply.title = 'Click to pull and hot-patch changed web assets';
                    }

                    if (detailsPanel) detailsPanel.style.display = 'block';

                    // Populate commit details
                    if (data.latest_commit) {
                        document.getElementById('upd-commits-behind-badge').textContent = `${data.commits_behind} commit(s) behind`;
                        document.getElementById('upd-latest-message').textContent = data.latest_commit.commit.message.split('\n')[0];
                        document.getElementById('upd-latest-author').textContent = data.latest_commit.commit.author.name;
                        document.getElementById('upd-latest-date').textContent = new Date(data.latest_commit.commit.author.date).toLocaleString();
                        const sha = data.latest_commit.sha.substring(0, 7);
                        document.getElementById('upd-latest-sha').textContent = sha;
                        const linkEl = document.getElementById('upd-latest-url');
                        if (linkEl) linkEl.href = data.latest_commit.html_url;
                    }

                    // Populate files table
                    const tbody = document.getElementById('upd-files-body');
                    if (tbody && data.changed_files && data.changed_files.length > 0) {
                        tbody.innerHTML = data.changed_files.map(f => `
                            <tr>
                                <td class="mono-code"><strong>${escapeHtml(f.filename)}</strong></td>
                                <td>
                                    <span class="badge ${f.status === 'added' ? 'badge-success' : f.status === 'removed' ? 'badge-danger' : 'badge-primary'}">
                                        ${f.status}
                                    </span>
                                </td>
                                <td>
                                    <span style="color: #10b981;">+${f.additions}</span> / 
                                    <span style="color: #ef4444;">-${f.deletions}</span>
                                </td>
                                <td>
                                    ${f.can_hot_apply 
                                        ? '<span class="badge badge-success">✓ Web Asset (Hot-Patchable)</span>' 
                                        : '<span class="badge badge-warning">⚙️ Go Engine (Rebuild Required)</span>'}
                                </td>
                            </tr>
                        `).join('');
                    } else if (tbody) {
                        tbody.innerHTML = '<tr><td colspan="4" class="text-center">Files listed in release commits.</td></tr>';
                    }

                    const binWarning = document.getElementById('upd-binary-warning');
                    if (binWarning) {
                        binWarning.style.display = data.binary_changed ? 'block' : 'none';
                    }

                    showToast(`Update available! Found ${data.commits_behind} new commit(s) on origin/main.`, 'info');
                } else {
                    if (badge) {
                        badge.className = 'badge badge-success';
                        badge.textContent = 'Up to Date (origin/main)';
                    }
                    const navBadge = document.getElementById('update-indicator-badge');
                    if (navBadge) navBadge.style.display = 'none';

                    if (btnApply) {
                        btnApply.disabled = true;
                    }
                    if (detailsPanel) detailsPanel.style.display = 'none';

                    showToast('✓ Platform is running the latest version from origin/main.', 'success');
                }

                // Update TÜBİTAK KamuSM TSS Client status card
                if (data.kamusm) {
                    const kVersionEl = document.getElementById('upd-kamusm-version');
                    const kStatusEl = document.getElementById('upd-kamusm-status');
                    if (kVersionEl) {
                        kVersionEl.textContent = `v${data.kamusm.latest_version || data.kamusm.current_version}`;
                    }
                    if (kStatusEl) {
                        if (data.kamusm.downloaded) {
                            kStatusEl.textContent = '✓ Updated & Downloaded from TÜBİTAK';
                            kStatusEl.style.color = '#10b981';
                        } else if (data.kamusm.update_available) {
                            kStatusEl.textContent = '⚡ New Version Available at TÜBİTAK';
                            kStatusEl.style.color = '#f59e0b';
                        } else {
                            kStatusEl.textContent = '✓ Verified Up to Date';
                            kStatusEl.style.color = '#10b981';
                        }
                    }
                }
            } catch (err) {
                if (badge) {
                    badge.className = 'badge badge-danger';
                    badge.textContent = 'Check Failed';
                }
                showToast('Update check failed: ' + err.message, 'error');
            } finally {
                btnCheck.disabled = false;
                btnCheck.textContent = '🔍 Check for Updates';
            }
        });
    }

    // Live Upgrade Progress Modal Controller
    let upgradeReloadTimer = null;

    function openUpgradeModal() {
        const modal = document.getElementById('upgrade-modal');
        if (modal) modal.style.display = 'flex';

        const closeBtn = document.getElementById('btn-close-upgrade-modal');
        const dismissBtn = document.getElementById('btn-dismiss-upgrade-modal');
        const reloadBtn = document.getElementById('btn-reload-after-upgrade');
        if (closeBtn) closeBtn.style.display = 'none';
        if (dismissBtn) dismissBtn.style.display = 'none';
        if (reloadBtn) reloadBtn.style.display = 'none';

        const fill = document.getElementById('upd-progress-fill');
        if (fill) fill.style.width = '0%';

        const pct = document.getElementById('upd-progress-percent');
        if (pct) pct.textContent = '0%';

        const stageBadge = document.getElementById('upd-progress-stage-badge');
        if (stageBadge) {
            stageBadge.className = 'badge badge-info';
            stageBadge.textContent = 'STARTING';
        }

        const stageText = document.getElementById('upd-progress-stage-text');
        if (stageText) stageText.textContent = 'Connecting to GitHub...';

        const msg = document.getElementById('upd-progress-msg');
        if (msg) msg.textContent = 'Preparing platform upgrade sequence...';

        const footerStatus = document.getElementById('upd-modal-footer-status');
        if (footerStatus) {
            footerStatus.innerHTML = '⚠️ Please do not close this browser tab while the update is being applied.';
            footerStatus.style.color = 'var(--text-muted)';
        }

        const consoleLog = document.getElementById('upd-console-log');
        if (consoleLog) {
            consoleLog.innerHTML = `<div class="upd-log-line" style="color: var(--text-muted);">[${new Date().toLocaleTimeString()}] Live upgrade session started.</div>`;
        }

        const stats = document.getElementById('upd-console-stats');
        if (stats) stats.textContent = '1 event';
    }

    function addUpgradeLog(message, type = 'info') {
        const consoleLog = document.getElementById('upd-console-log');
        if (!consoleLog) return;
        const line = document.createElement('div');
        line.className = 'upd-log-line' + (type === 'success' ? ' success' : type === 'error' ? ' error' : type === 'warn' ? ' warn' : '');
        line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        consoleLog.appendChild(line);
        consoleLog.scrollTop = consoleLog.scrollHeight;

        const stats = document.getElementById('upd-console-stats');
        if (stats) stats.textContent = `${consoleLog.children.length} events`;
    }

    function updateUpgradeProgress(data) {
        const percent = Math.min(100, Math.max(0, data.percent || 0));
        const fill = document.getElementById('upd-progress-fill');
        if (fill) fill.style.width = `${percent}%`;

        const pct = document.getElementById('upd-progress-percent');
        if (pct) pct.textContent = `${percent}%`;

        const stageBadge = document.getElementById('upd-progress-stage-badge');
        const stageText = document.getElementById('upd-progress-stage-text');
        const msg = document.getElementById('upd-progress-msg');

        if (data.stage && stageBadge) {
            stageBadge.textContent = data.stage;
            if (data.stage === 'ERROR' || !data.success) {
                stageBadge.className = 'badge badge-danger';
            } else if (data.done) {
                stageBadge.className = 'badge badge-success';
            } else {
                stageBadge.className = 'badge badge-info';
            }
        }

        if (stageText && data.stage) {
            switch (data.stage) {
                case 'INIT': stageText.textContent = 'Initializing engine'; break;
                case 'GITHUB_CHECK': stageText.textContent = 'Contacting GitHub'; break;
                case 'COMMIT_RESOLVED': stageText.textContent = 'Verifying release'; break;
                case 'GIT_SYNC':
                case 'GIT_PULL': stageText.textContent = 'Synchronizing Git delta'; break;
                case 'HOT_PATCH': stageText.textContent = 'Hot-patching files'; break;
                case 'VERSION_STATE': stageText.textContent = 'Writing version configuration'; break;
                case 'AUDIT_LOG': stageText.textContent = 'Writing audit trail'; break;
                case 'COMPLETE': stageText.textContent = 'Upgrade Complete!'; break;
                case 'ERROR': stageText.textContent = 'Upgrade Failed'; break;
                default: stageText.textContent = data.stage;
            }
        }

        if (msg && data.message) {
            msg.textContent = data.message;
        }

        if (data.message) {
            let lineType = 'info';
            if (data.stage === 'ERROR' || !data.success) lineType = 'error';
            else if (data.done || data.stage === 'COMPLETE') lineType = 'success';
            else if (data.stage === 'HOT_PATCH') lineType = 'info';
            addUpgradeLog(data.message, lineType);
        }

        if (data.done && data.success) {
            handleUpgradeCompleted(data);
        } else if (data.done && !data.success) {
            handleUpgradeFailed(data.message || 'Unknown error occurred during upgrade');
        }
    }

    function handleUpgradeCompleted(data) {
        const fill = document.getElementById('upd-progress-fill');
        if (fill) fill.style.width = '100%';

        const pct = document.getElementById('upd-progress-percent');
        if (pct) pct.textContent = '100%';

        const footerStatus = document.getElementById('upd-modal-footer-status');
        if (footerStatus) {
            footerStatus.innerHTML = `✓ <strong>Platform upgraded to ${data.new_version || 'latest'}!</strong> Reloading dashboard...`;
            footerStatus.style.color = '#10b981';
        }

        const closeBtn = document.getElementById('btn-close-upgrade-modal');
        const dismissBtn = document.getElementById('btn-dismiss-upgrade-modal');
        const reloadBtn = document.getElementById('btn-reload-after-upgrade');
        if (closeBtn) closeBtn.style.display = 'block';
        if (dismissBtn) dismissBtn.style.display = 'block';
        if (reloadBtn) reloadBtn.style.display = 'inline-flex';

        if (data.new_commit) {
            const commitEl = document.getElementById('upd-current-commit');
            if (commitEl) commitEl.textContent = data.new_commit;
        }

        if (badge) {
            badge.className = 'badge badge-success';
            badge.textContent = 'Updated to ' + (data.new_commit || 'latest');
        }

        showToast(`✓ Platform upgraded to ${data.new_version || 'latest'}!`, 'success');

        // Auto reload countdown and server healthcheck reconnection
        let remaining = 3;
        const countdownEl = document.getElementById('upd-reload-countdown');
        if (countdownEl) countdownEl.textContent = `${remaining}s`;

        if (upgradeReloadTimer) clearInterval(upgradeReloadTimer);
        upgradeReloadTimer = setInterval(() => {
            remaining--;
            if (countdownEl) countdownEl.textContent = `${Math.max(0, remaining)}s`;
            if (remaining <= 0) {
                clearInterval(upgradeReloadTimer);
                if (footerStatus) {
                    footerStatus.innerHTML = `🔄 <strong>Waiting for server restart...</strong> Reconnecting to dashboard...`;
                    footerStatus.style.color = '#38bdf8';
                }
                // Poll healthcheck until server is back online
                let checkAttempts = 0;
                const pollTimer = setInterval(async () => {
                    checkAttempts++;
                    try {
                        const hRes = await fetch('/api/v1/system/health', { cache: 'no-store' });
                        if (hRes.ok) {
                            clearInterval(pollTimer);
                            window.location.reload(true);
                            return;
                        }
                    } catch (e) {
                        // Service restarting, wait for next attempt
                    }
                    if (checkAttempts >= 20) {
                        clearInterval(pollTimer);
                        window.location.reload(true);
                    }
                }, 1000);
            }
        }, 1000);
    }

    function handleUpgradeFailed(errMessage) {
        const stageBadge = document.getElementById('upd-progress-stage-badge');
        if (stageBadge) {
            stageBadge.className = 'badge badge-danger';
            stageBadge.textContent = 'FAILED';
        }
        const footerStatus = document.getElementById('upd-modal-footer-status');
        if (footerStatus) {
            footerStatus.innerHTML = `❌ <strong>Upgrade failed:</strong> ${errMessage}`;
            footerStatus.style.color = '#ef4444';
        }
        const closeBtn = document.getElementById('btn-close-upgrade-modal');
        const dismissBtn = document.getElementById('btn-dismiss-upgrade-modal');
        if (closeBtn) closeBtn.style.display = 'block';
        if (dismissBtn) dismissBtn.style.display = 'block';
        showToast('Upgrade failed: ' + errMessage, 'error');
    }

    // Modal dismiss listeners
    const btnCloseModal = document.getElementById('btn-close-upgrade-modal');
    if (btnCloseModal) {
        btnCloseModal.addEventListener('click', () => {
            const m = document.getElementById('upgrade-modal');
            if (m) m.style.display = 'none';
            if (upgradeReloadTimer) clearInterval(upgradeReloadTimer);
        });
    }

    const btnDismissModal = document.getElementById('btn-dismiss-upgrade-modal');
    if (btnDismissModal) {
        btnDismissModal.addEventListener('click', () => {
            const m = document.getElementById('upgrade-modal');
            if (m) m.style.display = 'none';
            if (upgradeReloadTimer) clearInterval(upgradeReloadTimer);
        });
    }

    const btnReloadNow = document.getElementById('btn-reload-after-upgrade');
    if (btnReloadNow) {
        btnReloadNow.addEventListener('click', () => {
            if (upgradeReloadTimer) clearInterval(upgradeReloadTimer);
            window.location.reload(true);
        });
    }

    if (btnApply) {
        btnApply.addEventListener('click', async () => {
            if (!confirm('Apply available updates from GitHub to this server? Web assets and templates will be updated immediately.')) {
                return;
            }

            btnApply.disabled = true;
            btnApply.textContent = 'Upgrading Platform...';

            openUpgradeModal();
            addUpgradeLog('🚀 Initializing upgrade sequence from Web UI...');

            try {
                const res = await fetch('/api/v1/system/update/apply', {
                    method: 'POST',
                    headers: {
                        'Accept': 'text/event-stream'
                    }
                });

                if (!res.ok) {
                    throw new Error(`HTTP server error: ${res.status}`);
                }

                if (!res.body || !res.body.getReader) {
                    // Fallback for environments without stream reader
                    const data = await res.json();
                    updateUpgradeProgress({ percent: 100, stage: 'COMPLETE', message: data.message, done: true, success: data.success });
                    return;
                }

                const reader = res.body.getReader();
                const decoder = new TextDecoder('utf-8');
                let buffer = '';

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    buffer += decoder.decode(value, { stream: true });
                    const lines = buffer.split('\n');
                    buffer = lines.pop(); // keep trailing incomplete line

                    for (const line of lines) {
                        const trimmed = line.trim();
                        if (trimmed.startsWith('data: ')) {
                            try {
                                const data = JSON.parse(trimmed.slice(6));
                                updateUpgradeProgress(data);
                            } catch (e) {
                                console.error('Error parsing SSE event:', e);
                            }
                        }
                    }
                }
            } catch (err) {
                handleUpgradeFailed(err.message);
            } finally {
                btnApply.disabled = false;
                btnApply.textContent = '🚀 Apply Upgrade (Changed Files)';
            }
        });
    }
}

// ==============================================================================
// Real-Time System Telemetry & Performance Charts Engine (Canvas-based)
// Visualizes: CPU (%), RAM (Used/Total), Logs Received (EPS), Network I/O (KB/s)
// ==============================================================================
let telemetryChartTimer = null;
let telemetryHistoryData = null;

async function fetchTimeseriesAnalytics(hours = 24) {
    try {
        let url = `/api/v1/analytics/timeseries?hours=${hours}`;
        if (typeof currentTenantContext !== 'undefined' && currentTenantContext && currentTenantContext !== 'all' && currentTenantContext !== '*') {
            url += `&tenant=${encodeURIComponent(currentTenantContext)}`;
        }
        const res = await fetch(url);
        if (!res.ok) return null;
        return await res.json();
    } catch (e) {
        console.error('Failed to fetch timeseries analytics:', e);
        return null;
    }
}
window.fetchTimeseriesAnalytics = fetchTimeseriesAnalytics;

function initTelemetryCharts() {
    const canvasCPU = document.getElementById('chart-canvas-cpu');
    const canvasRAM = document.getElementById('chart-canvas-ram');
    const canvasLogs = document.getElementById('chart-canvas-logs');
    const canvasNet = document.getElementById('chart-canvas-net');

    if (!canvasCPU || !canvasRAM || !canvasLogs || !canvasNet) return;

    // Register direct click listeners for CPU and Network telemetry cards
    const cardCPU = document.getElementById('telemetry-card-cpu');
    if (cardCPU) {
        cardCPU.style.cursor = 'pointer';
        cardCPU.addEventListener('click', (e) => {
            e.preventDefault();
            openCPUDetailsModal();
        });
    }

    const cardNet = document.getElementById('telemetry-card-net');
    if (cardNet) {
        cardNet.style.cursor = 'pointer';
        cardNet.addEventListener('click', (e) => {
            e.preventDefault();
            openNetDetailsModal();
        });
    }

    // Modal backdrop click-to-close handlers
    const cpuModal = document.getElementById('cpu-details-modal');
    if (cpuModal) {
        cpuModal.addEventListener('click', (e) => {
            if (e.target === cpuModal) closeCPUDetailsModal();
        });
    }
    const netModal = document.getElementById('net-details-modal');
    if (netModal) {
        netModal.addEventListener('click', (e) => {
            if (e.target === netModal) closeNetDetailsModal();
        });
    }

    // Escape key listener to close open telemetry detail modals
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            if (window.cpuModalOpen) closeCPUDetailsModal();
            if (window.netModalOpen) closeNetDetailsModal();
        }
    });

    // Attach resize listeners to re-render smoothly
    window.addEventListener('resize', () => {
        if (telemetryHistoryData) renderAllTelemetryCharts(telemetryHistoryData);
    });

    // Start polling every 2 seconds
    fetchAndRenderTelemetryCharts();
    if (!telemetryChartTimer) {
        telemetryChartTimer = setInterval(fetchAndRenderTelemetryCharts, 2000);
    }
}

async function fetchAndRenderTelemetryCharts() {
    // Only render if dashboard tab is active
    const dashPane = document.getElementById('pane-dashboard');
    if (dashPane && !dashPane.classList.contains('active')) {
        return;
    }

    try {
        const res = await fetch('/api/v1/system/metrics/history');
        if (!res.ok) return;
        const data = await res.json();
        telemetryHistoryData = data;

        // Update Big Numeric Labels
        if (data.current) {
            const cur = data.current;

            // 1. CPU Label
            const elCpu = document.getElementById('chart-metric-cpu');
            if (elCpu) elCpu.textContent = `${(cur.cpu_percent || 0).toFixed(1)}%`;
            const elCores = document.getElementById('chart-meta-cores');
            if (elCores) {
                let coreTxt = `${cur.cpu_cores || 1} Cores (${cur.os || 'Linux'})`;
                if (cur.reserved_core) {
                    coreTxt += ` • 1 Core Reserved for Management`;
                }
                elCores.textContent = coreTxt;
            }

            // 2. RAM Label
            const elRam = document.getElementById('chart-metric-ram');
            if (elRam) {
                const usedGB = ((cur.ram_used_mb || 0) / 1024).toFixed(1);
                const totalGB = ((cur.ram_total_mb || 0) / 1024).toFixed(1);
                elRam.textContent = `${usedGB} / ${totalGB} GB`;
            }
            const elRamPct = document.getElementById('chart-meta-ram-pct');
            if (elRamPct) elRamPct.textContent = `${(cur.ram_percent || 0).toFixed(0)}%`;
            const elRamSub = document.getElementById('chart-sub-ram');
            if (elRamSub) elRamSub.textContent = `Allocated: ${(cur.ram_percent || 0).toFixed(1)}%`;

            // 3. Logs Received (EPS) Label
            const elLogs = document.getElementById('chart-metric-logs');
            if (elLogs) elLogs.textContent = `${Math.round(cur.logs_received_rate || 0).toLocaleString()} EPS`;
            const elPackets = document.getElementById('chart-sub-packets');
            if (elPackets) elPackets.textContent = `Total: ${(cur.total_packets_rx || 0).toLocaleString()} rx`;

            // 4. Network Throughput (In / Out) Label
            const elNet = document.getElementById('chart-metric-net');
            if (elNet) {
                const inFmt = formatTelemetryRate(cur.net_in_kbps || 0);
                const outFmt = formatTelemetryRate(cur.net_out_kbps || 0);
                elNet.textContent = `↓ ${inFmt} | ↑ ${outFmt}`;
            }

            // Refresh open modals live
            if (window.cpuModalOpen) {
                renderCPUDetails(cur);
            }
            if (window.netModalOpen) {
                renderNetDetails(cur);
            }
        }

        renderAllTelemetryCharts(data);
    } catch (e) {
        console.error('Error fetching telemetry metrics:', e);
    }
}

// ==============================================================================
// CPU Core Utilization & Network Interfaces Detail Modals
// ==============================================================================
window.cpuModalOpen = false;
window.netModalOpen = false;

function openCPUDetailsModal() {
    window.cpuModalOpen = true;
    const modal = document.getElementById('cpu-details-modal');
    if (modal) modal.style.display = 'flex';
    if (telemetryHistoryData && telemetryHistoryData.current) {
        renderCPUDetails(telemetryHistoryData.current);
    } else {
        fetch('/api/v1/system/metrics').then(r => r.json()).then(data => {
            renderCPUDetails(data);
        }).catch(err => console.error(err));
    }
}

function closeCPUDetailsModal() {
    window.cpuModalOpen = false;
    const modal = document.getElementById('cpu-details-modal');
    if (modal) modal.style.display = 'none';
}

function openNetDetailsModal() {
    window.netModalOpen = true;
    const modal = document.getElementById('net-details-modal');
    if (modal) modal.style.display = 'flex';
    if (telemetryHistoryData && telemetryHistoryData.current) {
        renderNetDetails(telemetryHistoryData.current);
    } else {
        fetch('/api/v1/system/metrics').then(r => r.json()).then(data => {
            renderNetDetails(data);
        }).catch(err => console.error(err));
    }
}

function closeNetDetailsModal() {
    window.netModalOpen = false;
    const modal = document.getElementById('net-details-modal');
    if (modal) modal.style.display = 'none';
}

window.openCPUDetailsModal = openCPUDetailsModal;
window.closeCPUDetailsModal = closeCPUDetailsModal;
window.openNetDetailsModal = openNetDetailsModal;
window.closeNetDetailsModal = closeNetDetailsModal;

function renderCPUDetails(cur) {
    if (!cur) return;

    // Top Summary
    const elTotPct = document.getElementById('cpu-modal-total-pct');
    if (elTotPct) elTotPct.textContent = `${(cur.cpu_percent || 0).toFixed(1)}%`;

    const elCores = document.getElementById('cpu-modal-core-count');
    if (elCores) elCores.textContent = `${cur.cpu_cores || 1}`;

    const elMaxProcs = document.getElementById('cpu-modal-maxprocs');
    if (elMaxProcs) elMaxProcs.textContent = `${cur.gomaxprocs || cur.cpu_cores || 1}`;

    const elResStatus = document.getElementById('cpu-modal-res-status');
    if (elResStatus) {
        if (cur.reserved_core) {
            elResStatus.innerHTML = `<span class="badge badge-warning" style="font-size: 0.75rem;">🛡️ 1 Core Reserved for Management</span>`;
        } else {
            elResStatus.innerHTML = `<span class="badge badge-secondary" style="font-size: 0.75rem;">⚡ All Cores Worker Active</span>`;
        }
    }

    // Cores Container
    const container = document.getElementById('cpu-cores-container');
    if (!container) return;

    const coresList = cur.cpu_cores_list || [];
    if (coresList.length === 0) {
        const totalCores = cur.cpu_cores || 1;
        for (let i = 0; i < totalCores; i++) {
            const isRes = cur.reserved_core && i === totalCores - 1;
            coresList.push({
                id: i,
                name: `CPU Core ${i}`,
                percent: cur.cpu_percent || 0,
                role: isRes ? 'Reserved for OS / Management' : 'Worker Thread',
                is_reserved: isRes
            });
        }
    }

    let html = '';
    coresList.forEach(core => {
        const pct = Math.max(0, Math.min(100, core.percent || 0));
        let barColor = '#06b6d4'; // cyan
        if (pct >= 85) {
            barColor = '#ef4444'; // red
        } else if (pct >= 60) {
            barColor = '#eab308'; // yellow
        }

        let roleBadge = `<span class="badge badge-info" style="font-size: 0.7rem;">⚡ ${core.role || 'Worker Thread'}</span>`;
        if (core.is_reserved) {
            roleBadge = `<span class="badge badge-warning" style="font-size: 0.7rem; background: rgba(234, 179, 8, 0.2); border: 1px solid rgba(234, 179, 8, 0.5); color: #fde047;">🛡️ ${core.role || 'Management Reserved'}</span>`;
        }

        html += `
            <div style="background: rgba(0, 0, 0, 0.25); border: 1px solid var(--border-color); border-radius: 8px; padding: 14px 16px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div style="font-weight: 600; font-size: 0.95rem; display: flex; align-items: center; gap: 8px;">
                        <span>💻 ${core.name}</span>
                        ${roleBadge}
                    </div>
                    <div style="font-family: monospace; font-size: 1.15rem; font-weight: 700; color: ${barColor};">
                        ${pct.toFixed(1)}%
                    </div>
                </div>
                <div style="width: 100%; height: 10px; background: rgba(255, 255, 255, 0.08); border-radius: 5px; overflow: hidden; position: relative;">
                    <div style="width: ${pct}%; height: 100%; background: ${barColor}; transition: width 0.4s ease; border-radius: 5px;"></div>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

function openNetDetailsModal() {
    window.netModalOpen = true;
    const modal = document.getElementById('net-details-modal');
    if (modal) modal.style.display = 'flex';
    if (telemetryHistoryData && telemetryHistoryData.current) {
        renderNetDetails(telemetryHistoryData.current);
    }
}

function closeNetDetailsModal() {
    window.netModalOpen = false;
    const modal = document.getElementById('net-details-modal');
    if (modal) modal.style.display = 'none';
}

function renderNetDetails(cur) {
    if (!cur) return;

    // Top Summary
    const elIn = document.getElementById('net-modal-in-rate');
    if (elIn) elIn.textContent = `↓ ${formatTelemetryRate(cur.net_in_kbps || 0)}`;

    const elOut = document.getElementById('net-modal-out-rate');
    if (elOut) elOut.textContent = `↑ ${formatTelemetryRate(cur.net_out_kbps || 0)}`;

    const elRx = document.getElementById('net-modal-total-rx');
    if (elRx) elRx.textContent = `${(cur.total_packets_rx || 0).toLocaleString()} rx`;

    const ifaces = cur.net_interfaces || [];
    const elIfCount = document.getElementById('net-modal-iface-count');
    if (elIfCount) elIfCount.textContent = `${ifaces.length}`;

    // Interfaces Container
    const container = document.getElementById('net-interfaces-container');
    if (!container) return;

    if (ifaces.length === 0) {
        container.innerHTML = `
            <div style="background: rgba(0, 0, 0, 0.2); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px; text-align: center;" class="text-muted">
                🌐 Main Host Network (Inbound: ${formatTelemetryRate(cur.net_in_kbps || 0)} | Outbound: ${formatTelemetryRate(cur.net_out_kbps || 0)})
            </div>
        `;
        return;
    }

    let html = '';
    ifaces.forEach(iface => {
        const isLoopback = iface.name === 'lo';
        const badgeColor = isLoopback ? 'badge-secondary' : 'badge-warning';

        html += `
            <div style="background: rgba(0, 0, 0, 0.25); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; margin-bottom: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.06); padding-bottom: 8px;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="badge ${badgeColor}" style="font-size: 0.85rem; font-weight: 700; padding: 4px 10px;">🌐 ${iface.name}</span>
                        <span style="font-size: 0.8rem; color: var(--text-muted);">${isLoopback ? 'Internal Loopback Interface' : 'Network Device Adapter'}</span>
                    </div>
                    <div style="font-size: 0.85rem; font-weight: 600; display: flex; gap: 16px;">
                        <span style="color: #22c55e;">↓ ${formatTelemetryRate(iface.net_in_kbps || 0)} (${(iface.rx_packets_per_sec || 0).toFixed(1)} pkts/s)</span>
                        <span style="color: #eab308;">↑ ${formatTelemetryRate(iface.net_out_kbps || 0)} (${(iface.tx_packets_per_sec || 0).toFixed(1)} pkts/s)</span>
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px;">
                    <!-- Inbound (Rx) -->
                    <div style="background: rgba(34, 197, 94, 0.05); border: 1px solid rgba(34, 197, 94, 0.2); border-radius: 6px; padding: 12px;">
                        <div style="font-weight: 600; font-size: 0.85rem; color: #22c55e; margin-bottom: 6px; display: flex; justify-content: space-between;">
                            <span>📥 Inbound Traffic (Rx)</span>
                            <span>${formatBytes(iface.rx_bytes || 0)}</span>
                        </div>
                        <div style="font-size: 0.8rem; display: flex; justify-content: space-between; color: var(--text-muted);">
                            <span>Total Packets: <strong style="color: var(--text-main);">${(iface.rx_packets || 0).toLocaleString()}</strong></span>
                            <span>Drops/Errors: <strong style="color: ${iface.rx_drop > 0 || iface.rx_errs > 0 ? '#ef4444' : 'var(--text-muted)'};">${iface.rx_drop || 0} / ${iface.rx_errs || 0}</strong></span>
                        </div>
                    </div>

                    <!-- Outbound (Tx) -->
                    <div style="background: rgba(234, 179, 8, 0.05); border: 1px solid rgba(234, 179, 8, 0.2); border-radius: 6px; padding: 12px;">
                        <div style="font-weight: 600; font-size: 0.85rem; color: #eab308; margin-bottom: 6px; display: flex; justify-content: space-between;">
                            <span>📤 Outbound Traffic (Tx)</span>
                            <span>${formatBytes(iface.tx_bytes || 0)}</span>
                        </div>
                        <div style="font-size: 0.8rem; display: flex; justify-content: space-between; color: var(--text-muted);">
                            <span>Total Packets: <strong style="color: var(--text-main);">${(iface.tx_packets || 0).toLocaleString()}</strong></span>
                            <span>Drops/Errors: <strong style="color: ${iface.tx_drop > 0 || iface.tx_errs > 0 ? '#ef4444' : 'var(--text-muted)'};">${iface.tx_drop || 0} / ${iface.tx_errs || 0}</strong></span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return '0 B';
    if (bytes >= 1073741824) {
        return `${(bytes / 1073741824).toFixed(2)} GB`;
    }
    if (bytes >= 1048576) {
        return `${(bytes / 1048576).toFixed(1)} MB`;
    }
    if (bytes >= 1024) {
        return `${(bytes / 1024).toFixed(1)} KB`;
    }
    return `${bytes} B`;
}

function formatTelemetryRate(kbps) {
    if (!kbps || kbps < 0) kbps = 0;
    if (kbps >= 1024) {
        return `${(kbps / 1024).toFixed(2)} MB/s`;
    }
    return `${kbps.toFixed(1)} KB/s`;
}

function renderAllTelemetryCharts(data) {
    if (!data || !data.points || data.points.length === 0) return;

    const points = data.points;
    const timestamps = points.map(p => p.timestamp);
    const maxPoints = data.max_points || 60;

    // 1. CPU Chart (Cyan area)
    drawSmoothAreaChart('chart-canvas-cpu', [
        {
            data: points.map(p => p.cpu_percent),
            color: '#06B6D4',
            fillColor: 'rgba(6, 182, 212, 0.28)'
        }
    ], {
        fixedMin: 0,
        fixedMax: 100,
        showLabels: true,
        formatLabel: val => `${Math.round(val)}%`,
        timestamps: timestamps,
        maxPoints: maxPoints
    });

    // 2. RAM Chart (Purple area)
    drawSmoothAreaChart('chart-canvas-ram', [
        {
            data: points.map(p => p.ram_percent),
            color: '#A855F7',
            fillColor: 'rgba(168, 85, 247, 0.28)'
        }
    ], {
        fixedMin: 0,
        fixedMax: 100,
        showLabels: true,
        formatLabel: val => `${Math.round(val)}%`,
        timestamps: timestamps,
        maxPoints: maxPoints
    });

    // 3. Logs Received (EPS) Chart (Green area)
    drawSmoothAreaChart('chart-canvas-logs', [
        {
            data: points.map(p => p.logs_received_rate),
            color: '#10B981',
            fillColor: 'rgba(16, 185, 129, 0.28)'
        }
    ], {
        fixedMin: 0,
        showLabels: true,
        formatLabel: val => `${Math.round(val)}`,
        timestamps: timestamps,
        maxPoints: maxPoints
    });

    // 4. Network Throughput Chart (Dual series: In / Rx Amber, Out / Tx Sky Blue)
    drawSmoothAreaChart('chart-canvas-net', [
        {
            data: points.map(p => p.net_in_kbps),
            color: '#F59E0B',
            fillColor: 'rgba(245, 158, 11, 0.22)',
            label: 'In (Rx)'
        },
        {
            data: points.map(p => p.net_out_kbps),
            color: '#38BDF8',
            fillColor: 'rgba(56, 189, 248, 0.12)',
            label: 'Out (Tx)'
        }
    ], {
        fixedMin: 0,
        showLabels: true,
        formatLabel: val => formatTelemetryRate(val),
        timestamps: timestamps,
        maxPoints: maxPoints
    });
}

function drawSmoothAreaChart(canvasId, seriesList, options = {}) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const wrap = canvas.parentElement;
    const width = (wrap && wrap.clientWidth > 50) ? wrap.clientWidth : (canvas.clientWidth || 340);
    const height = 130; // Constant fixed height: guaranteed never to shrink or collapse!

    // Lock CSS dimensions
    canvas.style.width = width + 'px';
    canvas.style.height = height + 'px';

    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);

    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); // Explicitly resets transform matrix to prevent scale compounding

    const padTop = 12;
    const padBottom = 22;
    const padLeft = 8;
    const padRight = 38; // space for Y-axis scale labels

    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    ctx.clearRect(0, 0, width, height);

    // Calculate value range
    let minVal = options.fixedMin !== undefined ? options.fixedMin : 0;
    let maxVal = options.fixedMax !== undefined ? options.fixedMax : 0;

    seriesList.forEach(s => {
        if (!s.data || s.data.length === 0) return;
        const sMax = Math.max(...s.data);
        if (sMax > maxVal) maxVal = sMax;
    });

    if (maxVal <= minVal) maxVal = minVal + 10;
    if (options.fixedMax === undefined) {
        maxVal = maxVal * 1.25; // 25% headroom
    }

    const valRange = maxVal - minVal;

    // Subtle horizontal grid lines at 0%, 50%, 100%
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    ctx.setLineDash([3, 3]);

    [0, 0.5, 1.0].forEach(pct => {
        const y = padTop + plotH * (1 - pct);
        ctx.beginPath();
        ctx.moveTo(padLeft, y);
        ctx.lineTo(width - padRight, y);
        ctx.stroke();

        // Right-aligned scale label
        if (options.showLabels) {
            ctx.fillStyle = 'rgba(142, 155, 176, 0.7)';
            ctx.font = '9px monospace';
            ctx.textAlign = 'left';
            const labelVal = minVal + valRange * pct;
            const text = options.formatLabel ? options.formatLabel(labelVal) : Math.round(labelVal);
            ctx.fillText(text, width - padRight + 4, y + 3);
        }
    });
    ctx.setLineDash([]); // reset dash

    const maxSlots = options.maxPoints || 60;
    const stepX = plotW / (maxSlots - 1);

    // Draw each series
    seriesList.forEach(series => {
        const data = series.data || [];
        if (data.length === 0) return;

        const count = data.length;

        // Position points from right edge backwards so scale never shrinks as points are added
        const points = data.map((val, idx) => {
            const fromRight = (count - 1 - idx) * stepX;
            const x = Math.max(padLeft, padLeft + plotW - fromRight);
            const clampedVal = Math.max(minVal, Math.min(maxVal, val));
            const y = padTop + plotH * (1 - (clampedVal - minVal) / valRange);
            return { x, y, val };
        });

        if (points.length === 1) {
            // Draw single point indicator
            const pt = points[0];
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, 4, 0, Math.PI * 2);
            ctx.fillStyle = series.color;
            ctx.fill();
            return;
        }

        // 1. Fill Area with smooth gradient
        const grad = ctx.createLinearGradient(0, padTop, 0, padTop + plotH);
        grad.addColorStop(0, series.fillColor || `${series.color}40`);
        grad.addColorStop(1, `${series.color}00`);

        ctx.beginPath();
        ctx.moveTo(points[0].x, padTop + plotH);
        ctx.lineTo(points[0].x, points[0].y);

        for (let i = 0; i < points.length - 1; i++) {
            const cpX = (points[i].x + points[i + 1].x) / 2;
            ctx.bezierCurveTo(cpX, points[i].y, cpX, points[i + 1].y, points[i + 1].x, points[i + 1].y);
        }

        ctx.lineTo(points[points.length - 1].x, padTop + plotH);
        ctx.closePath();
        ctx.fillStyle = grad;
        ctx.fill();

        // 2. Draw Curve Stroke Line
        ctx.beginPath();
        ctx.moveTo(points[0].x, points[0].y);

        for (let i = 0; i < points.length - 1; i++) {
            const cpX = (points[i].x + points[i + 1].x) / 2;
            ctx.bezierCurveTo(cpX, points[i].y, cpX, points[i + 1].y, points[i + 1].x, points[i + 1].y);
        }

        ctx.strokeStyle = series.color;
        ctx.lineWidth = 2.2;
        ctx.stroke();

        // 3. Glowing live end point indicator on latest point
        const lastPt = points[points.length - 1];
        ctx.beginPath();
        ctx.arc(lastPt.x, lastPt.y, 3.5, 0, Math.PI * 2);
        ctx.fillStyle = series.color;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(lastPt.x, lastPt.y, 6.5, 0, Math.PI * 2);
        ctx.strokeStyle = series.color;
        ctx.lineWidth = 1;
        ctx.stroke();
    });

    // Bottom time baseline
    ctx.strokeStyle = 'rgba(45, 51, 67, 0.7)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padLeft, height - padBottom);
    ctx.lineTo(width - padRight, height - padBottom);
    ctx.stroke();

    // Time axis labels
    if (options.timestamps && options.timestamps.length >= 2) {
        ctx.fillStyle = 'rgba(142, 155, 176, 0.7)';
        ctx.font = '9px monospace';
        ctx.textAlign = 'left';
        ctx.fillText(options.timestamps[0], padLeft, height - 6);

        ctx.textAlign = 'right';
        ctx.fillText(options.timestamps[options.timestamps.length - 1], width - padRight, height - 6);
    }
}

// ==========================================================================
// Security Alerts Notification Center Controller
// ==========================================================================
let headerAlertsList = [];
let headerAlertsUnreadCount = 0;

function initAlertNotificationCenter() {
    const btn = document.getElementById('header-alerts-btn');
    const dropdown = document.getElementById('header-alerts-dropdown');
    const btnClose = document.getElementById('btn-close-alerts-dropdown');
    const btnClear = document.getElementById('btn-clear-alerts-badge');
    const btnViewAll = document.getElementById('btn-view-all-siem-alerts');

    if (!btn || !dropdown) return;

    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = dropdown.style.display !== 'none';
        dropdown.style.display = isOpen ? 'none' : 'flex';
        if (!isOpen) {
            headerAlertsUnreadCount = 0;
            updateAlertsBadge();
        }
    });

    if (btnClose) {
        btnClose.addEventListener('click', (e) => {
            e.stopPropagation();
            dropdown.style.display = 'none';
        });
    }

    if (btnClear) {
        btnClear.addEventListener('click', (e) => {
            e.stopPropagation();
            headerAlertsUnreadCount = 0;
            updateAlertsBadge();
        });
    }

    if (btnViewAll) {
        btnViewAll.addEventListener('click', (e) => {
            e.preventDefault();
            dropdown.style.display = 'none';
            if (typeof switchTab === 'function') {
                switchTab('siem');
            }
        });
    }

    // Close on click outside
    document.addEventListener('click', (e) => {
        const wrapper = document.getElementById('header-alerts-wrapper');
        if (wrapper && !wrapper.contains(e.target)) {
            dropdown.style.display = 'none';
        }
    });

    // Initial fetch of recent alerts
    loadInitialAlertsForNotificationCenter();
}

async function loadInitialAlertsForNotificationCenter() {
    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/siem/alerts?limit=15&tenant=${encodeURIComponent(tenant)}`);
        if (!res.ok) return;
        const data = await res.json();
        const alerts = data.alerts || [];
        headerAlertsList = alerts;
        headerAlertsUnreadCount = alerts.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH').length;
        renderHeaderAlertsDropdown();
        updateAlertsBadge();
    } catch (e) {
        console.warn('Error fetching alerts for header notification center:', e);
    }
}

function addAlertToNotificationCenter(alert) {
    if (!alert) return;
    if (alert.id) {
        headerAlertsList = headerAlertsList.filter(a => a.id !== alert.id);
    }
    headerAlertsList.unshift(alert);
    if (headerAlertsList.length > 30) headerAlertsList.pop();

    headerAlertsUnreadCount++;
    renderHeaderAlertsDropdown();
    updateAlertsBadge();
}

function updateAlertsBadge() {
    const badge = document.getElementById('header-alerts-badge');
    const critBadge = document.getElementById('alerts-dropdown-crit-count');
    if (badge) {
        if (headerAlertsUnreadCount > 0) {
            badge.textContent = headerAlertsUnreadCount > 99 ? '99+' : headerAlertsUnreadCount;
            badge.style.display = 'inline-block';
        } else {
            badge.style.display = 'none';
        }
    }
    if (critBadge) {
        const crits = headerAlertsList.filter(a => a.severity === 'CRITICAL').length;
        if (crits > 0) {
            critBadge.textContent = `${crits} Critical`;
            critBadge.style.display = 'inline-block';
        } else {
            critBadge.style.display = 'none';
        }
    }
}

function renderHeaderAlertsDropdown() {
    const container = document.getElementById('alerts-dropdown-list');
    if (!container) return;

    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k, fallback) => fallback || k;
    const isTr = (window.i18n && window.i18n.currentLang === 'tr');

    if (!headerAlertsList || headerAlertsList.length === 0) {
        container.innerHTML = `
            <div class="alerts-dropdown-empty" style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 12px;">
                ${t('alerts_no_recent', isTr ? 'Yeni güvenlik uyarısı bulunmuyor.' : 'No recent security alerts.')}
            </div>
        `;
        return;
    }

    container.innerHTML = headerAlertsList.map(a => {
        const sev = (a.severity || 'low').toLowerCase();
        const sevClass = sev === 'critical' ? 'badge-danger' : (sev === 'high' ? 'badge-warning' : (sev === 'medium' ? 'badge-info' : 'badge-secondary'));
        const timeAgo = (typeof formatRelativeTime === 'function' && (a.created_at || a.timestamp)) ? formatRelativeTime(a.created_at || a.timestamp) : (isTr ? 'Yeni' : 'Recent');
        const source = a.source_ip || a.source_device || (isTr ? 'Ağ Tehdidi' : 'Network Threat');
        const ruleName = a.rule_name || a.title || 'Security Alert';

        return `
            <div class="alert-dropdown-item" onclick="onHeaderAlertClick('${escapeHtml(a.id || '')}')">
                <div class="alert-dropdown-item-header">
                    <span class="badge ${sevClass}" style="font-size: 9.5px; font-weight: 700; padding: 1px 5px;">${escapeHtml((a.severity || 'INFO').toUpperCase())}</span>
                    <span style="font-size: 10px; color: var(--text-muted);">${escapeHtml(timeAgo)}</span>
                </div>
                <div class="alert-dropdown-item-title">${escapeHtml(ruleName)}</div>
                <div class="alert-dropdown-item-meta">
                    <span><i class="fas fa-network-wired" style="font-size: 10px; margin-right: 3px;"></i>${escapeHtml(source)}</span>
                    <span style="color: var(--accent); font-weight: 500;">${isTr ? 'İncele &rarr;' : 'Inspect &rarr;'}</span>
                </div>
            </div>
        `;
    }).join('');
}

function onHeaderAlertClick(alertId) {
    const dropdown = document.getElementById('header-alerts-dropdown');
    if (dropdown) dropdown.style.display = 'none';

    if (alertId && typeof openSIEMInvestigate === 'function') {
        openSIEMInvestigate(alertId);
    } else if (typeof switchTab === 'function') {
        switchTab('siem');
    }
}

// ==========================================================================
// SIEM & Security Operations Center (SOC) Controller
// ==========================================================================
let siemFilterStatus = 'ALL';
let siemFilterSeverity = 'ALL';
let siemSearchQuery = '';
let currentInvestigatingAlertID = null;
let siemLiveSocket = null;

function initSIEMManagement() {
    // 0. Initialize Header Alert Notification Center
    initAlertNotificationCenter();

    // 1. Initial overview count to populate badge
    loadSIEMOverview();

    // 2. Connect Live Alert WebSocket
    connectSIEMLiveStream();

    // 3. Status filter buttons
    const statusFilterBtns = document.querySelectorAll('#siem-status-filters button');
    statusFilterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            statusFilterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            siemFilterStatus = btn.getAttribute('data-status') || 'ALL';
            loadSIEMAlerts();
        });
    });

    // 4. Severity select filter
    const sevSelect = document.getElementById('siem-filter-severity');
    if (sevSelect) {
        sevSelect.addEventListener('change', () => {
            siemFilterSeverity = sevSelect.value;
            loadSIEMAlerts();
        });
    }

    // 5. Search input with debounce
    const searchInput = document.getElementById('siem-search-input');
    if (searchInput) {
        let debounceTimer;
        searchInput.addEventListener('input', () => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                siemSearchQuery = searchInput.value.trim();
                loadSIEMAlerts();
            }, 300);
        });
    }

    // 6. Action buttons
    const btnRefresh = document.getElementById('btn-refresh-siem');
    if (btnRefresh) {
        btnRefresh.addEventListener('click', () => {
            loadSIEMData();
            showToast('SIEM telemetrisi güncellendi', 'info');
        });
    }

    const btnOpenMitre = document.getElementById('btn-open-mitre-matrix');
    if (btnOpenMitre) {
        btnOpenMitre.addEventListener('click', openSIEMMitreModal);
    }

    const btnSocOpt = document.getElementById('btn-soc-optimize-devices');
    if (btnSocOpt) {
        btnSocOpt.addEventListener('click', optimizeSIEMDeviceRules);
    }

    const btnOpenRules = document.getElementById('btn-open-siem-rules');
    if (btnOpenRules) {
        btnOpenRules.addEventListener('click', openSIEMRulesModal);
    }

    const btnOpenSOAR = document.getElementById('btn-open-soar-playbooks');
    if (btnOpenSOAR) {
        btnOpenSOAR.addEventListener('click', openSOARModal);
    }

    const btnOpenSimulate = document.getElementById('btn-open-siem-simulate');
    if (btnOpenSimulate) {
        btnOpenSimulate.addEventListener('click', () => {
            const isRootSuperAdmin = window.currentUser && (window.currentUser.is_root !== false && (window.currentUser.tenant_slug === 'default' || !window.currentUser.tenant_slug)) && window.currentUser.role === 'Super Administrator';
            if (!isRootSuperAdmin) {
                showToast('Yalnızca root organizasyonun Süper Yöneticisi tehdit simülasyonu gerçekleştirebilir.', 'error');
                return;
            }
            const modal = document.getElementById('siem-simulate-modal');
            if (modal) modal.style.display = 'flex';
        });
    }

    // 7. Modal close triggers
    const btnCloseInv = document.getElementById('btn-close-siem-inv');
    if (btnCloseInv) {
        btnCloseInv.addEventListener('click', () => {
            const m = document.getElementById('siem-investigate-modal');
            if (m) { m.classList.remove('active'); m.style.display = 'none'; }
        });
    }

    const btnCloseRules = document.getElementById('btn-close-siem-rules');
    if (btnCloseRules) {
        btnCloseRules.addEventListener('click', () => {
            const m = document.getElementById('siem-rules-modal');
            if (m) { m.classList.remove('active'); m.style.display = 'none'; }
        });
    }

    const btnCloseSim = document.getElementById('btn-close-siem-simulate');
    if (btnCloseSim) {
        btnCloseSim.addEventListener('click', () => {
            const m = document.getElementById('siem-simulate-modal');
            if (m) { m.classList.remove('active'); m.style.display = 'none'; }
        });
    }

    const btnCloseMitre = document.getElementById('btn-close-siem-mitre');
    if (btnCloseMitre) {
        btnCloseMitre.addEventListener('click', () => {
            const m = document.getElementById('siem-mitre-modal');
            if (m) { m.classList.remove('active'); m.style.display = 'none'; }
        });
    }

    const btnSyncMitre = document.getElementById('btn-sync-mitre-feed');
    if (btnSyncMitre) {
        btnSyncMitre.addEventListener('click', syncSIEMMitreFeed);
    }

    // Backdrop dismissal
    ['siem-investigate-modal', 'siem-rules-modal', 'siem-simulate-modal', 'siem-mitre-modal'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('click', (e) => {
                if (e.target === el) el.style.display = 'none';
            });
        }
    });

    // 8. Triage and Note triggers
    const btnSaveStatus = document.getElementById('btn-save-siem-status');
    if (btnSaveStatus) {
        btnSaveStatus.addEventListener('click', saveSIEMAlertStatus);
    }

    const btnAddNote = document.getElementById('btn-add-siem-note');
    if (btnAddNote) {
        btnAddNote.addEventListener('click', addSIEMAlertNote);
    }

    // 9. Simulation scenario triggers
    document.querySelectorAll('.sim-card').forEach(card => {
        card.addEventListener('click', () => {
            const scenario = card.getAttribute('data-scenario');
            if (scenario) runSIEMSimulation(scenario);
        });
    });
}

function loadSIEMData() {
    loadSIEMOverview();
    loadSIEMAlerts();
}

async function loadSIEMOverview() {
    try {
        const res = await fetch('/api/v1/siem/overview');
        if (res.status === 401 || (res.redirected && res.url.includes('/login'))) {
            window.location.href = '/login';
            return;
        }
        if (!res.ok) return;
        const data = await res.json();

        // Update Scoreboard
        const elActive = document.getElementById('siem-stat-active');
        if (elActive) elActive.textContent = (data.active_incidents || 0).toLocaleString();

        const elCritical = document.getElementById('siem-stat-critical');
        if (elCritical) elCritical.textContent = ((data.critical_alerts || 0) + (data.high_alerts || 0)).toLocaleString();

        const elCritSub = document.getElementById('siem-stat-critical-sub');
        if (elCritSub) elCritSub.textContent = `${data.critical_alerts || 0} Critical, ${data.high_alerts || 0} High`;

        const elRisk = document.getElementById('siem-stat-risk');
        if (elRisk) elRisk.textContent = `${data.mean_risk_score || 0} / 100`;

        const elRiskSub = document.getElementById('siem-stat-risk-sub');
        if (elRiskSub) {
            const score = data.mean_risk_score || 0;
            if (score > 70) elRiskSub.textContent = 'High perimeter threat activity';
            else if (score > 35) elRiskSub.textContent = 'Moderate security alerts detected';
            else elRiskSub.textContent = 'Low perimeter threat activity';
        }

        const elTotal = document.getElementById('siem-stat-total');
        if (elTotal) elTotal.textContent = (data.total_alerts || 0).toLocaleString();

        const elResolved = document.getElementById('siem-stat-resolved');
        if (elResolved) elResolved.textContent = (data.resolved_incidents || 0).toLocaleString();

        // Update Sidebar Badge
        const badge = document.getElementById('siem-active-badge');
        if (badge) {
            const active = data.active_incidents || 0;
            if (active > 0) {
                badge.style.display = 'inline-block';
                badge.textContent = active > 99 ? '99+' : active;
            } else {
                badge.style.display = 'none';
            }
        }

        // Render Top Attackers
        renderEntityList('siem-top-attackers-list', data.top_attackers || [], 'IP', 'events');

        // Render Top Targets (merge users & devices)
        const combinedTargets = (data.top_target_users || []).concat(data.top_target_devices || []);
        renderEntityList('siem-top-targets-list', combinedTargets, 'Asset', 'events');

        // Render MITRE ATT&CK Tactics
        renderEntityList('siem-mitre-tactics-list', data.mitre_tactic_distribution || [], 'Tactic', 'hits');

    } catch (e) {
        console.error('Failed to load SIEM overview:', e);
    }
}

function renderEntityList(containerId, list, typeLabel, unitLabel) {
    const el = document.getElementById(containerId);
    if (!el) return;

    if (!list || list.length === 0) {
        el.innerHTML = `<div class="text-muted text-center" style="padding: 12px 0;">No active ${typeLabel.toLowerCase()}s recorded</div>`;
        return;
    }

    el.innerHTML = list.map(item => `
        <div class="soc-entity-item">
            <span class="soc-entity-key">${escapeHtml(item.key)}</span>
            <span class="badge badge-outline" style="font-size: 11px;">${item.count.toLocaleString()} ${unitLabel}</span>
        </div>
    `).join('');
}

async function loadSIEMAlerts() {
    const tbody = document.getElementById('siem-alerts-body');
    if (!tbody) return;

    try {
        const params = new URLSearchParams();
        if (siemFilterStatus && siemFilterStatus !== 'ALL') params.append('status', siemFilterStatus);
        if (siemFilterSeverity && siemFilterSeverity !== 'ALL') params.append('severity', siemFilterSeverity);
        if (siemSearchQuery) params.append('search', siemSearchQuery);

        const res = await fetch(`/api/v1/siem/alerts?${params.toString()}`);
        if (res.status === 401 || (res.redirected && res.url.includes('/login'))) {
            window.location.href = '/login';
            return;
        }
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || `HTTP ${res.status}`);
        }
        const data = await res.json();
        const alerts = data.alerts || [];

        const countBadge = document.getElementById('siem-table-count');
        if (countBadge) countBadge.textContent = `${data.total || alerts.length} Incidents`;

        if (alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted" style="padding: 24px;">No security incidents match the current filters.</td></tr>`;
            return;
        }

        tbody.innerHTML = alerts.map(alert => {
            const sevBadge = getSeverityBadgeHTML(alert.severity);
            const statusBadge = `<span class="badge badge-status-${(alert.status || 'new').toLowerCase()}">${escapeHtml(alert.status)}</span>`;
            const mitreBadge = alert.mitre_technique ? `<span class="badge badge-mitre" title="${escapeHtml(alert.mitre_tactic || '')}">${escapeHtml(alert.mitre_technique)}</span>` : '<span class="text-muted">-</span>';
            const threatVector = `${escapeHtml(alert.source_ip || 'unknown')} &rarr; ${escapeHtml(alert.username || alert.device_name || alert.destination_ip || 'host')}`;
            const timeStr = formatRelativeTime(alert.created_at);
            const tenantBadge = (alert.tenant && (currentTenantContext === 'all' || alert.tenant !== 'default'))
                ? ` <span class="tenant-chip" title="Kiracı / Tenant" style="font-size: 11px; margin-left: 6px;">🏢 ${escapeHtml(alert.tenant)}</span>`
                : '';

            return `
                <tr>
                    <td>${sevBadge}</td>
                    <td style="font-size: 12px; color: var(--text-muted);">${timeStr}</td>
                    <td>
                        <div style="font-weight: 600; color: var(--text-main); display: flex; align-items: center; gap: 4px; flex-wrap: wrap;">
                            <span>${escapeHtml(alert.rule_name)}</span>
                            ${tenantBadge}
                        </div>
                        <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(alert.category)}</div>
                    </td>
                    <td>${mitreBadge}</td>
                    <td><span class="mono-code" style="font-size: 12px;">${threatVector}</span></td>
                    <td><span class="badge badge-outline">${alert.event_count || 1} pkts</span></td>
                    <td>${statusBadge}</td>
                    <td style="font-size: 12px;">${escapeHtml(alert.assigned_to || 'Unassigned')}</td>
                    <td style="text-align: right;">
                        <button class="btn btn-outline btn-sm" onclick="openSIEMInvestigate('${alert.id}')">🔍 Investigate</button>
                    </td>
                </tr>
            `;
        }).join('');

    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-red" style="padding: 20px;">Failed to load alerts: ${e.message}</td></tr>`;
    }
}

function getSeverityBadgeHTML(sev) {
    switch ((sev || '').toUpperCase()) {
        case 'CRITICAL':
            return '<span class="badge badge-danger pulsing-alert" style="font-weight: 700;">CRITICAL</span>';
        case 'HIGH':
            return '<span class="badge badge-danger" style="font-weight: 600;">HIGH</span>';
        case 'MEDIUM':
            return '<span class="badge badge-warning" style="font-weight: 600;">MEDIUM</span>';
        case 'LOW':
            return '<span class="badge badge-secondary">LOW</span>';
        default:
            return `<span class="badge badge-outline">${escapeHtml(sev || 'INFO')}</span>`;
    }
}

function formatRelativeTime(isoStr) {
    if (!isoStr) return '-';
    const date = new Date(isoStr);
    const now = new Date();
    const diffSec = Math.floor((now - date) / 1000);

    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

async function openSIEMInvestigate(alertID) {
    currentInvestigatingAlertID = alertID;
    const modal = document.getElementById('siem-investigate-modal');
    if (!modal) return;

    modal.classList.add('active');
    modal.style.display = 'flex';

    try {
        const res = await fetch(`/api/v1/siem/alerts/${alertID}`);
        if (!res.ok) throw new Error('Alert not found');
        const data = await res.json();
        const alert = data.alert;
        const notes = data.notes || [];

        // Header
        document.getElementById('siem-inv-title').textContent = alert.rule_name || 'Incident Details';
        document.getElementById('siem-inv-rule-badge').textContent = alert.rule_id || 'ALERT';
        document.getElementById('siem-inv-summary').textContent = alert.summary || 'Security event summary';

        // Details Grid
        document.getElementById('siem-inv-severity').innerHTML = getSeverityBadgeHTML(alert.severity);
        document.getElementById('siem-inv-risk').textContent = `${alert.risk_score || 0} / 100`;
        document.getElementById('siem-inv-src-ip').textContent = alert.source_ip || 'N/A';
        document.getElementById('siem-inv-user').textContent = alert.username || 'N/A';
        document.getElementById('siem-inv-device').textContent = alert.device_name || 'N/A';
        document.getElementById('siem-inv-mitre').textContent = `${alert.mitre_technique || 'N/A'} (${alert.mitre_tactic || 'General'})`;
        document.getElementById('siem-inv-count').textContent = `${alert.event_count || 1} logs matched`;
        document.getElementById('siem-inv-timeline').textContent = `${new Date(alert.first_seen).toLocaleTimeString()} - ${new Date(alert.last_seen).toLocaleTimeString()}`;
        const tenantEl = document.getElementById('siem-inv-tenant');
        if (tenantEl) {
            tenantEl.textContent = `🏢 ${alert.tenant || 'default'}`;
        }

        // Triage Controls
        document.getElementById('siem-inv-status-select').value = alert.status || 'NEW';
        document.getElementById('siem-inv-assigned-input').value = alert.assigned_to || (window.currentUser ? window.currentUser.username : 'admin');

        // Forensic Evidence Logs
        const evidenceEl = document.getElementById('siem-inv-evidence-logs');
        const evidenceCountEl = document.getElementById('siem-inv-evidence-count');
        const evLogs = alert.evidence_logs || [];
        evidenceCountEl.textContent = `${evLogs.length} events`;
        if (evLogs.length > 0) {
            evidenceEl.textContent = evLogs.join('\n');
        } else {
            evidenceEl.textContent = 'No raw log evidence attached to this alert.';
        }

        // Match connected endpoint agent for SOAR Active Mitigation
        let matchedAgent = null;
        try {
            const agRes = await fetch(`/api/v1/endpoint/agents`);
            if (agRes.ok) {
                const agData = await agRes.json();
                const agents = agData.agents || [];
                matchedAgent = agents.find(a => 
                    (alert.device_name && a.hostname && a.hostname.toLowerCase() === alert.device_name.toLowerCase()) ||
                    (alert.source_ip && (a.ip_address === alert.source_ip || (a.ip_addresses && a.ip_addresses.includes(alert.source_ip)))) ||
                    (alert.destination_ip && (a.ip_address === alert.destination_ip || (a.ip_addresses && a.ip_addresses.includes(alert.destination_ip))))
                );
            }
        } catch (_) {}

        const matchedBadge = document.getElementById('siem-inv-agent-matched-badge');
        const agentNameEl = document.getElementById('siem-inv-agent-name');
        const agentIsoEl = document.getElementById('siem-inv-agent-iso-badge');
        const btnIso = document.getElementById('btn-siem-quick-isolate');
        const btnIsoText = document.getElementById('btn-siem-quick-isolate-text');
        const btnOsquery = document.getElementById('btn-siem-quick-osquery');
        const btnRunPB = document.getElementById('btn-siem-run-playbook');

        if (matchedAgent) {
            if (matchedBadge) matchedBadge.innerHTML = `<span class="badge badge-success" style="font-size: 11px;">🟢 Ajan Çevrimiçi (${escapeHtml(matchedAgent.agent_version)})</span>`;
            if (agentNameEl) agentNameEl.textContent = matchedAgent.hostname + ' (' + (matchedAgent.ip_address || '-') + ')';
            if (agentIsoEl) {
                if (matchedAgent.is_isolated) {
                    agentIsoEl.className = 'badge badge-danger pulsing-alert';
                    agentIsoEl.textContent = 'ISOLATED';
                    if (btnIsoText) btnIsoText.textContent = 'İzolasyonu Kaldır';
                    if (btnIso) btnIso.onclick = () => openActiveResponseModal(matchedAgent.id, 'unisolate');
                } else {
                    agentIsoEl.className = 'badge badge-outline';
                    agentIsoEl.textContent = 'NORMAL';
                    if (btnIsoText) btnIsoText.textContent = 'Uç Noktayı İzole Et';
                    if (btnIso) btnIso.onclick = () => openActiveResponseModal(matchedAgent.id, 'isolate');
                }
            }
            if (btnOsquery) {
                btnOsquery.onclick = () => openActiveResponseModal(matchedAgent.id, 'osquery');
            }
            if (btnRunPB) {
                btnRunPB.onclick = () => openSOARRunModal(null, matchedAgent.id, alert.id);
            }
        } else {
            if (matchedBadge) matchedBadge.innerHTML = `<span class="badge badge-secondary" style="font-size: 11px;">⚪ Ajan Eşleşmedi</span>`;
            if (agentNameEl) agentNameEl.textContent = alert.device_name || alert.source_ip || 'Ajan bulunamadı';
            if (agentIsoEl) {
                agentIsoEl.className = 'badge badge-outline';
                agentIsoEl.textContent = 'N/A';
            }
            if (btnIso) {
                btnIso.onclick = () => showToast('Bu olay için kayıtlı aktif LogSeal ajanı bulunamadı.', 'warning');
            }
            if (btnOsquery) {
                btnOsquery.onclick = () => showToast('Adli sorgulama için bağlı bir ajan gereklidir.', 'warning');
            }
            if (btnRunPB) {
                btnRunPB.onclick = () => openSOARRunModal(null, null, alert.id);
            }
        }

        // Check if there are any pending SOAR approvals for this alert
        const pendingCard = document.getElementById('siem-inv-pending-approval-card');
        const pendingPBName = document.getElementById('siem-inv-pending-pb-name');
        const btnApprove = document.getElementById('btn-siem-approve-soar');
        const btnReject = document.getElementById('btn-siem-reject-soar');
        if (pendingCard) pendingCard.style.display = 'none';

        try {
            const execRes = await fetch(`/api/v1/soar/executions?status=PENDING_APPROVAL`);
            if (execRes.ok) {
                const execData = await execRes.json();
                const pendingExec = (execData.executions || []).find(e => e.alert_id === alert.id);
                if (pendingExec && pendingCard) {
                    pendingCard.style.display = 'block';
                    if (pendingPBName) pendingPBName.textContent = pendingExec.playbook_name;
                    if (btnApprove) btnApprove.onclick = () => approveSOARExecution(pendingExec.id);
                    if (btnReject) btnReject.onclick = () => rejectSOARExecution(pendingExec.id);
                }
            }
        } catch (_) {}

        // Render Case Notes
        renderSIEMNotes(notes);

    } catch (e) {
        showToast(`Adli detaylar yüklenemedi: ${e.message}`, 'error');
    }
}

function renderSIEMNotes(notes) {
    const notesStream = document.getElementById('siem-inv-notes-stream');
    if (!notesStream) return;

    if (!notes || notes.length === 0) {
        notesStream.innerHTML = '<div class="text-muted text-center" style="font-size: 12px; padding: 10px;">Henüz adli analiz notu eklenmedi.</div>';
        return;
    }

    notesStream.innerHTML = notes.map(n => `
        <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06); border-radius: 6px; padding: 8px 10px;">
            <div style="display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 4px;">
                <span style="font-weight: 600; color: var(--primary);">👤 ${escapeHtml(n.author)}</span>
                <span style="color: var(--text-muted);">${new Date(n.created_at).toLocaleString()}</span>
            </div>
            <div style="font-size: 12px; color: var(--text-main); white-space: pre-wrap;">${escapeHtml(n.note)}</div>
        </div>
    `).join('');
}

async function saveSIEMAlertStatus() {
    if (!currentInvestigatingAlertID) return;

    const status = document.getElementById('siem-inv-status-select').value;
    const assignedTo = document.getElementById('siem-inv-assigned-input').value.trim() || 'admin';

    try {
        const res = await fetch(`/api/v1/siem/alerts/${currentInvestigatingAlertID}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status, assigned_to: assignedTo }),
        });

        if (!res.ok) throw new Error('Update failed');
        showToast('Vaka durumu ve atama başarıyla kaydedildi', 'success');

        loadSIEMData();
    } catch (e) {
        showToast(`Durum güncellenemedi: ${e.message}`, 'error');
    }
}

async function addSIEMAlertNote() {
    if (!currentInvestigatingAlertID) return;

    const noteInput = document.getElementById('siem-inv-new-note');
    const noteText = noteInput.value.trim();
    if (!noteText) {
        showToast('Lütfen bir not metni giriniz', 'warning');
        return;
    }

    const author = window.currentUser ? window.currentUser.username : 'Analyst';

    try {
        const res = await fetch(`/api/v1/siem/alerts/${currentInvestigatingAlertID}/notes`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ author, note: noteText }),
        });

        if (!res.ok) throw new Error('Note failed');

        noteInput.value = '';
        showToast('Adli not eklendi', 'success');

        // Refresh notes in modal
        const alertRes = await fetch(`/api/v1/siem/alerts/${currentInvestigatingAlertID}`);
        if (alertRes.ok) {
            const data = await alertRes.json();
            renderSIEMNotes(data.notes || []);
        }
    } catch (e) {
        showToast(`Not eklenemedi: ${e.message}`, 'error');
    }
}

let allSIEMRules = [];

function renderFilteredSIEMRules() {
    const tbody = document.getElementById('siem-rules-body');
    const badge = document.getElementById('siem-rules-count-badge');
    const searchVal = (document.getElementById('siem-rules-search')?.value || '').toLowerCase().trim();
    const catVal = (document.getElementById('siem-rules-cat-filter')?.value || '').toLowerCase().trim();
    const priorityVal = (document.getElementById('siem-rules-priority-filter')?.value || '').trim();

    if (!tbody) return;

    let filtered = allSIEMRules.filter(rule => {
        if (catVal && (rule.category || '').toLowerCase() !== catVal) return false;
        if (priorityVal && (rule.priority || 'P1') !== priorityVal) return false;
        if (searchVal) {
            const matchId = (rule.id || '').toLowerCase().includes(searchVal);
            const matchName = (rule.name || '').toLowerCase().includes(searchVal);
            const matchDesc = (rule.description || '').toLowerCase().includes(searchVal);
            const matchTech = (rule.mitre_technique || '').toLowerCase().includes(searchVal);
            const matchTactic = (rule.mitre_tactic || '').toLowerCase().includes(searchVal);
            const matchSrc = (rule.source_ref || '').toLowerCase().includes(searchVal);
            if (!matchId && !matchName && !matchDesc && !matchTech && !matchTactic && !matchSrc) return false;
        }
        return true;
    });

    if (badge) {
        // Category-centric summary: count distinct curated catalog categories (MITRE-* dynamic rules excluded)
        const catSet = new Set(
            allSIEMRules
                .filter(r => !(r.id || '').startsWith('MITRE-'))
                .map(r => (r.category || '').toLowerCase())
                .filter(Boolean)
        );
        const shownCats = new Set(filtered.map(r => (r.category || '').toLowerCase()).filter(Boolean));
        const activeCount = filtered.filter(r => r.is_enabled).length;
        const isTR = !window.i18n || window.i18n.currentLang !== 'en';
        const catLabel = catVal ? `${shownCats.size} / ${catSet.size}` : `${catSet.size}`;
        badge.textContent = isTR
            ? `${catLabel} Kategori · ${activeCount}/${filtered.length} aktif kural`
            : `${catLabel} Categories · ${activeCount}/${filtered.length} active rules`;
        badge.title = isTR
            ? `Toplam ${allSIEMRules.length} kural`
            : `${allSIEMRules.length} rules total`;
    }

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center" style="padding: 24px; color: var(--text-muted);">Arama kriterlerine uygun kural bulunamadı.</td></tr>';
        return;
    }

    tbody.innerHTML = filtered.map(rule => {
        const prio = rule.priority || 'P1';
        const prioClass = prio === 'P1' ? 'badge-priority-p1' : 'badge-priority-p2';
        const sourceHtml = rule.source_ref 
            ? `<div style="margin-top: 4px;"><span class="badge-source-ref" title="${escapeHtml(rule.source_ref)}">📖 ${escapeHtml(rule.source_ref)}</span></div>` 
            : '';
        const catBadge = rule.category 
            ? `<span style="font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.7; margin-left: 6px;">[${escapeHtml(rule.category)}]</span>` 
            : '';

        return `
            <tr>
                <td><span class="mono-code" style="font-weight: 700; color: var(--primary);">${escapeHtml(rule.id)}</span></td>
                <td><span class="${prioClass}">${escapeHtml(prio)}</span></td>
                <td>
                    <div style="font-weight: 600; color: var(--text-main); display: flex; align-items: center;">
                        ${escapeHtml(rule.name)}
                        ${catBadge}
                    </div>
                    <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 2px;">${escapeHtml(rule.description || '')}</div>
                    ${sourceHtml}
                </td>
                <td>${getSeverityBadgeHTML(rule.severity)}</td>
                <td style="font-size: 12px;"><span class="badge badge-outline">${rule.threshold} ev / ${rule.timeframe_seconds}s</span></td>
                <td><span class="badge badge-mitre" title="${escapeHtml(rule.mitre_tactic)}">${escapeHtml(rule.mitre_technique || rule.mitre_tactic)}</span></td>
                <td style="text-align: center;">
                    <label class="switch">
                        <input type="checkbox" ${rule.is_enabled ? 'checked' : ''} onchange="toggleSIEMRule('${rule.id}', this.checked)">
                        <span class="slider"></span>
                    </label>
                </td>
            </tr>
        `;
    }).join('');
}

async function openSIEMRulesModal() {
    const modal = document.getElementById('siem-rules-modal');
    const tbody = document.getElementById('siem-rules-body');
    if (!modal || !tbody) return;

    modal.style.display = 'flex';
    tbody.innerHTML = '<tr><td colspan="7" class="text-center">Kurallar yükleniyor...</td></tr>';

    // Bind filter listeners once
    const searchInput = document.getElementById('siem-rules-search');
    const catSelect = document.getElementById('siem-rules-cat-filter');
    const prioSelect = document.getElementById('siem-rules-priority-filter');

    if (searchInput && !searchInput.dataset.bound) {
        searchInput.dataset.bound = 'true';
        searchInput.addEventListener('input', renderFilteredSIEMRules);
    }
    if (catSelect && !catSelect.dataset.bound) {
        catSelect.dataset.bound = 'true';
        catSelect.addEventListener('change', renderFilteredSIEMRules);
    }
    if (prioSelect && !prioSelect.dataset.bound) {
        prioSelect.dataset.bound = 'true';
        prioSelect.addEventListener('change', renderFilteredSIEMRules);
    }

    try {
        const res = await fetch('/api/v1/siem/rules');
        if (res.status === 401 || (res.redirected && res.url.includes('/login'))) {
            window.location.href = '/login';
            return;
        }
        if (!res.ok) throw new Error('API error');
        const data = await res.json();
        allSIEMRules = data.rules || [];

        renderFilteredSIEMRules();

    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-red">Hata: ${e.message}</td></tr>`;
    }
}

async function toggleSIEMRule(ruleID, enabled) {
    try {
        const res = await fetch(`/api/v1/siem/rules/${ruleID}/toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled }),
        });
        if (!res.ok) throw new Error('Toggle error');
        showToast(`Kural ${ruleID} ${enabled ? 'etkinleştirildi' : 'devre dışı bırakıldı'}`, 'info');
    } catch (e) {
        showToast(`Kural durumu güncellenemedi: ${e.message}`, 'error');
    }
}

async function runSIEMSimulation(scenario) {
    try {
        showToast(`Saldırı senaryosu başlatılıyor (${scenario})...`, 'info');
        const res = await fetch('/api/v1/siem/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario }),
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || 'Simulation failed');
        }

        document.getElementById('siem-simulate-modal').style.display = 'none';
        showToast('Saldırı simülasyonu korelasyon motorunda başarıyla tetiklendi!', 'success');

        // Automatically reload SIEM data after brief delay to capture new alert
        setTimeout(() => {
            loadSIEMData();
        }, 600);
    } catch (e) {
        showToast(`Simülasyon başarısız: ${e.message}`, 'error');
    }
}

function connectSIEMLiveStream() {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${window.location.host}/api/v1/siem/live${tenantQuerySuffix()}`;

    try {
        siemLiveSocket = new WebSocket(wsUrl);

        siemLiveSocket.onmessage = (event) => {
            try {
                const alert = JSON.parse(event.data);
                handleLiveIncomingAlert(alert);
            } catch (err) {
                console.error('Error parsing live SIEM alert:', err);
            }
        };

        siemLiveSocket.onclose = () => {
            // Reconnect after 5 seconds
            setTimeout(connectSIEMLiveStream, 5000);
        };
    } catch (e) {
        console.warn('SIEM WebSocket connection failed:', e);
    }
}

function handleLiveIncomingAlert(alert) {
    // Blocked toast alert bubble pop-up inside app window per user requirement.
    // Instead, register alert in the header Security Alerts notification center:
    if (typeof addAlertToNotificationCenter === 'function') {
        addAlertToNotificationCenter(alert);
    }

    // Refresh overview & counters
    loadSIEMOverview();

    // If currently on SIEM tab, refresh alerts table
    const activeTab = document.querySelector('.nav-item.active')?.getAttribute('data-tab');
    if (activeTab === 'siem') {
        loadSIEMAlerts();
    }
}

// ─── MITRE ATT&CK Matrix ──────────────────────────────────────────────────────
// The backend keeps the official STIX catalog persisted in PostgreSQL and a
// release watcher (conditional ETag GET, default every 24h) activates new
// ATT&CK versions automatically. The UI renders the cached report client-side
// so filtering/searching ~700 techniques doesn't hit the server.
const mitreUIState = { report: null, filter: 'all', search: '', showSub: true, wired: false };

function mitreFmtTime(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    if (isNaN(d.getTime()) || d.getFullYear() < 2000) return '—';
    return d.toLocaleString();
}

function wireSIEMMitreControls() {
    if (mitreUIState.wired) return;
    mitreUIState.wired = true;

    document.querySelectorAll('.mitre-filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            mitreUIState.filter = btn.getAttribute('data-filter') || 'all';
            document.querySelectorAll('.mitre-filter-btn').forEach(b => {
                b.classList.toggle('btn-primary', b === btn);
                b.classList.toggle('btn-outline', b !== btn);
            });
            renderSIEMMitreMatrix();
        });
    });

    const search = document.getElementById('mitre-search-input');
    if (search) {
        let t = null;
        search.addEventListener('input', () => {
            clearTimeout(t);
            t = setTimeout(() => {
                mitreUIState.search = search.value.trim().toLowerCase();
                renderSIEMMitreMatrix();
            }, 180);
        });
    }

    const sub = document.getElementById('mitre-show-subtechniques');
    if (sub) {
        sub.addEventListener('change', () => {
            mitreUIState.showSub = sub.checked;
            renderSIEMMitreMatrix();
        });
    }

    const toggle = document.getElementById('mitre-autosync-toggle');
    if (toggle) {
        toggle.addEventListener('change', async () => {
            toggle.disabled = true;
            try {
                const res = await fetch('/api/v1/siem/mitre/autosync', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled: toggle.checked }),
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Request failed');
                renderSIEMMitreAutoSync(data.status);
                showToast(toggle.checked
                    ? 'Yeni MITRE ATT&CK sürümleri otomatik etkinleştirilecek'
                    : 'Otomatik MITRE ATT&CK güncellemesi kapatıldı', 'success');
            } catch (e) {
                toggle.checked = !toggle.checked;
                showToast(`Hata: ${e.message}`, 'error');
            } finally {
                toggle.disabled = false;
            }
        });
    }

    const btnCheck = document.getElementById('btn-check-mitre-release');
    if (btnCheck) btnCheck.addEventListener('click', checkSIEMMitreRelease);

    const btnInstallAll = document.getElementById('btn-install-all-mitre');
    if (btnInstallAll) btnInstallAll.addEventListener('click', installAllSIEMMitre);

    const btnOpt = document.getElementById('btn-optimize-device-rules');
    if (btnOpt) btnOpt.addEventListener('click', optimizeSIEMDeviceRules);

    const btnEnableAll = document.getElementById('btn-enable-all-mitre');
    if (btnEnableAll) btnEnableAll.addEventListener('click', () => toggleAllSIEMMitre(true));

    const btnDisableAll = document.getElementById('btn-disable-all-mitre');
    if (btnDisableAll) btnDisableAll.addEventListener('click', () => toggleAllSIEMMitre(false));
}

async function openSIEMMitreModal() {
    const modal = document.getElementById('siem-mitre-modal');
    if (!modal) return;
    modal.style.display = 'flex';
    wireSIEMMitreControls();
    loadSIEMMitreMatrix();
}

function renderSIEMMitreAutoSync(st) {
    const toggle = document.getElementById('mitre-autosync-toggle');
    const el = document.getElementById('mitre-autosync-status');
    if (!st) return;
    if (toggle) toggle.checked = !!st.enabled;
    if (!el) return;

    const parts = [];
    if (st.enabled) {
        parts.push(`Every ${st.interval_hours || 24}h`);
        parts.push(`Next check: ${mitreFmtTime(st.next_check)}`);
    } else {
        parts.push('Watcher disabled');
    }
    parts.push(`Last check: ${mitreFmtTime(st.last_check)}`);
    if (st.last_result) parts.push(st.last_result);
    parts.push(st.persisted ? '💾 Persisted' : '⚠ Not persisted');

    el.innerHTML = escapeHtml(parts.join(' • '));
    if (st.last_error) {
        el.innerHTML += ` • <span class="text-red">${escapeHtml(st.last_error)}</span>`;
    }
}

async function loadSIEMMitreMatrix() {
    const container = document.getElementById('mitre-matrix-container');
    const versionLabel = document.getElementById('mitre-matrix-version-label');
    if (!container) return;

    try {
        const res = await fetch('/api/v1/siem/mitre');
        if (res.status === 401 || (res.redirected && res.url.includes('/login'))) {
            window.location.href = '/login';
            return;
        }
        if (!res.ok) throw new Error('Failed loading MITRE ATT&CK report');
        const report = await res.json();
        mitreUIState.report = report;

        // Stats
        const total = report.total_techniques || 0;
        const elTactics = document.getElementById('mitre-stat-tactics');
        if (elTactics) elTactics.textContent = report.total_tactics || (report.tactics || []).length;

        const elTechs = document.getElementById('mitre-stat-techniques');
        if (elTechs) elTechs.textContent = total.toLocaleString();
        const elTechsSub = elTechs?.parentElement?.querySelector('.stat-sub');
        if (elTechsSub && (report.total_parent_techniques || report.total_sub_techniques)) {
            elTechsSub.textContent = `${report.total_parent_techniques || 0} techniques • ${report.total_sub_techniques || 0} sub-techniques`;
        }

        const elCovered = document.getElementById('mitre-stat-covered');
        if (elCovered) elCovered.textContent = (report.covered_techniques || 0).toLocaleString();

        const elCovPct = document.getElementById('mitre-stat-coverage-pct');
        if (elCovPct && total > 0) {
            const pct = ((report.covered_techniques / total) * 100).toFixed(1);
            elCovPct.textContent = `${pct}% Active Detection Coverage`;
        }

        const elAlerts = document.getElementById('mitre-stat-alerts');
        if (elAlerts) elAlerts.textContent = (report.total_alerts_mapped || 0).toLocaleString();

        if (versionLabel) {
            const ver = report.attack_version || report.version || 'Enterprise ATT&CK';
            const src = report.is_baseline ? 'Embedded baseline (not yet synced)' : (report.source || 'Official Feed');
            let txt = `${ver} • ${src} • Updated ${mitreFmtTime(report.last_updated)}`;
            if (report.previous_version && report.previous_version !== ver) txt += ` • previous: ${report.previous_version}`;
            versionLabel.textContent = txt;
        }

        // New release banner
        const banner = document.getElementById('mitre-new-release-banner');
        if (banner) {
            if ((report.new_techniques || 0) > 0) {
                const ids = (report.new_technique_ids || []).slice(0, 12).map(id => `<span class="mono-code">${escapeHtml(id)}</span>`).join(', ');
                const more = (report.new_technique_ids || []).length > 12 ? ` +${report.new_technique_ids.length - 12} more` : '';
                banner.innerHTML = `✨ <strong>${escapeHtml(report.attack_version || 'New ATT&CK release')}</strong> activated` +
                    (report.previous_version ? ` (from ${escapeHtml(report.previous_version)})` : '') +
                    ` — <strong>${report.new_techniques}</strong> new technique(s) added to the matrix: ${ids}${more}. ` +
                    `<a href="#" id="mitre-banner-show-new" style="color: var(--primary);">Show them</a>`;
                banner.style.display = 'block';
                const link = document.getElementById('mitre-banner-show-new');
                if (link) link.addEventListener('click', ev => {
                    ev.preventDefault();
                    document.querySelector('.mitre-filter-btn[data-filter="new"]')?.click();
                });
            } else if (report.is_baseline) {
                banner.innerHTML = 'ℹ️ Only the embedded baseline is loaded. The full official catalog will be fetched automatically ' +
                    'shortly after startup, or click <strong>Sync Official Feed</strong> now.';
                banner.style.display = 'block';
            } else {
                banner.style.display = 'none';
            }
        }

        renderSIEMMitreAutoSync(report.auto_sync);
        renderSIEMMitreMatrix();
    } catch (e) {
        container.innerHTML = `<div class="text-center text-red" style="padding: 20px;">Hata: ${escapeHtml(e.message)}</div>`;
    }
}

function mitreTechMatches(tech) {
    const st = mitreUIState;
    if (!st.showSub && tech.sub_technique_of) return false;
    switch (st.filter) {
        case 'covered': if (!tech.covered) return false; break;
        case 'uncovered': if (tech.covered) return false; break;
        case 'alerts': if (!(tech.alert_count > 0)) return false; break;
        case 'new': if (!tech.is_new) return false; break;
    }
    if (st.search) {
        const hay = `${tech.id} ${tech.name} ${(tech.rule_ids || []).join(' ')} ${(tech.rule_names || []).join(' ')}`.toLowerCase();
        if (!hay.includes(st.search)) return false;
    }
    return true;
}

function renderSIEMMitreMatrix() {
    const container = document.getElementById('mitre-matrix-container');
    const report = mitreUIState.report;
    if (!container || !report) return;

    const tactics = report.tactics || [];
    if (tactics.length === 0) {
        container.innerHTML = '<div class="text-center text-muted" style="padding: 20px;">No tactics found.</div>';
        return;
    }

    const narrowing = mitreUIState.filter !== 'all' || !!mitreUIState.search;
    let shown = 0;

    const html = tactics.map(tac => {
        const techs = (tac.techniques || []).filter(mitreTechMatches);
        if (narrowing && techs.length === 0) return '';
        shown += techs.length;

        const covPct = (tac.coverage_percent || 0).toFixed(0);
        const newCount = (tac.techniques || []).filter(t => t.is_new).length;
        const alertCount = (tac.techniques || []).reduce((s, t) => s + (t.alert_count || 0), 0);
        const open = narrowing || tac.covered_techniques > 0 || newCount > 0;

        return `
            <details class="panel" ${open ? 'open' : ''} style="margin-bottom: 0; background: var(--bg-card); border: 1px solid ${tac.covered_techniques > 0 ? 'rgba(16, 185, 129, 0.35)' : 'var(--border-color)'}; border-radius: 8px; overflow: hidden;">
                <summary style="display: flex; justify-content: space-between; align-items: center; gap: 8px; padding: 10px 14px; background: rgba(255,255,255,0.02); cursor: pointer; list-style: none;">
                    <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                        <span class="mono-code" style="font-weight: 700; color: var(--primary); font-size: 11px;">${escapeHtml(tac.id)}</span>
                        <span style="font-weight: 600; font-size: 13.5px; color: var(--text-main);">${escapeHtml(tac.name)}</span>
                        <span style="font-size: 11px; color: var(--text-muted);">(${tac.covered_techniques}/${tac.total_techniques} covered${narrowing ? ` • ${techs.length} shown` : ''})</span>
                        ${newCount > 0 ? `<span class="badge" style="font-size: 9.5px; background: rgba(139, 92, 246, 0.2); color: #c4b5fd; border: 1px solid rgba(139, 92, 246, 0.5);">${newCount} NEW</span>` : ''}
                        ${alertCount > 0 ? `<span class="badge badge-danger" style="font-size: 9.5px;">${alertCount.toLocaleString()} alerts</span>` : ''}
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span class="badge ${tac.covered_techniques > 0 ? 'badge-success' : 'badge-outline'}" style="font-size: 10.5px;">${covPct}% Coverage</span>
                        <a href="${escapeHtml(tac.url || '#')}" target="_blank" rel="noopener" onclick="event.stopPropagation()" style="font-size: 11px; color: var(--primary); text-decoration: none;" title="Open in MITRE ATT&CK Knowledgebase">MITRE ↗</a>
                    </div>
                </summary>
                <div class="panel-body" style="padding: 12px 14px; border-top: 1px solid var(--border-color);">
                    <div style="font-size: 11.5px; color: var(--text-muted); margin-bottom: 10px;">${escapeHtml(tac.description || '')}</div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 8px;">
                        ${techs.map(renderSIEMMitreTechnique).join('') || '<div class="text-muted" style="font-size: 11.5px;">No techniques match.</div>'}
                    </div>
                </div>
            </details>
        `;
    }).join('');

    container.innerHTML = html || `<div class="text-center text-muted" style="padding: 20px;">No techniques match the current filter.</div>`;
    if (narrowing) {
        container.insertAdjacentHTML('afterbegin', `<div style="font-size: 11.5px; color: var(--text-muted);">${shown.toLocaleString()} technique placement(s) match.</div>`);
    }
}

function renderSIEMMitreTechnique(tech) {
    const isCovered = tech.covered;
    const isSub = !!tech.sub_technique_of;
    const ruleBadges = (tech.rule_ids || []).map((r, i) =>
        `<span class="badge badge-secondary" style="font-size: 9.5px; padding: 2px 4px;" title="${escapeHtml((tech.rule_names || [])[i] || '')}">${escapeHtml(r)}</span>`
    ).join(' ');
    const bg = isCovered ? 'rgba(16, 185, 129, 0.09)' : (tech.is_new ? 'rgba(139, 92, 246, 0.07)' : 'var(--bg-main)');
    const border = isCovered ? 'rgba(16, 185, 129, 0.4)' : (tech.is_new ? 'rgba(139, 92, 246, 0.4)' : 'var(--border-color)');
    const lastSeen = tech.last_seen_alert ? ` • last ${mitreFmtTime(tech.last_seen_alert)}` : '';

    return `
        <div class="mitre-tech-card" id="mitre-card-${escapeHtml(tech.id)}" 
             onclick="toggleSIEMMitreTechnique('${escapeHtml(tech.id)}', ${!isCovered}, event)"
             style="padding: 9px 11px; ${isSub ? 'margin-left: 10px; border-left-width: 3px;' : ''} background: ${bg}; border: 1px solid ${border}; border-radius: 6px; display: flex; flex-direction: column; gap: 5px; cursor: pointer; transition: all 0.2s ease; position: relative;"
             title="Click to ${isCovered ? 'disable' : 'enable'} this detection rule">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 6px;">
                <div style="flex: 1; min-width: 0;">
                    <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
                        <span class="mono-code" style="font-size: 11px; font-weight: 700; color: ${isCovered ? '#34d399' : 'var(--primary)'};">${escapeHtml(tech.id)}</span>
                        <span style="font-size: ${isSub ? '11.5px' : '12px'}; font-weight: 600; color: ${isCovered ? 'var(--text-main)' : 'var(--text-muted)'};" title="${escapeHtml(tech.description || '')}">
                            ${escapeHtml(tech.name)}
                        </span>
                    </div>
                </div>
                <div style="display: flex; gap: 4px; align-items: center; flex-shrink: 0;" onclick="event.stopPropagation()">
                    ${tech.is_new ? '<span class="badge" style="font-size: 9px; background: rgba(139, 92, 246, 0.25); color: #c4b5fd; border: 1px solid rgba(139, 92, 246, 0.5);">NEW</span>' : ''}
                    <button class="btn ${isCovered ? 'btn-success' : 'btn-outline'} mitre-toggle-pill" 
                            id="mitre-btn-${escapeHtml(tech.id)}"
                            onclick="toggleSIEMMitreTechnique('${escapeHtml(tech.id)}', ${!isCovered}, event)"
                            style="padding: 2px 7px; font-size: 10px; font-weight: 600; border-radius: 12px; cursor: pointer; transition: all 0.15s ease; ${isCovered ? 'background: #059669; border-color: #059669;' : 'opacity: 0.75;'}"
                            title="${isCovered ? 'Rule Active — Click to Disable' : 'Rule Inactive — Click to Enable'}">
                        ${isCovered ? '✓ Active' : '○ Enable'}
                    </button>
                    <a href="${escapeHtml(tech.url || '#')}" target="_blank" rel="noopener" style="font-size: 11px; color: var(--text-muted); padding: 0 2px; text-decoration: none;" title="Open in MITRE ATT&CK Website">↗</a>
                </div>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 2px; gap: 6px; font-size: 10.5px;">
                <div style="display: flex; gap: 4px; flex-wrap: wrap;">${ruleBadges || '<span style="font-size: 10px; color: var(--text-muted); font-style: italic;">Auto-managed</span>'}</div>
                ${tech.alert_count > 0 ? `<span class="badge badge-danger" style="font-size: 9.5px;" title="${escapeHtml(lastSeen)}">${tech.alert_count.toLocaleString()} alerts</span>` : ''}
            </div>
        </div>
    `;
}

window.toggleSIEMMitreTechnique = async (techId, enable, event) => {
    if (event) event.stopPropagation();
    
    const btn = document.getElementById(`mitre-btn-${techId}`);
    if (btn) {
        btn.disabled = true;
        btn.textContent = '…';
    }

    try {
        const res = await fetch('/api/v1/siem/mitre/toggle-technique', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ technique_id: techId, enabled: enable })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed toggling technique');

        // Smoothly update local state without harsh reload
        if (mitreUIState.report && mitreUIState.report.tactics) {
            mitreUIState.report.tactics.forEach(tac => {
                (tac.techniques || []).forEach(t => {
                    if (t.id === techId || (!techId.includes('.') && t.sub_technique_of === techId)) {
                        const was = t.covered;
                        t.covered = enable;
                        if (was !== enable) {
                            if (enable) tac.covered_techniques++;
                            else tac.covered_techniques = Math.max(0, tac.covered_techniques - 1);
                        }
                    }
                });
                if (tac.total_techniques > 0) {
                    tac.coverage_percent = (tac.covered_techniques / tac.total_techniques) * 100.0;
                }
            });

            const allTechs = mitreUIState.report.tactics.flatMap(t => t.techniques || []);
            const uniqueCovered = new Set(allTechs.filter(t => t.covered).map(t => t.id)).size;
            mitreUIState.report.covered_techniques = uniqueCovered;

            const elCovered = document.getElementById('mitre-stat-covered');
            if (elCovered) elCovered.textContent = uniqueCovered.toLocaleString();
            const elCovPct = document.getElementById('mitre-stat-coverage-pct');
            if (elCovPct && mitreUIState.report.total_techniques > 0) {
                const pct = ((uniqueCovered / mitreUIState.report.total_techniques) * 100).toFixed(1);
                elCovPct.textContent = `${pct}% Active Detection Coverage`;
            }
        }

        renderSIEMMitreMatrix();
        showToast(`Technique ${techId} ${enable ? 'activated & covered' : 'disabled'}`, 'success');
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
        renderSIEMMitreMatrix();
    }
};

window.installAllSIEMMitre = async () => {
    if (!confirm('This will install and enable SIEM correlation detection rules for all 697 MITRE ATT&CK techniques in the official catalog.\n\nProceed with installation?')) {
        return;
    }
    const btn = document.getElementById('btn-install-all-mitre');
    const alertBox = document.getElementById('mitre-sync-alert');
    if (btn) btn.disabled = true;
    if (alertBox) {
        alertBox.style.display = 'block';
        alertBox.className = 'alert-box alert-info';
        alertBox.textContent = '⚡ Installing detection rules for all MITRE ATT&CK techniques from official STIX feed…';
    }

    try {
        const res = await fetch('/api/v1/siem/mitre/install-all', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Install failed');

        if (alertBox) {
            alertBox.className = 'alert-box alert-success';
            alertBox.textContent = `✓ ${data.message || 'All MITRE ATT&CK techniques successfully installed!'}`;
        }
        showToast('Tüm MITRE ATT&CK teknikleri başarıyla kuruldu!', 'success');
        setTimeout(loadSIEMMitreMatrix, 400);
    } catch (e) {
        if (alertBox) {
            alertBox.className = 'alert-box alert-danger';
            alertBox.textContent = `✗ Hata: ${e.message}`;
        }
        showToast(`Kurulum hatası: ${e.message}`, 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
};

window.toggleAllSIEMMitre = async (enable) => {
    const action = enable ? 'enable' : 'disable';
    if (!confirm(`Are you sure you want to ${action} all MITRE ATT&CK detection rules across the matrix?`)) {
        return;
    }
    try {
        const res = await fetch('/api/v1/siem/mitre/toggle-all', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enable })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Bulk toggle failed');
        showToast(data.message || `All rules ${action}d!`, 'success');
        setTimeout(loadSIEMMitreMatrix, 300);
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
    }
};

async function syncSIEMMitreFeed() {
    const btn = document.getElementById('btn-sync-mitre-feed');
    const alertBox = document.getElementById('mitre-sync-alert');

    if (btn) btn.disabled = true;
    if (alertBox) {
        alertBox.style.display = 'block';
        alertBox.className = 'alert-box alert-info';
        alertBox.textContent = 'Downloading official MITRE Enterprise ATT&CK STIX 2.1 feed (~50 MB, GitHub)… this can take up to a minute.';
    }

    try {
        const res = await fetch('/api/v1/siem/mitre/sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Sync failed');

        if (alertBox) {
            alertBox.className = 'alert-box alert-success';
            alertBox.textContent = `✓ ${data.message || 'MITRE ATT&CK definitions synchronized successfully!'}`;
        }
        showToast('MITRE ATT&CK matrisi güncellendi!', 'success');
        setTimeout(loadSIEMMitreMatrix, 300);
    } catch (e) {
        if (alertBox) {
            alertBox.className = 'alert-box alert-danger';
            alertBox.textContent = `✗ Synchronization notice: ${e.message}. The previously persisted catalog stays active.`;
        }
        showToast(`Senkronizasyon uyarısı: ${e.message}`, 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function checkSIEMMitreRelease() {
    const btn = document.getElementById('btn-check-mitre-release');
    const alertBox = document.getElementById('mitre-sync-alert');
    if (btn) btn.disabled = true;
    if (alertBox) {
        alertBox.style.display = 'block';
        alertBox.className = 'alert-box alert-info';
        alertBox.textContent = 'Checking MITRE for a newer ATT&CK release…';
    }
    try {
        const res = await fetch('/api/v1/siem/mitre/autosync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ check_now: true }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Check failed');
        if (alertBox) {
            alertBox.className = 'alert-box alert-success';
            alertBox.textContent = `✓ ${data.message || 'Check complete'}`;
        }
        renderSIEMMitreAutoSync(data.status);
        setTimeout(loadSIEMMitreMatrix, 300);
    } catch (e) {
        if (alertBox) {
            alertBox.className = 'alert-box alert-danger';
            alertBox.textContent = `✗ ${e.message}`;
        }
    } finally {
        if (btn) btn.disabled = false;
    }
}

window.optimizeSIEMDeviceRules = async () => {
    const alertBox = document.getElementById('mitre-sync-alert');
    const btn = document.getElementById('btn-optimize-device-rules');
    const btnSoc = document.getElementById('btn-soc-optimize-devices');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span>⏳</span> <span>Optimizing...</span>';
    }
    if (btnSoc) {
        btnSoc.disabled = true;
        btnSoc.innerHTML = '<span>⏳</span> <span>Optimizing...</span>';
    }

    if (alertBox) {
        alertBox.style.display = 'block';
        alertBox.className = 'alert-box alert-info';
        alertBox.textContent = '🎯 Analyzing registered inventory devices and mapping optimal MITRE ATT&CK correlation rules…';
    }

    try {
        const res = await fetch('/api/v1/siem/mitre/optimize-devices', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Optimization failed');

        const vendors = (data.detected_vendors || []).join(', ') || 'Standard Infrastructure';
        const profilesList = (data.profiles || []).map(p => `• ${p}`).join('\n');
        const alertMsg = `✓ Inventory Device Rule Optimization Complete!\n\n` +
            `Discovered Devices: ${data.devices_count} (${vendors})\n\n` +
            `Active Protection Profiles:\n${profilesList}\n\n` +
            `Activated Threat Rules: ${data.activated_rules} of ${data.total_rules} rules live in SIEM correlation engine.`;

        if (alertBox) {
            alertBox.className = 'alert-box alert-success';
            alertBox.textContent = data.message || alertMsg;
        }

        alert(alertMsg);
        if (typeof showToast === 'function') {
            showToast(`Cihazlara göre optimize edildi: ${data.activated_rules} kural devrede!`, 'success');
        }

        if (typeof loadSIEMMitreMatrix === 'function') loadSIEMMitreMatrix();
        if (typeof loadSIEMRules === 'function') loadSIEMRules();
        if (typeof loadSIEMOverview === 'function') loadSIEMOverview();
    } catch (e) {
        if (alertBox) {
            alertBox.className = 'alert-box alert-danger';
            alertBox.textContent = `✗ Optimization Error: ${e.message}`;
        }
        alert('Optimization error: ' + e.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<span>🎯</span> <span data-i18n="btn_optimize_devices">Optimize for Devices</span>';
        }
        if (btnSoc) {
            btnSoc.disabled = false;
            btnSoc.innerHTML = '<span>🎯</span> <span data-i18n="btn_optimize_devices">Optimize Rules for Devices</span>';
        }
    }
};

/* ==============================================================================
   MULTI-TENANT & EDGE PROXY GOVERNANCE (MSSP & REMOTE ARCHITECTURE)
   ============================================================================== */

let currentTenants = [];
let currentTenantContext = localStorage.getItem('active_tenant_slug') || 'all';
let currentEdgeNodes = [];
let tenantSessionIsRoot = true;
let tenantTotals = null;

function updateSidebarBrandLogo(slug) {
    const logoImg = document.getElementById('sidebar-brand-logo');
    if (!logoImg) return;
    const targetSlug = (slug && slug !== 'all') ? slug : 'default';
    logoImg.src = `/api/v1/tenants/logo?slug=${encodeURIComponent(targetSlug)}&t=${Date.now()}`;
}

function setTenantContext(slug, { silent = false } = {}) {
    currentTenantContext = slug || 'all';
    localStorage.setItem('active_tenant_slug', currentTenantContext);
    const sel = document.getElementById('tenant-context-selector');
    if (sel && sel.value !== currentTenantContext) sel.value = currentTenantContext;
    renderTenantSidebarMeta();
    updateSidebarBrandLogo(currentTenantContext);
    if (!silent) refreshTenantScopedViews();
}

// Re-query every tenant-scoped view so the UI only shows the selected tenant's data
function refreshTenantScopedViews() {
    try { loadEdgeNodes(); } catch (e) { /* noop */ }
    if (typeof loadDevices === 'function') { try { loadDevices(); } catch (e) { /* noop */ } }
    if (typeof loadUnregisteredSources === 'function') { try { loadUnregisteredSources(); } catch (e) { /* noop */ } }
    if (typeof loadArchives === 'function') { try { loadArchives(); } catch (e) { /* noop */ } }
    // Dashboard counters: reset EPS baseline and poll immediately
    lastPacketCount = 0;
    fetch('/api/v1/dashboard').then(r => r.ok ? r.json() : null).then(data => {
        if (!data) return;
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
        set('stat-logs-today', Number(data.logs_today || 0).toLocaleString());
        set('stat-total-inserted', Number(data.total_inserted || 0).toLocaleString());
        set('stat-active-devices', data.active_devices || 0);
        set('stat-total-devices', `${data.total_devices || 0} registered assets`);
        set('stat-unknown-sources', data.unknown_sources || 0);
        if (data.tenant_scope) set('current-eps', `${Math.round(data.tenant_eps || 0).toLocaleString()} EPS`);
    }).catch(() => {});
    // Live stream: reconnect with the new ?tenant= (onclose handler reconnects automatically)
    if (liveSocket && liveSocket.readyState <= 1) {
        const container = document.getElementById('live-log-container');
        if (container) { container.innerHTML = ''; liveLogCount = 0; }
        try { liveSocket.close(); } catch (e) { /* noop */ }
    }
    // Log search: re-run if the search view is open
    const activeNav = document.querySelector('.nav-item.active');
    if (activeNav && activeNav.getAttribute('data-tab') === 'search') {
        document.getElementById('btn-search-exec')?.click();
    }
    // SIEM overview, alerts, MITRE matrix, and live alert websocket
    if (typeof loadSIEMOverview === 'function') { try { loadSIEMOverview(); } catch (e) { /* noop */ } }
    if (typeof loadSIEMAlerts === 'function') { try { loadSIEMAlerts(); } catch (e) { /* noop */ } }
    if (typeof loadSIEMMitreMatrix === 'function') { try { loadSIEMMitreMatrix(); } catch (e) { /* noop */ } }
    if (siemLiveSocket && siemLiveSocket.readyState <= 1) {
        try { siemLiveSocket.close(); } catch (e) { /* noop */ }
    }
    populateDeviceTenantSelect();
}

function renderTenantSidebarMeta() {
    const meta = document.getElementById('tenant-context-meta');
    if (!meta) return;
    const t = currentTenants.find(x => x.slug === currentTenantContext);
    const fmtEps = (v) => Math.round(v || 0).toLocaleString();
    if (!t) {
        const tot = tenantTotals || { nodes: 0, devices: 0, eps: 0 };
        meta.innerHTML = `<span class="tenant-meta-pill is-root">∞ Global</span>
            <span>${tot.nodes} node · ${tot.devices} cihaz · ${fmtEps(tot.eps)} EPS</span>`;
        return;
    }
    const unlimited = t.unlimited || t.slug === 'default';
    const nodeQuota = unlimited || !t.max_nodes ? '∞' : t.max_nodes;
    const epsQuota = unlimited || !t.max_eps ? '∞' : Number(t.max_eps).toLocaleString();
    meta.innerHTML = `<span class="tenant-meta-pill ${unlimited ? 'is-root' : ''}">${unlimited ? '∞ Root' : 'Kiracı'}</span>
        <span>${t.node_count || 0}/${nodeQuota} node · ${fmtEps(t.current_eps)}/${epsQuota} EPS</span>`;
}

function populateDeviceTenantSelect() {
    const sel = document.getElementById('dev-tenant');
    const group = document.getElementById('dev-tenant-group');
    if (!sel) return;
    if (!tenantSessionIsRoot) {
        if (group) group.style.display = 'none';
        sel.innerHTML = '';
        return;
    }
    if (group) group.style.display = '';
    const list = currentTenants.length ? currentTenants : [{ slug: 'default', name: 'Default Organization (Root)' }];
    sel.innerHTML = list.map(t => `<option value="${escapeHtml(t.slug)}">${escapeHtml(t.name)} (${escapeHtml(t.slug)})</option>`).join('');
    sel.value = (currentTenantContext && currentTenantContext !== 'all') ? currentTenantContext : 'default';
}

function initTenantManagement() {
    const sel = document.getElementById('tenant-context-selector');
    if (sel) {
        sel.addEventListener('change', (e) => {
            setTenantContext(e.target.value);
            if (typeof showToast === 'function') {
                const t = currentTenants.find(x => x.slug === currentTenantContext);
                showToast(`Kiracı bağlamı: ${t ? t.name : 'Tüm Kiracılar (Global)'}`, 'info');
            }
        });
    }
    loadTenants();
}

async function loadTenants() {
    const sel = document.getElementById('tenant-context-selector');
    const tbody = document.getElementById('tbody-tenants');

    try {
        const res = await fetch('/api/v1/tenants');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        currentTenants = data.tenants || [];
        tenantTotals = data.totals || null;
        tenantSessionIsRoot = data.is_root !== false;

        // Tenant users are locked to their own organization
        if (!tenantSessionIsRoot && data.current_tenant) {
            if (currentTenantContext !== data.current_tenant) setTenantContext(data.current_tenant);
        } else if (currentTenantContext !== 'all' && !currentTenants.some(t => t.slug === currentTenantContext)) {
            // Stale selection (tenant deleted) → fall back to global view
            setTenantContext('all');
        }

        // 1. Populate sidebar tenant context selector
        if (sel) {
            const allLabel = (window.i18n ? window.i18n.t('opt_all_tenants') : null) || '🌐 Tüm Kiracılar (Global Görünüm)';
            let options = tenantSessionIsRoot ? `<option value="all">${escapeHtml(allLabel)}</option>` : '';
            currentTenants.forEach(t => {
                const icon = t.slug === 'default' ? '👑' : '🏢';
                options += `<option value="${escapeHtml(t.slug)}">${icon} ${escapeHtml(t.name)}</option>`;
            });
            sel.innerHTML = options;
            sel.value = currentTenantContext;
            sel.disabled = !tenantSessionIsRoot;
            const wrap = document.getElementById('tenant-context-wrapper');
            if (wrap) wrap.classList.toggle('is-locked', !tenantSessionIsRoot);
        }
        renderTenantSidebarMeta();
        populateDeviceTenantSelect();
        const addTenantBtn = document.querySelector('[onclick="openAddTenantModal()"]');
        if (addTenantBtn) addTenantBtn.style.display = tenantSessionIsRoot ? '' : 'none';

        // 2. Populate Settings > Tenants table
        if (tbody) {
            if (currentTenants.length === 0) {
                tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 24px;">Henüz kiracı bulunmuyor.</td></tr>`;
                return;
            }

            let html = '';
            currentTenants.forEach(t => {
                const isDefault = (t.slug === 'default');
                const createdDate = t.created_at ? new Date(t.created_at).toLocaleDateString() : '-';
                const adminInfo = t.admin_name || t.admin_username
                    ? `<div><strong>${escapeHtml(t.admin_name || t.admin_username)}</strong> <span style="font-size: 0.72rem; color: var(--text-muted);">(@${escapeHtml(t.admin_username || '')})</span></div><div style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(t.admin_email || '')}</div>`
                    : `<span style="color: var(--text-muted); font-size: 0.78rem;">Sistem Yöneticisi</span>`;

                const statusBadge = (t.status === 'active')
                    ? `<span class="badge" style="background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34,197,94,0.3);">✓ Aktif</span>`
                    : `<span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245,158,11,0.3);">${escapeHtml(t.status)}</span>`;

                const unlimited = isDefault || t.unlimited;
                const nodeQuota = unlimited || !t.max_nodes ? '∞' : t.max_nodes;
                const epsQuota = unlimited || !t.max_eps ? '∞' : Number(t.max_eps).toLocaleString();
                const isExceeded = !!t.quota_exceeded;
                const isWarning = !unlimited && ((t.node_quota_percent && t.node_quota_percent >= 80) || (t.eps_quota_percent && t.eps_quota_percent >= 80) || (t.storage_quota_percent && t.storage_quota_percent >= 80));
                let quotaBadge = '';
                if (isExceeded) {
                    quotaBadge = `<span class="badge" style="background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); font-size: 0.7rem; margin-bottom: 3px; display: inline-block;">⚠️ Kota Aşıldı</span><br>`;
                } else if (isWarning) {
                    quotaBadge = `<span class="badge" style="background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); font-size: 0.7rem; margin-bottom: 3px; display: inline-block;">⚠️ %80+ Kota Kullanımı</span><br>`;
                }
                const limitsStr = `<div style="font-size: 0.78rem; line-height: 1.5;">
                        ${unlimited ? '<span class="tenant-meta-pill is-root" style="margin-bottom:3px;">∞ Sınırsız (Root)</span><br>' : quotaBadge}
                        Node: <strong>${t.node_count || 0}</strong> / ${nodeQuota}
                        &nbsp;|&nbsp; EPS: <strong>${Math.round(t.current_eps || 0).toLocaleString()}</strong> / ${epsQuota}
                        <div style="font-size: 0.7rem; color: var(--text-muted);">${t.device_count || 0} kayıtlı cihaz</div>
                    </div>`;

                // Retention & Storage
                const retentionDays = Number(t.retention_days || 0);
                const retentionBadge = retentionDays > 0
                    ? `<span class="badge" style="background: rgba(14, 165, 233, 0.15); color: #38bdf8; border: 1px solid rgba(14,165,233,0.3); font-size: 0.72rem;">🕒 ${retentionDays} Gün</span>`
                    : `<span class="badge" style="background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148,163,184,0.3); font-size: 0.72rem;">♾️ Süresiz</span>`;

                const storageGB = Number(t.storage_gb || 0).toFixed(2);
                const maxStorageGB = Number(t.max_storage_gb || 0);
                let storageBar = '';
                if (maxStorageGB > 0) {
                    const storagePct = Math.min(100, Math.round(t.storage_quota_percent || 0));
                    const barColor = (storagePct >= 90 || t.storage_exceeded) ? '#ef4444' : storagePct >= 75 ? '#f59e0b' : '#38bdf8';
                    const exceededWarn = t.storage_exceeded ? '<span style="color: #ef4444; font-weight: 600;">(Aşıldı!)</span> ' : '';
                    storageBar = `
                        <div style="font-size: 0.72rem; margin-top: 4px;">
                            ${exceededWarn}<strong>${storageGB} GB</strong> / ${maxStorageGB} GB (%${storagePct})
                        </div>
                        <div style="width: 100%; max-width: 130px; height: 5px; background: rgba(255,255,255,0.1); border-radius: 3px; overflow: hidden; margin-top: 2px;">
                            <div style="width: ${storagePct}%; height: 100%; background: ${barColor};"></div>
                        </div>`;
                } else {
                    storageBar = `<div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 4px;"><strong>${storageGB} GB</strong> (Sınırsız)</div>`;
                }

                const timeBounds = (t.oldest_log_time || t.newest_log_time)
                    ? `<div style="font-size: 0.68rem; color: var(--text-muted); margin-top: 3px;" title="İlk ve son log kayıt zamanları">
                        📅 ${(t.oldest_log_time || '').split(' ')[0]} ➔ ${(t.newest_log_time || '').split(' ')[0]}
                       </div>`
                    : '';

                const storageRetHtml = `<div>${retentionBadge}</div>${storageBar}${timeBounds}`;

                const policy = t.ingest_policy || 'permissive';
                const isStrict = (policy === 'strict');
                const policyBadge = isStrict
                    ? `<span class="badge" style="background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3);">🛡️ Beyaz Liste</span>`
                    : `<span class="badge" style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3);">⚡ Otomatik Keşif</span>`;
                const togglePolicyBtn = (!isDefault && tenantSessionIsRoot)
                    ? `<button class="btn btn-outline" style="padding: 2px 6px; font-size: 0.68rem; margin-top: 4px; display: inline-flex; align-items: center; gap: 3px;" onclick="toggleTenantPolicy('${escapeHtml(t.slug)}', '${policy}')" title="Giriş politikasını değiştir">🔄 ${isStrict ? 'Keşfe Aç' : 'Beyaz Liste Yap'}</button>`
                    : '';
                const policyHtml = `<div>${policyBadge}</div>${togglePolicyBtn}`;

                html += `
                    <tr>
                        <td><code style="background: rgba(0,0,0,0.3); padding: 3px 6px; border-radius: 4px; font-size: 0.8rem;">${escapeHtml(t.slug)}</code></td>
                        <td>
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <img src="/api/v1/tenants/logo?slug=${encodeURIComponent(t.slug)}" alt="${escapeHtml(t.name)}" style="width: 28px; height: 28px; object-fit: contain; border-radius: 4px; background: rgba(255,255,255,0.06); border: 1px solid var(--border-color); padding: 2px; flex-shrink: 0;" onerror="this.src='/static/images/logo.svg'">
                                <div>
                                    <div style="font-weight: 600; color: var(--text-main);">${escapeHtml(t.name)}</div>
                                    <div style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(t.description || '')}</div>
                                </div>
                            </div>
                        </td>
                        <td>${adminInfo}</td>
                        <td>${statusBadge}</td>
                        <td>${limitsStr}</td>
                        <td>${storageRetHtml}</td>
                        <td>${policyHtml}</td>
                        <td style="font-size: 0.8rem;">${createdDate}</td>
                        <td style="text-align: right;">
                            <div style="display: flex; justify-content: flex-end; gap: 6px;">
                                <button class="btn btn-outline" style="padding: 3px 8px; font-size: 0.75rem;" onclick="switchTenantContext('${escapeHtml(t.slug)}')">
                                    🔍 Seç
                                </button>
                                <button class="btn btn-outline" style="padding: 3px 8px; font-size: 0.75rem;" onclick="openUploadTenantLogoModal('${escapeHtml(t.slug)}', '${escapeHtml(t.name)}')" title="Marka Logosunu Düzenle / Yükle">
                                    🖼️ Logo
                                </button>
                                ${tenantSessionIsRoot ? `
                                <button class="btn btn-outline" style="padding: 3px 8px; font-size: 0.75rem;" onclick="openEditTenantQuotasModal('${escapeHtml(t.slug)}')" title="Limitleri ve Saklama Süresini Düzenle">
                                    ⚙️ Limitler
                                </button>` : ''}
                                ${!isDefault && tenantSessionIsRoot ? `
                                <button class="btn btn-outline text-danger" style="padding: 3px 8px; font-size: 0.75rem;" onclick="deleteTenant('${escapeHtml(t.slug)}', '${escapeHtml(t.name)}')" title="Kiracıyı Sil">
                                    🗑️
                                </button>` : ''}
                            </div>
                        </td>
                    </tr>`;
            });
            tbody.innerHTML = html;
        }
    } catch (err) {
        console.error('Failed loading tenants:', err);
    }
}

window.toggleTenantPolicy = async function(slug, currentPolicy) {
    const newPolicy = currentPolicy === 'strict' ? 'permissive' : 'strict';
    const policyLabel = newPolicy === 'strict' ? '🛡️ Beyaz Liste (Bilinmeyen trafik engellenir)' : '⚡ Otomatik Keşif (Bilinmeyen trafik tespit edilir)';
    if (!confirm(`'${slug}' kiracısının giriş politikasını '${policyLabel}' olarak değiştirmek istiyor musunuz?`)) return;

    try {
        const res = await fetch('/api/v1/tenants', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ slug: slug, ingest_policy: newPolicy })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);
        if (typeof showToast === 'function') {
            showToast(`✓ Giriş politikası güncellendi: ${slug} -> ${newPolicy}`, 'success');
        }
        loadTenants();
    } catch (err) {
        alert('Politika güncellenemedi: ' + err.message);
    }
};

function switchTenantContext(slug) {
    setTenantContext(slug);
    if (typeof showToast === 'function') {
        const t = currentTenants.find(x => x.slug === slug);
        showToast(`Kiracı bağlamına geçildi: ${t ? t.name : slug}`, 'success');
    }
}

function openAddTenantModal() {
    const modal = document.getElementById('modal-add-tenant');
    if (!modal) return;
    document.getElementById('tenant-new-slug').value = '';
    document.getElementById('tenant-new-name').value = '';
    document.getElementById('tenant-new-desc').value = '';
    document.getElementById('tenant-new-admin-name').value = '';
    document.getElementById('tenant-new-admin-email').value = '';
    document.getElementById('tenant-new-admin-username').value = '';
    document.getElementById('tenant-new-admin-pass').value = '';
    document.getElementById('tenant-new-max-nodes').value = '10';
    document.getElementById('tenant-new-max-eps').value = '5000';
    const retDays = document.getElementById('tenant-new-retention-days');
    if (retDays) retDays.value = '0';
    const maxStorage = document.getElementById('tenant-new-max-storage');
    if (maxStorage) maxStorage.value = '0';
    const policySel = document.getElementById('tenant-new-ingest-policy');
    if (policySel) policySel.value = 'permissive';
    modal.style.display = 'flex';
}

function closeAddTenantModal() {
    const modal = document.getElementById('modal-add-tenant');
    if (modal) modal.style.display = 'none';
}

async function submitAddTenant() {
    const slug = document.getElementById('tenant-new-slug').value.trim();
    const name = document.getElementById('tenant-new-name').value.trim();
    const desc = document.getElementById('tenant-new-desc').value.trim();
    const adminName = document.getElementById('tenant-new-admin-name').value.trim();
    const adminEmail = document.getElementById('tenant-new-admin-email').value.trim();
    const adminUsername = document.getElementById('tenant-new-admin-username').value.trim();
    const adminPass = document.getElementById('tenant-new-admin-pass').value.trim();
    const maxNodes = parseInt(document.getElementById('tenant-new-max-nodes').value, 10) || 0;
    const maxEps = parseInt(document.getElementById('tenant-new-max-eps').value, 10) || 0;
    const retentionDays = parseInt(document.getElementById('tenant-new-retention-days')?.value, 10) || 0;
    const maxStorage = parseInt(document.getElementById('tenant-new-max-storage')?.value, 10) || 0;
    const ingestPolicy = (document.getElementById('tenant-new-ingest-policy')?.value) || 'permissive';

    if (!name) {
        alert('Lütfen kiracı / müşteri adını girin!');
        return;
    }

    const btn = document.getElementById('btn-save-tenant');
    try {
        if (btn) { btn.disabled = true; btn.textContent = 'Oluşturuluyor...'; }

        const res = await fetch('/api/v1/tenants', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                slug: slug,
                name: name,
                description: desc,
                admin_name: adminName,
                admin_email: adminEmail,
                admin_username: adminUsername,
                admin_initial_pass: adminPass,
                max_nodes: maxNodes,
                max_eps: maxEps,
                retention_days: retentionDays,
                max_storage_gb: maxStorage,
                ingest_policy: ingestPolicy
            })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);

        if (typeof showToast === 'function') {
            showToast(`✓ Kiracı ve yönetici hesabı başarıyla oluşturuldu: ${name}`, 'success');
        }
        closeAddTenantModal();
        loadTenants();
    } catch (err) {
        alert('Kiracı oluşturulamadı: ' + err.message);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = '✓ Kiracıyı Oluştur'; }
    }
}

window.openEditTenantQuotasModal = function(slug) {
    const t = currentTenants.find(x => x.slug === slug);
    if (!t) return;
    const modal = document.getElementById('modal-edit-tenant-quotas');
    if (!modal) return;
    document.getElementById('tenant-edit-slug').value = t.slug;
    const nameEl = document.getElementById('modal-edit-quotas-tenant-name');
    if (nameEl) nameEl.textContent = `${t.name} (${t.slug})`;
    document.getElementById('tenant-edit-max-nodes').value = t.max_nodes || 0;
    document.getElementById('tenant-edit-max-eps').value = t.max_eps || 0;
    document.getElementById('tenant-edit-retention-days').value = t.retention_days || 0;
    document.getElementById('tenant-edit-max-storage').value = t.max_storage_gb || 0;
    const policySel = document.getElementById('tenant-edit-ingest-policy');
    if (policySel) policySel.value = t.ingest_policy || 'permissive';
    modal.style.display = 'flex';
};

window.closeEditTenantQuotasModal = function() {
    const modal = document.getElementById('modal-edit-tenant-quotas');
    if (modal) modal.style.display = 'none';
};

window.submitEditTenantQuotas = async function() {
    const slug = document.getElementById('tenant-edit-slug').value.trim();
    if (!slug) return;
    const maxNodes = parseInt(document.getElementById('tenant-edit-max-nodes').value, 10) || 0;
    const maxEps = parseInt(document.getElementById('tenant-edit-max-eps').value, 10) || 0;
    const retentionDays = parseInt(document.getElementById('tenant-edit-retention-days').value, 10) || 0;
    const maxStorageGB = parseInt(document.getElementById('tenant-edit-max-storage').value, 10) || 0;
    const ingestPolicy = document.getElementById('tenant-edit-ingest-policy')?.value || 'permissive';

    const btn = document.getElementById('btn-save-tenant-quotas');
    try {
        if (btn) { btn.disabled = true; btn.textContent = 'Kaydediliyor...'; }
        const res = await fetch('/api/v1/tenants', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                slug: slug,
                max_nodes: maxNodes,
                max_eps: maxEps,
                retention_days: retentionDays,
                max_storage_gb: maxStorageGB,
                ingest_policy: ingestPolicy
            })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);
        if (typeof showToast === 'function') {
            showToast(`✓ Kiracı limitleri ve saklama süresi güncellendi: ${slug}`, 'success');
        }
        closeEditTenantQuotasModal();
        loadTenants();
    } catch (err) {
        alert('Limitler güncellenemedi: ' + err.message);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = '✓ Limitleri Kaydet'; }
    }
};

window.triggerSingleTenantPrune = async function() {
    const slug = document.getElementById('tenant-edit-slug').value.trim();
    if (!slug) return;
    if (!confirm(`'${slug}' kiracısının saklama süresi dolan kayıtları ve aşan depolama kotalarını şimdi temizlemek istiyor musunuz?`)) return;

    try {
        const res = await fetch('/api/v1/tenants/prune', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant: slug, drop_partitions: true })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);
        if (typeof showToast === 'function') {
            showToast(`✓ '${slug}' için temizleme işlemi tamamlandı`, 'success');
        }
        closeEditTenantQuotasModal();
        loadTenants();
    } catch (err) {
        alert('Temizleme işlemi başarısız: ' + err.message);
    }
};

window.triggerTenantPrune = async function() {
    if (!confirm('Tüm kiracıların saklama süresi dolan kayıtları ve aşan depolama kotaları taranıp temizlenecek. Devam etmek istiyor musunuz?')) return;

    const btn = document.getElementById('btn-trigger-retention-prune');
    try {
        if (btn) { btn.disabled = true; btn.innerHTML = '🧹 Temizleniyor...'; }
        const res = await fetch('/api/v1/tenants/prune', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ drop_partitions: true })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);
        if (typeof showToast === 'function') {
            showToast(`✓ Saklama ve kota temizleme tamamlandı (${data.tenants_evaluated || 0} kiracı tarandı)`, 'success');
        }
        loadTenants();
    } catch (err) {
        alert('Temizleme başarısız: ' + err.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="14" height="14" style="vertical-align: middle;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg> <span data-i18n="btn_prune_retention">Kotaları &amp; Saklamayı Temizle</span>`;
        }
    }
};

async function deleteTenant(slug, name) {
    if (!confirm(`'${name}' (${slug}) kiracısını ve ilişkili verileri silmek istediğinize emin misiniz?`)) return;

    try {
        const res = await fetch(`/api/v1/tenants?slug=${encodeURIComponent(slug)}`, {
            method: 'DELETE'
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);

        if (typeof showToast === 'function') {
            showToast(`Kiracı silindi: ${name}`, 'info');
        }
        if (currentTenantContext === slug) {
            switchTenantContext('all');
        }
        loadTenants();
    } catch (err) {
        alert('Kiracı silinemedi: ' + err.message);
    }
}

/* ==============================================================================
   EDGE PROXY NODES (ADMIN & CLOUD PRECONFIGURATION)
   ============================================================================== */

async function loadEdgeNodes() {
    const tbody = document.getElementById('tbody-edge-nodes');
    if (!tbody) return;
    const t = (k, fb) => (window.i18n ? window.i18n.t(k) : (fb || k));

    try {
        let url = '/api/v1/settings/edge/nodes';
        if (currentTenantContext && currentTenantContext !== 'all') {
            url += `?tenant=${encodeURIComponent(currentTenantContext)}`;
        }

        const res = await fetch(url);
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        currentEdgeNodes = data.nodes || [];

        if (currentEdgeNodes.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" style="text-align: center; color: var(--text-muted); padding: 32px 16px;">
                        <div style="font-size: 28px; margin-bottom: 8px;">🌐</div>
                        <div style="font-weight: 600; margin-bottom: 4px;">${t('edge_empty_title', 'Seçili bağlamda kayıtlı Edge Proxy düğümü bulunmuyor.')}</div>
                        <div style="font-size: 0.82rem; margin-bottom: 12px;">${t('edge_empty_desc', 'Uzak ofis veya müşteri ağlarınızdan güvenli log aktarımı için yeni bir düğüm ekleyin.')}</div>
                        <button class="btn btn-primary" onclick="openAddEdgeNodeModal()">${t('btn_add_edge_node', '+ Yeni Proxy Düğümü Ekle')}</button>
                    </td>
                </tr>`;
            return;
        }

        const intervals = [
            { id: 'online', label: t('opt_sync_online', 'online (Anlık / Gerçek Zamanlı)') },
            { id: 'every 60 second', label: t('opt_sync_60s', 'every 60 second (60 saniyede bir)') },
            { id: 'every 5 min', label: t('opt_sync_5m', 'every 5 min (5 dakikada bir)') },
            { id: 'every 15 min', label: t('opt_sync_15m', 'every 15 min (15 dakikada bir)') },
            { id: 'every 30 min', label: t('opt_sync_30m', 'every 30 min (30 dakikada bir)') },
            { id: 'every hour', label: t('opt_sync_1h', 'every hour (Her saat başı)') }
        ];

        let html = '';
        currentEdgeNodes.forEach(n => {
            const isOnline = (n.status === 'online');
            const isDegraded = (n.status === 'degraded');
            const isPending = (n.status === 'pending');
            const statusBadge = isOnline
                ? `<span class="badge" style="background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34,197,94,0.3); font-weight: 600;">${t('status_online', '● Online')}</span>`
                : (isDegraded
                    ? `<span class="badge" style="background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245,158,11,0.4); font-weight: 600;">${t('status_degraded', '⚠️ Gecikmeli')}</span>`
                    : (isPending
                        ? `<span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245,158,11,0.3);">${t('status_pending', '⏳ Bekliyor')}</span>`
                        : `<span class="badge" style="background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.3);">${t('status_offline', '○ Çevrimdışı')}</span>`));

            const isActPending = (n.activation_status === 'pending_activation');
            const actBadge = isActPending
                ? `<div style="margin-top: 4px;"><span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245,158,11,0.3); font-size: 0.72rem;">${t('act_pending_badge', '⏳ Etkinleştirme Bekliyor')}</span></div>`
                : `<div style="margin-top: 4px;"><span class="badge" style="background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34,197,94,0.3); font-size: 0.72rem;">${t('act_active_badge', '✓ Aktif')}</span></div>`;

            let lastSeenStr = t('not_connected_yet', 'Henüz bağlanmadı');
            if (n.last_seen_at) {
                const diffMs = Date.now() - new Date(n.last_seen_at).getTime();
                const diffSec = Math.floor(diffMs / 1000);
                if (diffSec < 60) lastSeenStr = `${diffSec} ${t('ago_sec', 'sn önce')}`;
                else if (diffSec < 3600) lastSeenStr = `${Math.floor(diffSec / 60)} ${t('ago_min', 'dk önce')}`;
                else lastSeenStr = `${Math.floor(diffSec / 3600)} ${t('ago_hour', 'sa önce')}`;
            }
            if (n.last_ip) {
                lastSeenStr += ` <span style="color: var(--text-muted); font-size: 0.75rem;">(${escapeHtml(n.last_ip)})</span>`;
            }

            const currentInterval = n.sync_interval || 'online';
            let optionsHtml = '';
            intervals.forEach(opt => {
                const sel = (opt.id === currentInterval) ? 'selected' : '';
                optionsHtml += `<option value="${opt.id}" ${sel}>${opt.label}</option>`;
            });

            const tokenDisp = n.token_prefix || (n.token && n.token.length > 14
                ? `${n.token.substring(0, 10)}...${n.token.substring(n.token.length - 4)}`
                : (n.token || 'lp_edge_***'));

            let expiryBadge = `<span class="badge" style="background: rgba(148,163,184,0.1); color: #94a3b8; font-size: 0.7rem;">♾️ ${t('badge_key_never', 'Süresiz')}</span>`;
            if (n.key_expires_at) {
                const expDate = new Date(n.key_expires_at);
                const isExpired = expDate.getTime() < Date.now();
                if (isExpired) {
                    expiryBadge = `<span class="badge" style="background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.3); font-size: 0.7rem;">⚠️ ${t('badge_key_expired', 'Süresi Doldu')}: ${expDate.toLocaleDateString()}</span>`;
                } else {
                    expiryBadge = `<span class="badge" style="background: rgba(34,197,94,0.1); color: #4ade80; border: 1px solid rgba(34,197,94,0.2); font-size: 0.7rem;">⏳ ${t('badge_key_expires', 'Bitiş')}: ${expDate.toLocaleDateString()}</span>`;
                }
            }

            let cidrBadge = `<span class="badge" style="background: rgba(56,189,248,0.08); color: #38bdf8; font-size: 0.7rem;">🌐 ${t('filter_all', 'Tüm IP\'ler (*)')}</span>`;
            if (n.allowed_cidrs && n.allowed_cidrs.trim() !== '' && n.allowed_cidrs.trim() !== '*') {
                const cleanCidr = n.allowed_cidrs.trim();
                const shortCidr = cleanCidr.length > 16 ? cleanCidr.substring(0, 14) + '...' : cleanCidr;
                cidrBadge = `<span class="badge" style="background: rgba(168,85,247,0.15); color: #c084fc; border: 1px solid rgba(168,85,247,0.3); font-size: 0.7rem;" title="${escapeHtml(cleanCidr)}">🔒 ${escapeHtml(shortCidr)}</span>`;
            }

            const adminInfo = (n.admin_name || n.admin_username)
                ? `<div><strong>${escapeHtml(n.admin_name || n.admin_username)}</strong> <span style="font-size: 0.72rem; color: var(--text-muted);">(@${escapeHtml(n.admin_username || '')})</span></div><div style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(n.admin_email || '')}</div>`
                : `<span style="color: var(--text-muted); font-size: 0.75rem;">${t('unassigned', 'Atanmadı')}</span>`;

            html += `
                <tr>
                    <td>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span style="font-size: 1.1rem;">🖥️</span>
                            <div>
                                <div style="font-weight: 600; color: var(--text-main);">${escapeHtml(n.name)}</div>
                                <div style="font-size: 0.72rem; color: var(--text-muted);">v${escapeHtml(n.version || '1.6.5')}</div>
                            </div>
                        </div>
                    </td>
                    <td><span class="badge badge-outline" style="font-size: 0.78rem;">${escapeHtml(n.tenant_name || 'default')}</span></td>
                    <td>${adminInfo}</td>
                    <td>${statusBadge}${actBadge}</td>
                    <td>
                        <select class="input" style="padding: 4px 8px; font-size: 0.78rem; width: auto; font-weight: 500; border-color: rgba(56, 189, 248, 0.4);"
                                onchange="updateEdgeNodeInterval('${n.id}', this.value)">
                            ${optionsHtml}
                        </select>
                    </td>
                    <td style="font-size: 0.82rem;">${lastSeenStr}</td>
                    <td style="font-family: monospace; font-weight: 600; font-size: 0.85rem;">
                        ${(n.logs_forwarded || 0).toLocaleString()}
                    </td>
                    <td>
                        <div style="display: flex; flex-direction: column; gap: 4px;">
                            <div style="display: flex; align-items: center; gap: 6px;">
                                <code style="font-size: 0.75rem; background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">${escapeHtml(tokenDisp)}</code>
                                ${n.token ? `<button class="btn btn-outline" style="padding: 2px 6px; font-size: 0.72rem;" onclick="copyToClipboard('${n.token}', '${t('token_copied', 'Token panoya kopyalandı!')}')" title="Copy Token">📋</button>` : ''}
                            </div>
                            <div style="display: flex; gap: 4px; flex-wrap: wrap;">
                                ${expiryBadge}
                                ${cidrBadge}
                            </div>
                        </div>
                    </td>
                    <td style="text-align: right;">
                        <div style="display: flex; justify-content: flex-end; gap: 6px; flex-wrap: wrap;">
                            <button class="btn btn-outline" style="padding: 3px 8px; font-size: 0.75rem; color: #facc15; border-color: rgba(234,179,8,0.4);" onclick="openRotateEdgeKeyModal('${n.id}', '${escapeHtml(n.name)}')" title="${t('btn_rotate_key', 'Anahtarı Yenile')}">
                                🔑 ${t('btn_rotate_key', 'Anahtarı Yenile')}
                            </button>
                            ${isActPending ? `
                            <button class="btn btn-primary" style="padding: 3px 8px; font-size: 0.75rem;" onclick="openActivateEdgeNodeModal('${n.id}')" title="Activate &amp; Configure">
                                ${t('btn_activate', '⚡ Etkinleştir')}
                            </button>` : `
                            <button class="btn btn-outline" style="padding: 3px 8px; font-size: 0.75rem;" onclick="openActivateEdgeNodeModal('${n.id}')" title="Settings">
                                ${t('btn_settings', '⚙️ Ayarlar')}
                            </button>`}
                            <button class="btn btn-outline" style="padding: 3px 8px; font-size: 0.75rem;" onclick="copyNodeInstallCurl('${n.token || ''}', '${escapeHtml(n.name)}')" title="Install Command">
                                ${t('btn_install', '💻 Kurulum')}
                            </button>
                            <button class="btn btn-outline text-danger" style="padding: 3px 8px; font-size: 0.75rem;" onclick="deleteEdgeNode('${n.id}', '${escapeHtml(n.name)}')" title="Delete Node">
                                🗑️
                            </button>
                        </div>
                    </td>
                </tr>`;
        });

        tbody.innerHTML = html;
    } catch (err) {
        console.error('Failed loading edge nodes:', err);
        tbody.innerHTML = `<tr><td colspan="9" class="text-danger" style="text-align: center; padding: 16px;">Düğümler yüklenirken hata oluştu: ${escapeHtml(err.message)}</td></tr>`;
    }
}

async function updateEdgeNodeInterval(nodeId, newInterval) {
    try {
        const res = await fetch('/api/v1/settings/edge/nodes/interval', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: nodeId, sync_interval: newInterval })
        });
        if (!res.ok) {
            const data = await res.json();
            throw new Error(data.error || 'HTTP ' + res.status);
        }

        if (typeof showToast === 'function') {
            showToast(`✓ Gönderim zamanlaması bulutta güncellendi: ${newInterval}`, 'success');
        }
    } catch (err) {
        alert('Zamanlama güncellenemedi: ' + err.message);
        loadEdgeNodes();
    }
}

function openAddEdgeNodeModal() {
    const modal = document.getElementById('modal-add-edge-node');
    if (!modal) return;

    document.getElementById('edge-new-node-name').value = '';
    document.getElementById('edge-new-tenant-name').value = (currentTenantContext && currentTenantContext !== 'all') ? currentTenantContext : 'default';
    document.getElementById('edge-new-act-status').value = 'active';
    document.getElementById('edge-new-admin-name').value = '';
    document.getElementById('edge-new-admin-email').value = '';
    document.getElementById('edge-new-admin-username').value = '';
    document.getElementById('edge-new-admin-pass').value = '';
    document.getElementById('edge-new-sync-interval').value = 'online';
    if (document.getElementById('edge-new-allowed-cidrs')) document.getElementById('edge-new-allowed-cidrs').value = '';
    if (document.getElementById('edge-new-key-expiry')) document.getElementById('edge-new-key-expiry').value = '0';

    document.getElementById('edge-form-container').style.display = 'block';
    document.getElementById('edge-create-success-box').style.display = 'none';

    const saveBtn = document.getElementById('btn-save-edge-node');
    if (saveBtn) {
        saveBtn.style.display = 'inline-block';
        saveBtn.disabled = false;
        saveBtn.textContent = 'Oluştur ve Token Al';
    }

    modal.style.display = 'flex';
}

function closeAddEdgeNodeModal() {
    const modal = document.getElementById('modal-add-edge-node');
    if (modal) modal.style.display = 'none';
}

async function submitAddEdgeNode() {
    const nameInput = document.getElementById('edge-new-node-name');
    const tenantInput = document.getElementById('edge-new-tenant-name');
    const actStatusInput = document.getElementById('edge-new-act-status');
    const adminNameInput = document.getElementById('edge-new-admin-name');
    const adminEmailInput = document.getElementById('edge-new-admin-email');
    const adminUsernameInput = document.getElementById('edge-new-admin-username');
    const adminPassInput = document.getElementById('edge-new-admin-pass');
    const intervalInput = document.getElementById('edge-new-sync-interval');
    const cidrsInput = document.getElementById('edge-new-allowed-cidrs');
    const expiryInput = document.getElementById('edge-new-key-expiry');
    const saveBtn = document.getElementById('btn-save-edge-node');

    const name = nameInput.value.trim();
    if (!name) {
        alert('Lütfen düğüm için bir isim girin!');
        nameInput.focus();
        return;
    }

    const tenant = tenantInput.value.trim() || 'default';
    const actStatus = actStatusInput.value || 'active';
    const interval = intervalInput.value || 'online';
    const allowedCIDRs = cidrsInput ? cidrsInput.value.trim() : '';
    const expiresDays = expiryInput ? (parseInt(expiryInput.value, 10) || 0) : 0;

    try {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Oluşturuluyor...';

        const res = await fetch('/api/v1/settings/edge/nodes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: name,
                tenant_name: tenant,
                activation_status: actStatus,
                admin_name: adminNameInput.value.trim(),
                admin_email: adminEmailInput.value.trim(),
                admin_username: adminUsernameInput.value.trim(),
                admin_initial_pass: adminPassInput.value.trim(),
                sync_interval: interval,
                allowed_cidrs: allowedCIDRs,
                expires_days: expiresDays
            })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);

        // Display Success Box with generated token & 1-line curl command
        document.getElementById('edge-form-container').style.display = 'none';
        document.getElementById('edge-create-success-box').style.display = 'block';

        const token = data.token;
        document.getElementById('edge-result-token').value = token;

        const endpoint = window.location.origin;
        const installCmd = `curl -k -sSL ${endpoint}/api/v1/edge/install.sh | sudo bash -s -- --endpoint ${endpoint} --token ${token} --name "${data.name}"`;
        document.getElementById('edge-result-curl').value = installCmd;

        saveBtn.style.display = 'none';
        loadEdgeNodes();
    } catch (err) {
        alert('Düğüm oluşturulamadı: ' + err.message);
        saveBtn.disabled = false;
        saveBtn.textContent = 'Oluştur ve Token Al';
    }
}

function openActivateEdgeNodeModal(nodeId) {
    const node = currentEdgeNodes.find(n => n.id === nodeId);
    if (!node) {
        alert('Düğüm bulunamadı!');
        return;
    }

    const modal = document.getElementById('modal-activate-edge-node');
    if (!modal) return;

    document.getElementById('act-edge-node-id').value = node.id;
    document.getElementById('act-edge-node-name-disp').textContent = node.name || '-';
    document.getElementById('act-edge-tenant-disp').textContent = node.tenant_name || 'default';

    document.getElementById('act-edge-admin-name').value = node.admin_name || '';
    document.getElementById('act-edge-admin-email').value = node.admin_email || '';
    document.getElementById('act-edge-admin-username').value = node.admin_username || '';
    document.getElementById('act-edge-admin-pass').value = node.admin_initial_pass || '';
    document.getElementById('act-edge-sync-interval').value = node.sync_interval || 'online';
    if (document.getElementById('act-edge-allowed-cidrs')) {
        document.getElementById('act-edge-allowed-cidrs').value = node.allowed_cidrs || '';
    }

    const ldap = node.ldap_config || {};
    document.getElementById('act-edge-ldap-enabled').checked = !!ldap.enabled;
    document.getElementById('act-edge-ldap-host').value = ldap.host || '';
    document.getElementById('act-edge-ldap-port').value = ldap.port || 389;
    document.getElementById('act-edge-ldap-basedn').value = ldap.base_dn || '';
    document.getElementById('act-edge-ldap-binddn').value = ldap.bind_dn || '';
    document.getElementById('act-edge-ldap-bindpass').value = ldap.bind_password || '';
    document.getElementById('act-edge-ldap-filter').value = ldap.user_filter || '(&(objectClass=user)(sAMAccountName={username}))';

    modal.style.display = 'flex';
}

function closeActivateEdgeNodeModal() {
    const modal = document.getElementById('modal-activate-edge-node');
    if (modal) modal.style.display = 'none';
}

async function submitActivateEdgeNode() {
    const nodeId = document.getElementById('act-edge-node-id').value;
    const adminName = document.getElementById('act-edge-admin-name').value.trim();
    const adminEmail = document.getElementById('act-edge-admin-email').value.trim();
    const adminUsername = document.getElementById('act-edge-admin-username').value.trim();
    const adminPass = document.getElementById('act-edge-admin-pass').value.trim();
    const syncInterval = document.getElementById('act-edge-sync-interval').value;
    const allowedCIDRs = document.getElementById('act-edge-allowed-cidrs') ? document.getElementById('act-edge-allowed-cidrs').value.trim() : '';

    const ldapConfig = {
        enabled: document.getElementById('act-edge-ldap-enabled').checked,
        host: document.getElementById('act-edge-ldap-host').value.trim(),
        port: parseInt(document.getElementById('act-edge-ldap-port').value, 10) || 389,
        base_dn: document.getElementById('act-edge-ldap-basedn').value.trim(),
        bind_dn: document.getElementById('act-edge-ldap-binddn').value.trim(),
        bind_password: document.getElementById('act-edge-ldap-bindpass').value.trim(),
        user_filter: document.getElementById('act-edge-ldap-filter').value.trim() || '(&(objectClass=user)(sAMAccountName={username}))'
    };

    const btn = document.getElementById('btn-save-act-edge');
    try {
        if (btn) { btn.disabled = true; btn.textContent = 'Kaydediliyor...'; }

        const res = await fetch('/api/v1/settings/edge/nodes/activate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                id: nodeId,
                admin_name: adminName,
                admin_email: adminEmail,
                admin_username: adminUsername,
                admin_pass: adminPass,
                sync_interval: syncInterval,
                ldap_config: ldapConfig,
                allowed_cidrs: allowedCIDRs
            })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);

        if (typeof showToast === 'function') {
            showToast('✓ Düğüm etkinleştirildi ve bulut ayarları güncellendi!', 'success');
        }
        closeActivateEdgeNodeModal();
        loadEdgeNodes();
    } catch (err) {
        alert('Düğüm etkinleştirilemedi: ' + err.message);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = '⚡ Düğümü Etkinleştir & Kaydet'; }
    }
}

function copyEdgeResultToken() {
    const token = document.getElementById('edge-result-token').value;
    copyToClipboard(token, 'Token panoya kopyalandı!');
}

function copyEdgeResultCurl() {
    const cmd = document.getElementById('edge-result-curl').value;
    copyToClipboard(cmd, 'Kurulum komutu panoya kopyalandı!');
}

function copyNodeInstallCurl(token, name) {
    const endpoint = window.location.origin;
    const cmd = `curl -k -sSL ${endpoint}/api/v1/edge/install.sh | sudo bash -s -- --endpoint ${endpoint} --token ${token} --name "${name}"`;
    copyToClipboard(cmd, `'${name}' için kurulum komutu kopyalandı!`);
}

async function deleteEdgeNode(nodeId, nodeName) {
    if (!confirm(`'${nodeName}' adlı edge proxy düğümünü silmek ve yetkisini iptal etmek istediğinize emin misiniz?\n\nBu düğümün log aktarımı durdurulacaktır.`)) {
        return;
    }

    try {
        const res = await fetch(`/api/v1/settings/edge/nodes/delete?id=${nodeId}`, {
            method: 'DELETE'
        });
        if (!res.ok) {
            const data = await res.json();
            throw new Error(data.error || 'HTTP ' + res.status);
        }

        if (typeof showToast === 'function') {
            showToast(`Düğüm silindi: ${nodeName}`, 'info');
        }
        loadEdgeNodes();
    } catch (err) {
        alert('Düğüm silinemedi: ' + err.message);
    }
}

function openRotateEdgeKeyModal(nodeId, nodeName) {
    const modal = document.getElementById('modal-rotate-edge-key');
    if (!modal) return;
    document.getElementById('rotate-edge-node-id').value = nodeId;
    document.getElementById('rotate-edge-node-name-disp').value = nodeName;
    document.getElementById('rotate-edge-key-expiry').value = '90';
    document.getElementById('rotate-key-form-container').style.display = 'block';
    document.getElementById('rotate-key-success-box').style.display = 'none';
    const btn = document.getElementById('btn-submit-rotate-key');
    if (btn) {
        btn.disabled = false;
        btn.style.display = 'inline-block';
        btn.textContent = '🔄 Anahtarı Yenile';
    }
    modal.style.display = 'flex';
}

function closeRotateEdgeKeyModal() {
    const modal = document.getElementById('modal-rotate-edge-key');
    if (modal) modal.style.display = 'none';
}

async function submitRotateEdgeNodeKey() {
    const nodeId = document.getElementById('rotate-edge-node-id').value;
    const expiryDays = parseInt(document.getElementById('rotate-edge-key-expiry').value, 10) || 0;
    const btn = document.getElementById('btn-submit-rotate-key');

    try {
        if (btn) { btn.disabled = true; btn.textContent = 'Yenileniyor...'; }
        const res = await fetch('/api/v1/settings/edge/nodes/rotate-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: nodeId, expires_days: expiryDays })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);

        document.getElementById('rotate-key-form-container').style.display = 'none';
        document.getElementById('rotate-key-success-box').style.display = 'block';
        document.getElementById('rotate-result-token').value = data.token;
        if (btn) btn.style.display = 'none';

        if (typeof showToast === 'function') {
            showToast('✓ Zero-Trust API anahtarı başarıyla yenilendi!', 'success');
        }
        loadEdgeNodes();
    } catch (err) {
        alert('Anahtar yenilenemedi: ' + err.message);
        if (btn) { btn.disabled = false; btn.textContent = '🔄 Anahtarı Yenile'; }
    }
}

function copyRotateResultToken() {
    const token = document.getElementById('rotate-result-token').value;
    copyToClipboard(token, 'Yeni token panoya kopyalandı!');
}

// ==============================================================================
// Support & Diagnostic Debug Bundle Functions
// ==============================================================================

function openDebugSection() {
    switchTab('support');
}

async function submitGenerateDebugBundle() {
    const btn = document.getElementById('btn-create-debug-bundle');
    const desc = document.getElementById('debug-issue-desc') ? document.getElementById('debug-issue-desc').value.trim() : '';
    const email = document.getElementById('debug-contact-email') ? document.getElementById('debug-contact-email').value.trim() : '';
    const incSettings = document.getElementById('debug-opt-settings') ? document.getElementById('debug-opt-settings').checked : true;
    const incTelemetry = document.getElementById('debug-opt-telemetry') ? document.getElementById('debug-opt-telemetry').checked : true;
    const incLogs = document.getElementById('debug-opt-logs') ? document.getElementById('debug-opt-logs').checked : true;
    const incDBLogs = document.getElementById('debug-opt-db-logs') ? document.getElementById('debug-opt-db-logs').checked : true;
    const incSIEMEvents = document.getElementById('debug-opt-siem-events') ? document.getElementById('debug-opt-siem-events').checked : true;

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> <span>${(window.translations && window.translations[currentLang] && window.translations[currentLang].debug_generating) || 'Paket oluşturuluyor...'}</span>`;
    }

    try {
        const payload = {
            issue_description: desc,
            contact_email: email,
            include_settings: incSettings,
            include_telemetry: incTelemetry,
            include_logs: incLogs,
            include_db_logs: incDBLogs,
            include_siem_events: incSIEMEvents
        };

        const res = await fetch('/api/v1/debug/bundle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${res.status}`);
        }

        const data = await res.json();
        const b = data.bundle;

        // Show result card
        const card = document.getElementById('debug-result-card');
        if (card) {
            card.style.display = 'block';
        }

        const resId = document.getElementById('debug-res-id');
        if (resId) resId.textContent = `#${b.id}`;

        const resPasscode = document.getElementById('debug-res-passcode');
        if (resPasscode) resPasscode.textContent = b.access_passcode;

        // Ensure fully qualified, absolute URL using current browser origin
        let fullDownloadUrl = '';
        try {
            fullDownloadUrl = new URL(data.download_url || `/support/download?id=${b.id}`, window.location.origin).href;
        } catch (e) {
            fullDownloadUrl = `${window.location.origin}/support/download?id=${b.id}`;
        }

        const resUrl = document.getElementById('debug-res-url');
        if (resUrl) resUrl.value = fullDownloadUrl;

        const emailBanner = document.getElementById('debug-res-email-banner');
        if (emailBanner) {
            if (data.email_sent) {
                emailBanner.style.color = '#10b981';
                emailBanner.textContent = (window.translations && window.translations[currentLang] && window.translations[currentLang].debug_email_status_sent) || '✅ Bildirim ve şifre e-posta ile Süper Yöneticiye iletildi.';
            } else {
                emailBanner.style.color = '#94a3b8';
                emailBanner.textContent = (window.translations && window.translations[currentLang] && window.translations[currentLang].debug_email_status_none) || 'ℹ️ E-posta sunucusu yapılandırılmamış; indirme bağlantısını ve şifreyi doğrudan paylaşabilirsiniz.';
            }
        }

        const directUrl = `${fullDownloadUrl}${fullDownloadUrl.includes('?') ? '&' : '?'}passcode=${encodeURIComponent(b.access_passcode)}`;
        const directLink = document.getElementById('debug-res-direct-link');
        if (directLink) {
            directLink.href = directUrl;
            directLink.setAttribute('download', b.filename || `support-bundle-${b.id}.tar.gz`);
            directLink.onclick = function(e) {
                window.location.href = directUrl;
                return false;
            };
        }

        if (typeof showToast === 'function') {
            showToast('Tanılama paketi başarıyla oluşturuldu!', 'success');
        }

        // Refresh bundles history list
        loadDebugBundles();

    } catch (err) {
        alert('Destek paketi oluşturulamadı: ' + err.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<span data-i18n="btn_generate_debug">${(window.translations && window.translations[currentLang] && window.translations[currentLang].btn_generate_debug) || '⚡ Paketi Oluştur ve Gönder'}</span>`;
        }
    }
}

function copyDebugLink() {
    const input = document.getElementById('debug-res-url');
    if (!input || !input.value) return;
    input.focus();
    input.select();
    if (input.setSelectionRange) input.setSelectionRange(0, 99999);
    const msg = (window.translations && window.translations[currentLang] && window.translations[currentLang].btn_copy_done) || 'İndirme bağlantısı kopyalandı!';
    copyToClipboard(input.value, msg);
    const btn = document.getElementById('btn-copy-link');
    if (btn) {
        const orig = btn.innerHTML;
        btn.innerHTML = '✓ ' + ((window.translations && window.translations[currentLang] && window.translations[currentLang].btn_copy_done) || 'Kopyalandı!');
        setTimeout(() => { btn.innerHTML = orig; }, 2500);
    }
}

function copyDebugPasscode() {
    const el = document.getElementById('debug-res-passcode');
    if (!el || !el.textContent) return;
    const text = el.textContent.trim();
    const msg = (window.translations && window.translations[currentLang] && window.translations[currentLang].btn_copy_done) || 'Şifre kopyalandı!';
    copyToClipboard(text, msg);
    const btn = document.getElementById('btn-copy-passcode');
    if (btn) {
        const orig = btn.innerHTML;
        btn.innerHTML = '✓ ' + ((window.translations && window.translations[currentLang] && window.translations[currentLang].btn_copy_done) || 'Kopyalandı!');
        setTimeout(() => { btn.innerHTML = orig; }, 2500);
    }
}

async function loadDebugBundles() {
    const tbody = document.getElementById('debug-bundles-body');
    if (!tbody) return;

    try {
        const res = await fetch('/api/v1/debug/bundles');
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">Paketler yüklenemedi (HTTP ${res.status})</td></tr>`;
            return;
        }

        const data = await res.json();
        const bundles = data.bundles || [];

        if (bundles.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted" style="padding: 16px;">Henüz oluşturulmuş destek paketi yok.</td></tr>`;
            return;
        }

        tbody.innerHTML = bundles.map(b => {
            const sizeKB = (b.file_size / 1024).toFixed(1);
            const dateStr = new Date(b.created_at).toLocaleString();
            const downloadUrl = `/support/download?id=${b.id}&passcode=${encodeURIComponent(b.access_passcode)}`;

            const createdDate = new Date(b.created_at);
            const expiresDate = b.expires_at ? new Date(b.expires_at) : new Date(createdDate.getTime() + 7 * 24 * 3600 * 1000);
            const now = new Date();
            const isExpired = now > expiresDate;
            const diffMs = expiresDate - now;
            const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

            let ttlBadge = '';
            if (isExpired) {
                ttlBadge = `<span class="badge" style="background: rgba(239, 68, 68, 0.2); color: #f87171; font-size: 0.72rem;">❌ ${(window.translations && window.translations[currentLang] && window.translations[currentLang].badge_expired) || 'Süresi Doldu'}</span>`;
            } else if (diffDays <= 1) {
                ttlBadge = `<span class="badge" style="background: rgba(245, 158, 11, 0.2); color: #fbbf24; font-size: 0.72rem;">⚠️ ${(window.translations && window.translations[currentLang] && window.translations[currentLang].badge_expiring_today) || '< 24 Saat'}</span>`;
            } else {
                ttlBadge = `<span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #34d399; font-size: 0.72rem;">⏳ ${diffDays} ${(window.translations && window.translations[currentLang] && window.translations[currentLang].lbl_days_left) || 'gün kaldı'}</span>`;
            }

            return `
                <tr>
                    <td><strong class="mono-code" style="color: var(--primary);">#${escapeHtml(b.id)}</strong></td>
                    <td style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(dateStr)}</td>
                    <td><span class="badge badge-secondary">${escapeHtml(b.requested_by)}</span> <small class="text-muted">(${escapeHtml(b.tenant_slug)})</small></td>
                    <td class="mono-code">${sizeKB} KB</td>
                    <td>
                        <div style="display: flex; align-items: center; gap: 4px;">
                            <code class="mono-code" style="color: #38bdf8; background: rgba(56, 189, 248, 0.1); padding: 1px 6px; border-radius: 4px;">${escapeHtml(b.access_passcode)}</code>
                            <button type="button" class="btn btn-outline" style="padding: 1px 5px; font-size: 0.7rem;" onclick="copyToClipboard('${escapeHtml(b.access_passcode)}', 'Şifre kopyalandı!')" title="Şifreyi Kopyala">📋</button>
                        </div>
                    </td>
                    <td style="text-align: center;"><span class="badge ${b.download_count > 0 ? 'badge-success' : 'badge-secondary'}">${b.download_count}</span></td>
                    <td style="text-align: center;">${ttlBadge}</td>
                    <td>
                        ${isExpired ? `
                            <span class="text-muted" style="font-size: 0.75rem;">(Silindi)</span>
                        ` : `
                            <a href="${downloadUrl}" download="${escapeHtml(b.filename)}" class="btn btn-xs btn-outline" style="text-decoration: none; padding: 2px 8px;">
                                ⬇️ ${(window.translations && window.translations[currentLang] && window.translations[currentLang].th_actions) || 'İndir'}
                            </a>
                        `}
                    </td>
                </tr>
            `;
        }).join('');

    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger">Hata: ${escapeHtml(err.message)}</td></tr>`;
    }
}

// ==========================================================================
// Enterprise Security & Password Policy Helpers
// ==========================================================================
function checkPasswordStrength(pw, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    if (!pw) {
        container.innerHTML = '';
        return;
    }

    const rules = [
        { label: '8+ Karakter', pass: pw.length >= 8 },
        { label: 'Büyük Harf (A-Z)', pass: /[A-Z]/.test(pw) },
        { label: 'Küçük Harf (a-z)', pass: /[a-z]/.test(pw) },
        { label: 'Rakam (0-9)', pass: /[0-9]/.test(pw) },
        { label: 'Sembol (@#$%...)', pass: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?~`'"]/.test(pw) }
    ];

    container.innerHTML = rules.map(r => {
        const color = r.pass ? '#22c55e' : '#94a3b8';
        const bg = r.pass ? 'rgba(34, 197, 94, 0.15)' : 'rgba(255, 255, 255, 0.05)';
        const border = r.pass ? 'rgba(34, 197, 94, 0.35)' : 'rgba(255, 255, 255, 0.1)';
        const icon = r.pass ? '✓' : '○';
        return `<span style="display: inline-flex; align-items: center; gap: 4px; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: 500; background: ${bg}; color: ${color}; border: 1px solid ${border};">
            <span>${icon}</span> ${r.label}
        </span>`;
    }).join('');
}

function initChangePasswordModal() {
    const modal = document.getElementById('modal-change-password');
    const btnOpen = document.getElementById('btn-open-change-password');
    const btnClose = document.getElementById('btn-close-change-password');
    const btnCancel = document.getElementById('btn-cancel-change-password');
    const btnSubmit = document.getElementById('btn-submit-change-password');
    const curInput = document.getElementById('change-pass-current');
    const newInput = document.getElementById('change-pass-new');
    const confirmInput = document.getElementById('change-pass-confirm');
    const errBox = document.getElementById('change-pass-error');
    const succBox = document.getElementById('change-pass-success');
    const strengthBox = document.getElementById('change-pass-strength');

    const resetForm = () => {
        if (curInput) curInput.value = '';
        if (newInput) newInput.value = '';
        if (confirmInput) confirmInput.value = '';
        if (errBox) { errBox.style.display = 'none'; errBox.textContent = ''; }
        if (succBox) { succBox.style.display = 'none'; succBox.textContent = ''; }
        if (strengthBox) strengthBox.innerHTML = '';
    };

    const closeModal = () => {
        if (modal) modal.style.display = 'none';
        resetForm();
    };

    if (btnOpen) {
        btnOpen.addEventListener('click', (e) => {
            e.preventDefault();
            resetForm();
            if (modal) modal.style.display = 'flex';
            if (curInput) curInput.focus();
        });
    }

    if (btnClose) btnClose.addEventListener('click', closeModal);
    if (btnCancel) btnCancel.addEventListener('click', closeModal);

    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });
    }

    if (btnSubmit) {
        btnSubmit.addEventListener('click', async () => {
            const current_password = curInput ? curInput.value : '';
            const new_password = newInput ? newInput.value : '';
            const confirm_password = confirmInput ? confirmInput.value : '';

            if (errBox) { errBox.style.display = 'none'; errBox.textContent = ''; }
            if (succBox) { succBox.style.display = 'none'; succBox.textContent = ''; }

            if (!current_password) {
                if (errBox) {
                    errBox.textContent = (window.translations && window.translations[currentLang] && window.translations[currentLang].err_current_password_required) || 'Mevcut şifrenizi giriniz.';
                    errBox.style.display = 'block';
                }
                return;
            }

            if (!new_password) {
                if (errBox) {
                    errBox.textContent = (window.translations && window.translations[currentLang] && window.translations[currentLang].err_new_password_required) || 'Yeni şifrenizi giriniz.';
                    errBox.style.display = 'block';
                }
                return;
            }

            if (new_password !== confirm_password) {
                if (errBox) {
                    errBox.textContent = (window.translations && window.translations[currentLang] && window.translations[currentLang].err_passwords_do_not_match) || 'Yeni şifreler birbiriyle eşleşmiyor.';
                    errBox.style.display = 'block';
                }
                return;
            }

            btnSubmit.disabled = true;
            btnSubmit.textContent = '...';

            try {
                const res = await fetch('/api/v1/auth/change-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ current_password, new_password })
                });

                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    throw new Error(data.error || `HTTP ${res.status}`);
                }

                if (succBox) {
                    succBox.textContent = (window.translations && window.translations[currentLang] && window.translations[currentLang].msg_password_changed_success) || 'Şifreniz başarıyla güncellendi!';
                    succBox.style.display = 'block';
                }
                showToast('Şifreniz başarıyla güncellendi', 'success');

                setTimeout(() => {
                    closeModal();
                }, 1400);

            } catch (err) {
                if (errBox) {
                    errBox.textContent = err.message;
                    errBox.style.display = 'block';
                } else {
                    showToast(err.message, 'error');
                }
            } finally {
                btnSubmit.disabled = false;
                btnSubmit.textContent = (window.translations && window.translations[currentLang] && window.translations[currentLang].btn_save_password) || 'Şifreyi Güncelle';
            }
        });
    }
}

// ==========================================================================
// Deep Vendor & Application Badge Intelligence
// ==========================================================================
function renderVendorBadge(vendor) {
    if (!vendor) return '';
    const vLower = String(vendor).toLowerCase();

    if (vLower.includes('fortinet') || vLower.includes('fortigate')) {
        return `<span class="badge" style="background: rgba(239, 68, 68, 0.16); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.35); font-weight: 600; padding: 2px 7px; border-radius: 4px; font-size: 11px; display: inline-flex; align-items: center; gap: 4px;" title="Fortinet FortiGate Firewall / UTM">🛡️ Fortinet</span>`;
    }
    if (vLower.includes('cisco')) {
        return `<span class="badge" style="background: rgba(14, 165, 233, 0.16); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.35); font-weight: 600; padding: 2px 7px; border-radius: 4px; font-size: 11px; display: inline-flex; align-items: center; gap: 4px;" title="Cisco IOS / NX-OS Network Device">🌐 Cisco</span>`;
    }
    if (vLower.includes('aruba') || vLower.includes('hpe')) {
        return `<span class="badge" style="background: rgba(245, 158, 11, 0.16); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.35); font-weight: 600; padding: 2px 7px; border-radius: 4px; font-size: 11px; display: inline-flex; align-items: center; gap: 4px;" title="Aruba / HPE Switch or Controller">📶 Aruba/HPE</span>`;
    }
    if (vLower.includes('juniper') || vLower.includes('junos')) {
        return `<span class="badge" style="background: rgba(16, 185, 129, 0.16); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.35); font-weight: 600; padding: 2px 7px; border-radius: 4px; font-size: 11px; display: inline-flex; align-items: center; gap: 4px;" title="Juniper Junos OS Router / Switch">🌲 Juniper</span>`;
    }

    return `<span class="badge badge-secondary" style="font-size: 11px; padding: 2px 6px;">🏷️ ${escapeHtml(vendor)}</span>`;
}

function formatApplicationBadge(app) {
    if (!app) return '';
    return `<span class="badge badge-outline" style="font-size: 10.5px; padding: 1px 6px; border-color: rgba(255,255,255,0.14); color: var(--text-main); font-family: monospace; font-weight: 500;">${escapeHtml(app)}</span>`;
}

// ==========================================================================
// Administrative & Security Audit Trail Controller
// ==========================================================================
async function loadAuditLogs() {
    const tbody = document.getElementById('tbody-audit-logs');
    if (!tbody) return;

    const actionSelect = document.getElementById('audit-filter-action');
    const searchInput = document.getElementById('audit-filter-search');
    const totalBadge = document.getElementById('audit-total-badge');

    const action = actionSelect ? actionSelect.value.trim() : '';
    const search = searchInput ? searchInput.value.trim() : '';

    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 20px;">Denetim izleri yükleniyor...</td></tr>`;

    try {
        const params = new URLSearchParams();
        if (action) params.set('action', action);
        if (search) params.set('search', search);
        params.set('limit', '50');

        const res = await fetch(`/api/v1/audit/logs?${params.toString()}`);
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || `HTTP ${res.status}`);
        }

        const data = await res.json();
        const logs = data.logs || [];
        const total = data.total || logs.length;

        if (totalBadge) {
            totalBadge.textContent = `${total} ${(window.translations && window.translations[currentLang] && window.translations[currentLang].lbl_audit_events) || 'Kayıt / Event'}`;
        }

        if (logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 24px;">Kriterlere uygun denetim kaydı bulunamadı.</td></tr>`;
            return;
        }

        tbody.innerHTML = logs.map(l => {
            const dateStr = l.created_at ? new Date(l.created_at).toLocaleString() : '-';
            const statusUpper = String(l.status || 'SUCCESS').toUpperCase();
            const statusBadge = statusUpper === 'SUCCESS'
                ? `<span class="badge" style="background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3); font-size: 11px;">✓ SUCCESS</span>`
                : `<span class="badge" style="background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); font-size: 11px;">✕ ${escapeHtml(statusUpper)}</span>`;

            let actionBadgeStyle = 'background: rgba(148, 163, 184, 0.15); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.25);';
            if (l.action && l.action.startsWith('AUTH_')) {
                actionBadgeStyle = 'background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3);';
            } else if (l.action && l.action.includes('DELETE')) {
                actionBadgeStyle = 'background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3);';
            } else if (l.action && l.action.includes('CREATE')) {
                actionBadgeStyle = 'background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3);';
            }

            const actionBadge = `<span class="badge mono-code" style="${actionBadgeStyle} font-size: 11px; font-weight: 600;">${escapeHtml(l.action)}</span>`;

            let detailsText = '';
            if (typeof l.details === 'object' && l.details !== null) {
                detailsText = JSON.stringify(l.details);
            } else {
                detailsText = String(l.details || '');
            }

            return `
                <tr>
                    <td style="font-size: 12px; color: var(--text-muted); white-space: nowrap;">${escapeHtml(dateStr)}</td>
                    <td>
                        <span style="font-weight: 600; display: inline-flex; align-items: center; gap: 4px;">
                            <span>👤</span> ${escapeHtml(l.username || 'system')}
                        </span>
                    </td>
                    <td><code class="mono-code" style="font-size: 12px; color: #38bdf8;">${escapeHtml(l.source_ip || '-')}</code></td>
                    <td>${actionBadge}</td>
                    <td><span class="mono-code" style="font-size: 12px;">${escapeHtml(l.resource || '-')}</span></td>
                    <td>${statusBadge}</td>
                    <td><span class="tenant-chip" style="font-size: 11px;">🏢 ${escapeHtml(l.tenant_slug || 'default')}</span></td>
                    <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 11px; color: var(--text-muted);" title="${escapeHtml(detailsText)}">
                        ${escapeHtml(detailsText || '-')}
                    </td>
                </tr>
            `;
        }).join('');

    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--danger); padding: 20px;">Denetim izleri alınamadı: ${escapeHtml(err.message)}</td></tr>`;
    }
}

// ============================================================================
// VALTRIVO LOGSEAL - MULTI-TENANT SIEM & SOC REPORTING ENGINE
// ============================================================================

let reportsInitialized = false;

function loadReportsView() {
    const badge = document.getElementById('reports-active-tenant-badge');
    if (badge) {
        const isEn = (window.i18n && window.i18n.currentLang === 'en') || localStorage.getItem('logseal_lang') === 'en';
        badge.textContent = isEn ? 'Active Tenant: Default' : 'Aktif Kiracı: Default';
    }

    if (!reportsInitialized) {
        initReportsEventListeners();
        reportsInitialized = true;
    }

    loadReportIncidents();
    loadReportHistory();
    generateReportPreview();
}

function initReportsEventListeners() {
    // Template radio cards selection
    const cards = document.querySelectorAll('.report-type-card');
    cards.forEach(card => {
        card.addEventListener('click', () => {
            cards.forEach(c => {
                c.classList.remove('active');
                c.style.borderColor = 'var(--border-color)';
            });
            card.classList.add('active');
            card.style.borderColor = 'var(--primary)';
            const radio = card.querySelector('input[type="radio"]');
            if (radio) {
                radio.checked = true;
                const incidentGroup = document.getElementById('report-incident-selector-group');
                if (incidentGroup) {
                    incidentGroup.style.display = (radio.value === 'incident_rca') ? 'block' : 'none';
                }
            }
        });
    });

    // Timeframe selector
    const timeframeSelect = document.getElementById('report-timeframe-select');
    const customDateBox = document.getElementById('report-custom-date-container');
    if (timeframeSelect && customDateBox) {
        timeframeSelect.addEventListener('change', () => {
            customDateBox.style.display = (timeframeSelect.value === 'custom') ? 'block' : 'none';
        });
    }

    // Report Language selector
    const langSelect = document.getElementById('report-language-select');
    if (langSelect) {
        langSelect.addEventListener('change', () => {
            generateReportPreview();
        });
    }

    // Preview Mode Toggle (Visual vs Raw Text)
    const btnVisual = document.getElementById('btn-preview-mode-visual');
    const btnRaw = document.getElementById('btn-preview-mode-raw');
    const canvasVisual = document.getElementById('report-visual-canvas');
    const canvasRaw = document.getElementById('report-raw-canvas');

    if (btnVisual && btnRaw && canvasVisual && canvasRaw) {
        btnVisual.addEventListener('click', () => {
            btnVisual.classList.add('active');
            btnRaw.classList.remove('active');
            canvasVisual.style.display = 'block';
            canvasRaw.style.display = 'none';
        });

        btnRaw.addEventListener('click', () => {
            btnRaw.classList.add('active');
            btnVisual.classList.remove('active');
            canvasVisual.style.display = 'none';
            canvasRaw.style.display = 'block';
        });
    }

    // Action buttons
    document.getElementById('btn-report-preview')?.addEventListener('click', generateReportPreview);
    document.getElementById('btn-report-export-pdf')?.addEventListener('click', () => exportReport('pdf'));
    document.getElementById('btn-report-export-docx')?.addEventListener('click', () => exportReport('docx'));
    document.getElementById('btn-report-export-csv')?.addEventListener('click', () => exportReport('csv'));
    document.getElementById('btn-report-export-json')?.addEventListener('click', () => exportReport('json'));
    document.getElementById('btn-report-export-txt')?.addEventListener('click', () => exportReport('txt'));
    document.getElementById('btn-refresh-report-history')?.addEventListener('click', loadReportHistory);
}

function getReportFilterParams() {
    const params = new URLSearchParams();

    const selectedRadio = document.querySelector('input[name="report_template_type"]:checked');
    params.set('type', selectedRadio ? selectedRadio.value : 'incident_rca');

    // Language selection: explicit selector or fallback to app language
    const langSelect = document.getElementById('report-language-select');
    let reportLang = langSelect ? langSelect.value : 'app';
    if (!reportLang || reportLang === 'app') {
        reportLang = (window.i18n && window.i18n.currentLang) || localStorage.getItem('logseal_lang') || 'tr';
    }
    params.set('lang', reportLang);

    const timeframe = document.getElementById('report-timeframe-select')?.value || '24h';
    params.set('timeframe', timeframe);

    if (timeframe === 'custom') {
        const start = document.getElementById('report-custom-start')?.value;
        const end = document.getElementById('report-custom-end')?.value;
        if (start) params.set('start_time', start);
        if (end) params.set('end_time', end);
    }

    const classification = document.getElementById('report-classification-select')?.value || 'TLP:AMBER / CONFIDENTIAL';
    params.set('classification', classification);

    const incident = document.getElementById('report-incident-select')?.value;
    if (incident) params.set('incident_id', incident);

    // In report section, the tenant should not change and should always be Default
    params.set('tenant', 'default');

    return params;
}

async function generateReportPreview() {
    const previewBtn = document.getElementById('btn-report-preview');
    const summaryText = document.getElementById('report-preview-summary-text');
    const rawText = document.getElementById('report-raw-text');

    const isEn = (window.i18n && window.i18n.currentLang === 'en') || localStorage.getItem('logseal_lang') === 'en';
    if (previewBtn) previewBtn.disabled = true;
    if (summaryText) summaryText.textContent = isEn ?
        'Compiling report data and querying cryptographic ledger...' :
        'Rapor verisi dinamik olarak derleniyor ve şifreli kanıt defteri sorgulanıyor...';

    try {
        const params = getReportFilterParams();
        const res = await fetch(`/api/v1/reports/preview?${params.toString()}`);
        if (!res.ok) {
            const errText = await res.text();
            throw new Error(errText || (isEn ? 'Failed to generate preview' : 'Önizleme oluşturulamadı'));
        }

        const data = await res.json();
        if (data.report) {
            renderVisualReportPreview(data.report);
        }
        if (rawText && data.text_preview) {
            rawText.textContent = data.text_preview;
        }

    } catch (err) {
        console.error('Report preview error:', err);
        if (summaryText) {
            summaryText.innerHTML = `<span style="color: var(--danger);">${isEn ? 'Error:' : 'Hata:'} ${escapeHtml(err.message)}</span>`;
        }
    } finally {
        if (previewBtn) previewBtn.disabled = false;
    }
}

function renderVisualReportPreview(report) {
    if (!report) return;

    const isEn = report.language === 'en' || (!report.language && (window.i18n && window.i18n.currentLang === 'en'));

    // Header Strip
    const titleEl = document.getElementById('report-preview-title');
    if (titleEl) titleEl.textContent = report.title || (isEn ? 'SOC Investigation Report' : 'SOC Raporu');

    const metaEl = document.getElementById('report-preview-meta');
    if (metaEl) {
        if (isEn) {
            metaEl.textContent = `Tenant: ${report.tenant?.tenant_name || 'Default'} [Slug: ${report.tenant?.tenant_slug || 'default'}] | Report ID: ${report.report_id} | Timestamp: Verified`;
        } else {
            metaEl.textContent = `Kiracı: ${report.tenant?.tenant_name || 'Varsayılan'} [Kısa Ad: ${report.tenant?.tenant_slug || 'default'}] | Rapor ID: ${report.report_id} | Zaman Damgası: Doğrulandı`;
        }
    }

    const classEl = document.getElementById('report-preview-classification');
    if (classEl) {
        classEl.textContent = report.classification || 'TLP:AMBER';
    }

    const windowEl = document.getElementById('report-preview-window');
    if (windowEl) {
        const startStr = report.start_time ? new Date(report.start_time).toUTCString() : '';
        const endStr = report.end_time ? new Date(report.end_time).toUTCString() : '';
        windowEl.textContent = `${startStr} - ${endStr}`;
    }

    // Summary & KPIs
    const summaryText = document.getElementById('report-preview-summary-text');
    if (summaryText) summaryText.textContent = report.executive_summary || (isEn ? 'No summary available.' : 'Özet bulunmuyor.');

    const kpiMTTD = document.getElementById('report-kpi-mttd');
    if (kpiMTTD) kpiMTTD.textContent = `${report.mttd_minutes || 0} min`;

    const kpiMTTA = document.getElementById('report-kpi-mtta');
    if (kpiMTTA) kpiMTTA.textContent = `${report.mtta_minutes || 0} min`;

    const kpiMTTR = document.getElementById('report-kpi-mttr');
    if (kpiMTTR) kpiMTTR.textContent = `${report.mttr_minutes || 0} min`;

    const kpiLegal = document.getElementById('report-kpi-legal');
    if (kpiLegal) {
        if (report.regulatory_impact?.law5651_relevant) {
            kpiLegal.textContent = isEn ? 'Law 5651 Sealed (.zd)' : '5651 Mühürlendi (.zd)';
            kpiLegal.style.color = 'var(--success)';
        } else {
            kpiLegal.textContent = isEn ? 'Compliant' : 'Uyumlu';
            kpiLegal.style.color = 'var(--text-main)';
        }
    }

    // Threat Section (MITRE)
    const threatBody = document.getElementById('report-preview-threat-body');
    const threatSec = document.getElementById('report-preview-threat-section');
    if (threatBody && threatSec) {
        if (report.threat_mappings && report.threat_mappings.length > 0) {
            threatSec.style.display = 'block';
            threatBody.innerHTML = report.threat_mappings.map(m => `
                <tr>
                    <td><span class="badge badge-outline" style="font-size: 11px;">${escapeHtml(m.tactic_id)}</span></td>
                    <td><code class="mono-code" style="color: #38bdf8; font-size: 11px;">${escapeHtml(m.technique_id)}</code></td>
                    <td style="font-weight: 600;">${escapeHtml(m.name)}</td>
                    <td style="color: var(--text-muted);">${escapeHtml(m.rule_name)}</td>
                    <td><span class="badge badge-secondary" style="font-size: 10px;">${escapeHtml(m.d3fend_id || 'D3-IT')}</span></td>
                </tr>
            `).join('');
        } else {
            threatSec.style.display = 'none';
        }
    }

    // IOC Section
    const iocBody = document.getElementById('report-preview-ioc-body');
    const iocSec = document.getElementById('report-preview-ioc-section');
    if (iocBody && iocSec) {
        if (report.iocs && report.iocs.length > 0) {
            iocSec.style.display = 'block';
            iocBody.innerHTML = report.iocs.map(ioc => `
                <tr>
                    <td><span class="badge badge-warning" style="font-size: 10px;">${escapeHtml(ioc.type)}</span></td>
                    <td><code class="mono-code" style="color: #f87171; font-weight: 600; font-size: 11px;">${escapeHtml(ioc.value)}</code></td>
                    <td><span class="badge badge-outline" style="font-size: 10px;">${escapeHtml(ioc.confidence)}</span></td>
                    <td style="color: var(--text-muted);">${escapeHtml(ioc.reputation)}</td>
                    <td><span class="badge badge-success" style="font-size: 10px;">${escapeHtml(ioc.action_taken)}</span></td>
                </tr>
            `).join('');
        } else {
            iocSec.style.display = 'none';
        }
    }

    // Chain of Custody & Law 5651 Evidence Ledger
    const custodyBody = document.getElementById('report-preview-custody-body');
    const custodySec = document.getElementById('report-preview-custody-section');
    if (custodyBody && custodySec) {
        if (report.chain_of_custody && report.chain_of_custody.length > 0) {
            custodySec.style.display = 'block';
            custodyBody.innerHTML = report.chain_of_custody.map(ev => `
                <tr>
                    <td><strong class="mono-code" style="font-size: 11px;">${escapeHtml(ev.evidence_id)}</strong></td>
                    <td style="font-size: 11px;">${escapeHtml(ev.artifact_type)}</td>
                    <td style="font-size: 11px; color: var(--text-muted);">${escapeHtml(ev.source_host)}</td>
                    <td><code class="mono-code" style="font-size: 10px; color: #818cf8;" title="${escapeHtml(ev.sha256_hash)}">${escapeHtml(ev.sha256_hash.substring(0, 18))}...</code></td>
                    <td><span class="badge badge-success" style="font-size: 10px; font-weight: 600;">🔒 ${escapeHtml(ev.tsa_token_zd)}</span></td>
                    <td style="font-size: 11px; color: var(--text-muted);">${escapeHtml(ev.custodian)}</td>
                </tr>
            `).join('');
        } else {
            custodySec.style.display = 'none';
        }
    }

    // Root Cause & Actions
    const rootCauseEl = document.getElementById('report-preview-root-cause');
    const actionsListEl = document.getElementById('report-preview-actions-list');
    const rcaSec = document.getElementById('report-preview-rca-section');

    if (rcaSec && rootCauseEl && actionsListEl) {
        if (report.root_cause || (report.remediation_plan && report.remediation_plan.length > 0)) {
            rcaSec.style.display = 'block';
            const rcLabel = isEn ? 'Root Cause Finding:' : 'Kök Neden Tespiti:';
            rootCauseEl.textContent = report.root_cause ? `${rcLabel} ${report.root_cause}` : '';
            actionsListEl.innerHTML = (report.remediation_plan || []).map(p => `<li>${escapeHtml(p)}</li>`).join('');
        } else {
            rcaSec.style.display = 'none';
        }
    }
}

function exportReport(format) {
    const params = getReportFilterParams();
    params.set('format', format);

    const isEn = (window.i18n && window.i18n.currentLang === 'en') || localStorage.getItem('logseal_lang') === 'en';
    const toastMsg = isEn ?
        `Generating and downloading ${format.toUpperCase()} report...` :
        `Rapor (${format.toUpperCase()}) oluşturuluyor ve indiriliyor...`;

    if (typeof showToast === 'function') {
        showToast(toastMsg, 'info');
    }

    const downloadUrl = `/api/v1/reports/export?${params.toString()}`;
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.target = '_blank';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    // Refresh history after generation
    setTimeout(loadReportHistory, 1500);
}

async function loadReportHistory() {
    const tbody = document.getElementById('report-history-body');
    if (!tbody) return;

    const isEn = (window.i18n && window.i18n.currentLang === 'en') || localStorage.getItem('logseal_lang') === 'en';

    try {
        const res = await fetch('/api/v1/reports/history');
        if (!res.ok) throw new Error(isEn ? 'Failed to fetch history' : 'Geçmiş alınamadı');

        const data = await res.json();
        const list = data.history || [];

        if (list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 16px;">${isEn ? 'No generated report history records yet.' : 'Henüz oluşturulmuş rapor kaydı bulunmuyor.'}</td></tr>`;
            return;
        }

        tbody.innerHTML = list.map(item => {
            const dateStr = item.generated_at ? new Date(item.generated_at).toLocaleString() : '-';
            const formatBadge = item.format === 'PDF' ? 'badge-danger' :
                                item.format === 'DOCX' ? 'badge-info' :
                                item.format === 'CSV' ? 'badge-success' : 'badge-secondary';

            return `
                <tr>
                    <td><strong class="mono-code" style="font-size: 12px; color: var(--primary);">${escapeHtml(item.id)}</strong></td>
                    <td style="font-weight: 500; font-size: 12px;">${escapeHtml(item.title || item.report_type)}</td>
                    <td><span class="tenant-chip" style="font-size: 11px;">🏢 ${escapeHtml(item.tenant_slug || 'default')}</span></td>
                    <td><span class="badge badge-outline" style="font-size: 10px;">${escapeHtml(item.classification)}</span></td>
                    <td><span class="badge ${formatBadge}" style="font-size: 10px; font-weight: 700;">${escapeHtml(item.format)}</span></td>
                    <td style="font-size: 12px; color: var(--text-muted);">👤 ${escapeHtml(item.generated_by || 'system')}</td>
                    <td style="font-size: 11px; color: var(--text-muted);">${escapeHtml(dateStr)}</td>
                    <td>
                        <button class="btn btn-outline btn-sm" style="font-size: 10px; padding: 2px 8px;" onclick="exportReport('${escapeHtml((item.format || 'pdf').toLowerCase())}')">
                            ${isEn ? 'Download' : 'İndir'}
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

    } catch (err) {
        console.error('Report history load error:', err);
    }
}

async function loadReportIncidents() {
    const select = document.getElementById('report-incident-select');
    if (!select) return;

    try {
        const tenant = window.currentTenantSlug || '';
        const res = await fetch(`/api/v1/siem/alerts?limit=15&tenant=${encodeURIComponent(tenant)}`);
        if (!res.ok) return;

        const data = await res.json();
        const alerts = data.alerts || [];

        let html = '<option value="" selected>En Son Kritik Olaylar (Otomatik)</option>';
        alerts.forEach(a => {
            html += `<option value="${escapeHtml(a.id)}">${escapeHtml(a.rule_name || a.summary)} [${escapeHtml(a.severity)}]</option>`;
        });
        select.innerHTML = html;
    } catch (err) {
        console.error('Failed to load SIEM incidents for report selector:', err);
    }
}

// Network Ports & Architecture Guide Modal Controller
function openPortsHelpModal() {
    const modal = document.getElementById('ports-help-modal');
    if (modal) {
        if (window.i18n && typeof window.i18n.applyTranslations === 'function') {
            window.i18n.applyTranslations();
        }
        modal.style.display = 'flex';
    }
}

function closePortsHelpModal() {
    const modal = document.getElementById('ports-help-modal');
    if (modal) modal.style.display = 'none';
}

function copyPortsFirewallUFW() {
    const cmd = "sudo ufw allow 22/tcp && sudo ufw allow 8443/tcp && sudo ufw allow 8080/tcp && sudo ufw allow 514/udp && sudo ufw allow 514/tcp && sudo ufw allow 5514/udp && sudo ufw allow 5514/tcp && sudo ufw allow 6514/tcp";
    const block = document.getElementById('ports-firewall-code-block');
    if (block) block.innerHTML = `<code>${cmd}</code>`;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(cmd).then(() => {
            const msg = (window.i18n && window.i18n.t('toast_ufw_copied')) || '✓ UFW Firewall commands copied to clipboard!';
            showToast(msg, 'success');
        }).catch(() => {
            showToast('Please copy the command manually.', 'info');
        });
    } else {
        showToast('Clipboard access unavailable.', 'info');
    }
}

function copyPortsFirewallFirewalld() {
    const cmd = "sudo firewall-cmd --permanent --add-port=8443/tcp --add-port=8080/tcp --add-port=514/udp --add-port=514/tcp --add-port=5514/udp --add-port=5514/tcp --add-port=6514/tcp && sudo firewall-cmd --reload";
    const block = document.getElementById('ports-firewall-code-block');
    if (block) block.innerHTML = `<code>${cmd}</code>`;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(cmd).then(() => {
            const msg = (window.i18n && window.i18n.t('toast_firewalld_copied')) || '✓ Firewalld commands copied to clipboard!';
            showToast(msg, 'success');
        }).catch(() => {
            showToast('Please copy the command manually.', 'info');
        });
    } else {
        showToast('Clipboard access unavailable.', 'info');
    }
}

function copyBaremetalCommands() {
    const cmd = "sudo systemctl status syslog-platform && sudo journalctl -u syslog-platform -f";
    const block = document.getElementById('ports-firewall-code-block');
    if (block) block.innerHTML = `<code>${cmd}</code>`;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(cmd).then(() => {
            const msg = (window.i18n && window.i18n.t('toast_baremetal_copied')) || '✓ Bare-metal systemd commands copied to clipboard!';
            showToast(msg, 'success');
        }).catch(() => {
            showToast('Please copy the command manually.', 'info');
        });
    } else {
        showToast('Clipboard access unavailable.', 'info');
    }
}

// ==========================================
// Documentation Viewer & Markdown Rendering
// ==========================================
let currentViewingDoc = '';

function downloadDoc(fileName) {
    if (!fileName) return;
    const cleanName = encodeURIComponent(fileName);
    window.location.href = `/api/v1/docs/download?file=${cleanName}`;
}

function viewDocInline(fileName) {
    if (!fileName) return;
    openDocViewerModal(fileName);
}

function openDocViewerModal(fileName) {
    currentViewingDoc = fileName;
    const modal = document.getElementById('modal-doc-viewer');
    if (!modal) {
        window.open(`/api/v1/docs/view?file=${encodeURIComponent(fileName)}`, '_blank');
        return;
    }
    const titleEl = document.getElementById('doc-viewer-modal-title');
    const pathEl = document.getElementById('doc-viewer-footer-path');
    const contentEl = document.getElementById('doc-viewer-modal-content');
    if (titleEl) titleEl.textContent = fileName;
    if (pathEl) pathEl.textContent = 'docs/' + fileName;
    if (contentEl) {
        const loadingText = (typeof t === 'function' ? t('lbl_doc_loading') : null) || 'Doküman yükleniyor...';
        contentEl.innerHTML = `<div style="text-align: center; padding: 50px 20px; color: var(--text-muted);"><span class="live-dot" style="display:inline-block; margin-right:8px;"></span> ${loadingText}</div>`;
    }
    modal.style.display = 'flex';

    fetch(`/api/v1/docs/view?file=${encodeURIComponent(fileName)}&raw=true`)
        .then(res => {
            if (!res.ok) throw new Error('Doküman alınamadı (' + res.status + ')');
            return res.text();
        })
        .then(md => {
            renderMarkdownInto(contentEl, md);
        })
        .catch(err => {
            if (contentEl) {
                contentEl.innerHTML = `<div class="alert alert-danger" style="margin: 20px 0;"><strong>Hata:</strong> ${err.message}</div>`;
            }
        });
}

function closeDocViewerModal() {
    const modal = document.getElementById('modal-doc-viewer');
    if (modal) modal.style.display = 'none';
}

function openCurrentDocInNewTab() {
    if (!currentViewingDoc) return;
    window.open(`/api/v1/docs/view?file=${encodeURIComponent(currentViewingDoc)}`, '_blank');
}

function downloadCurrentDoc() {
    if (!currentViewingDoc) return;
    downloadDoc(currentViewingDoc);
}

function renderMarkdownInto(container, md) {
    if (!container) return;
    if (window.marked && typeof window.marked.parse === 'function') {
        container.innerHTML = window.marked.parse(md);
    } else {
        container.innerHTML = '<pre style="white-space: pre-wrap; font-family: var(--font-mono);">' + 
            md.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') + 
            '</pre>';
        return;
    }

    // Wrap tables in .table-responsive for seamless scrolling
    container.querySelectorAll('table').forEach(table => {
        if (!table.parentElement.classList.contains('table-responsive')) {
            const wrapper = document.createElement('div');
            wrapper.className = 'table-responsive';
            table.parentNode.insertBefore(wrapper, table);
            wrapper.appendChild(table);
        }
    });

    // Wrap pre code blocks with code header and copy button
    container.querySelectorAll('pre').forEach(pre => {
        if (!pre.parentElement.classList.contains('code-block-wrapper')) {
            const wrapper = document.createElement('div');
            wrapper.className = 'code-block-wrapper';
            const header = document.createElement('div');
            header.className = 'code-block-header';
            const code = pre.querySelector('code');
            let lang = 'CODE';
            if (code && code.className) {
                const m = code.className.match(/language-([a-zA-Z0-9_-]+)/);
                if (m) lang = m[1].toUpperCase();
            }
            const copyLabel = (typeof t === 'function' ? t('btn_copy') : null) || 'Kopyala';
            header.innerHTML = `<span>${lang}</span><button class="btn-copy-code" onclick="copyDocCode(this)">📋 ${copyLabel}</button>`;
            pre.parentNode.insertBefore(wrapper, pre);
            wrapper.appendChild(header);
            wrapper.appendChild(pre);
        }
    });
}

function copyDocCode(btn) {
    const pre = btn.closest('.code-block-wrapper')?.querySelector('pre');
    if (!pre) return;
    navigator.clipboard.writeText(pre.innerText).then(() => {
        const orig = btn.textContent;
        const copiedLabel = (typeof t === 'function' ? t('lbl_copied') : null) || 'Kopyalandı!';
        btn.textContent = '✓ ' + copiedLabel;
        setTimeout(() => { btn.textContent = orig; }, 2000);
    }).catch(() => {
        btn.textContent = 'Hata!';
    });
}

function showDocsTab(docType) {
    closePortsHelpModal();
    if (docType === 'baremetal') {
        viewDocInline('STANDALONE_INSTALL.md');
    } else if (docType === 'ports') {
        viewDocInline('PORT_SPECIFICATIONS.md');
    } else if (docType === 'mitre') {
        viewDocInline('MITRE_ATTACK_GUIDE.md');
    } else {
        viewDocInline('HELP.md');
    }
}

// ==========================================
// Tenant Branding Logo Management (Settings)
// ==========================================
let selectedTenantLogoFile = null;

function openUploadTenantLogoModal(slug, name) {
    const modal = document.getElementById('modal-upload-tenant-logo');
    if (!modal) return;

    selectedTenantLogoFile = null;
    const slugInput = document.getElementById('upload-logo-tenant-slug');
    const subtitle = document.getElementById('modal-logo-tenant-subtitle');
    const preview = document.getElementById('upload-logo-preview');
    const fileInput = document.getElementById('upload-logo-input');
    const msg = document.getElementById('upload-logo-msg');

    const effectiveSlug = slug || 'default';
    if (slugInput) slugInput.value = effectiveSlug;
    if (subtitle) {
        const isRoot = (effectiveSlug === 'default');
        subtitle.textContent = isRoot 
            ? `${name || 'Default Organization'} (Root Kök Sistem Logosu)` 
            : `${name || effectiveSlug} (${effectiveSlug})`;
    }
    if (fileInput) fileInput.value = '';
    if (msg) { msg.style.display = 'none'; msg.textContent = ''; }

    if (preview) {
        preview.src = `/api/v1/tenants/logo?slug=${encodeURIComponent(effectiveSlug)}&t=${Date.now()}`;
    }

    modal.style.display = 'flex';
}

function closeUploadTenantLogoModal() {
    const modal = document.getElementById('modal-upload-tenant-logo');
    if (modal) modal.style.display = 'none';
    selectedTenantLogoFile = null;
}

function handleTenantLogoFileChange(event) {
    const file = event.target.files && event.target.files[0];
    const preview = document.getElementById('upload-logo-preview');
    const msg = document.getElementById('upload-logo-msg');

    if (!file) return;

    if (file.size > 5 * 1024 * 1024) {
        if (msg) {
            msg.style.display = 'block';
            msg.style.background = 'rgba(239, 68, 68, 0.15)';
            msg.style.color = '#f87171';
            msg.textContent = (window.i18n && window.i18n.t('err_file_too_large')) || 'Dosya boyutu 5 MB sınırını aşıyor.';
        }
        event.target.value = '';
        return;
    }

    selectedTenantLogoFile = file;
    if (msg) msg.style.display = 'none';

    // Live preview
    const reader = new FileReader();
    reader.onload = (e) => {
        if (preview) preview.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

async function submitTenantLogo() {
    const slugInput = document.getElementById('upload-logo-tenant-slug');
    const slug = slugInput ? slugInput.value : 'default';
    const msg = document.getElementById('upload-logo-msg');
    const saveBtn = document.getElementById('btn-submit-tenant-logo');

    if (!selectedTenantLogoFile) {
        if (msg) {
            msg.style.display = 'block';
            msg.style.background = 'rgba(239, 68, 68, 0.15)';
            msg.style.color = '#f87171';
            msg.textContent = (window.i18n && window.i18n.t('err_select_logo_file')) || 'Lütfen yüklenecek bir logo dosyası seçin.';
        }
        return;
    }

    const formData = new FormData();
    formData.append('slug', slug);
    formData.append('logo', selectedTenantLogoFile);

    try {
        if (saveBtn) {
            saveBtn.disabled = true;
            saveBtn.textContent = '...';
        }

        const res = await fetch(`/api/v1/tenants/logo?slug=${encodeURIComponent(slug)}`, {
            method: 'POST',
            body: formData
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Yükleme başarısız');

        showToast((window.i18n && window.i18n.t('toast_logo_updated')) || '✓ Marka logosu başarıyla güncellendi.', 'success');
        closeUploadTenantLogoModal();

        // Refresh views
        if (typeof loadTenants === 'function') loadTenants();
        updateSidebarBrandLogo(currentTenantContext);
    } catch (err) {
        if (msg) {
            msg.style.display = 'block';
            msg.style.background = 'rgba(239, 68, 68, 0.15)';
            msg.style.color = '#f87171';
            msg.textContent = err.message;
        }
    } finally {
        if (saveBtn) {
            saveBtn.disabled = false;
            saveBtn.textContent = (window.i18n && window.i18n.t('btn_upload_save_logo')) || 'Logoyu Kaydet';
        }
    }
}

async function resetTenantLogo() {
    const slugInput = document.getElementById('upload-logo-tenant-slug');
    const slug = slugInput ? slugInput.value : 'default';

    const confirmMsg = (window.i18n && window.i18n.t('confirm_reset_logo')) || 'Bu kiracının logosu sistem varsayılanına sıfırlansın mı?';
    if (!confirm(confirmMsg)) return;

    try {
        const res = await fetch(`/api/v1/tenants/logo?slug=${encodeURIComponent(slug)}`, {
            method: 'DELETE'
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Sıfırlama başarısız');

        showToast((window.i18n && window.i18n.t('toast_logo_reset')) || '✓ Logo varsayılan durumuna getirildi.', 'success');
        closeUploadTenantLogoModal();

        if (typeof loadTenants === 'function') loadTenants();
        updateSidebarBrandLogo(currentTenantContext);
    } catch (err) {
        showToast(err.message, 'error');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // Initial sync of sidebar brand logo
    updateSidebarBrandLogo(localStorage.getItem('active_tenant_slug') || 'default');

    // Endpoint Security search & filter bindings
    document.getElementById('btn-ep-agents-filter-apply')?.addEventListener('click', () => {
        loadEndpointAgents();
    });
    document.getElementById('ep-agents-search')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') loadEndpointAgents();
    });
    document.getElementById('ep-agents-os-filter')?.addEventListener('change', () => {
        loadEndpointAgents();
    });
    document.getElementById('ep-agents-status-filter')?.addEventListener('change', () => {
        loadEndpointAgents();
    });
});

// --- Endpoint Security UI Logic ---

let currentEndpointSection = 'endpoint-sec-dashboard';

function switchEndpointSubSection(targetId) {
    if (!targetId) targetId = 'endpoint-sec-dashboard';
    currentEndpointSection = targetId;

    document.querySelectorAll('.endpoint-section').forEach(sec => {
        sec.style.display = (sec.id === targetId) ? 'block' : 'none';
    });

    document.querySelectorAll('.endpoint-nav-btn').forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-target') === targetId);
    });

    document.querySelectorAll('#nav-submenu-endpoint .nav-subitem').forEach(sub => {
        sub.classList.toggle('active', sub.getAttribute('data-endpoint-target') === targetId);
    });

    // Translate any static labels in the newly visible section
    if (window.i18n && typeof window.i18n.applyTranslations === 'function') {
        window.i18n.applyTranslations();
    }

    if (targetId === 'endpoint-sec-agents') {
        loadEndpointAgents();
        if (typeof switchQuickPlatform === 'function') switchQuickPlatform(currentQuickPlatform);
    } else if (targetId === 'endpoint-sec-tokens') {
        loadEndpointTokens();
    } else if (targetId === 'endpoint-sec-dashboard') {
        loadEndpointDashboard();
    } else if (targetId === 'endpoint-sec-guide') {
        initEndpointGuide();
    } else if (targetId === 'endpoint-sec-inventory') {
        loadEndpointInventory();
    } else if (targetId === 'endpoint-sec-vulnerabilities') {
        loadCVEStatus();
        loadEndpointVulnerabilities();
    } else if (targetId === 'endpoint-sec-patches') {
        loadEndpointPatches();
    } else if (targetId === 'endpoint-sec-fim') {
        loadEndpointFIM();
    } else if (targetId === 'endpoint-sec-usb') {
        loadEndpointUSB();
    } else if (targetId === 'endpoint-sec-edr') {
        loadEndpointEDR();
    } else if (targetId === 'endpoint-sec-network') {
        loadEndpointNetwork();
    } else if (targetId === 'endpoint-sec-ransomware') {
        loadEndpointRansomware();
    } else if (targetId === 'endpoint-sec-policies') {
        loadEndpointPolicies();
    }
}

async function loadEndpointDashboard() {
    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/dashboard?tenant=${encodeURIComponent(tenant)}`);
        if (!res.ok) return;
        const data = await res.json();

        // Top Stat Cards
        document.getElementById('ep-stat-total-agents').textContent = (data.total_agents || 0).toLocaleString();
        document.getElementById('ep-stat-total-badge').textContent = (data.total_agents || 0);
        document.getElementById('ep-stat-online').textContent = data.online_agents || 0;
        document.getElementById('ep-stat-offline').textContent = data.offline_agents || 0;
        document.getElementById('ep-stat-stale').textContent = data.stale_agents || 0;

        document.getElementById('ep-stat-linux').textContent = data.linux_agents || 0;
        document.getElementById('ep-stat-windows').textContent = data.windows_agents || 0;
        document.getElementById('ep-stat-darwin').textContent = data.darwin_agents || 0;

        document.getElementById('ep-stat-crit-vulns').textContent = (data.critical_vulns || 0).toLocaleString();
        document.getElementById('ep-stat-crit-badge').textContent = `${data.critical_vulns || 0} CRIT`;
        document.getElementById('ep-stat-high-vulns').textContent = data.high_vulns || 0;
        document.getElementById('ep-stat-kev-vulns').textContent = data.cisa_kev_vulns || 0;

        const pct = (data.patch_compliance_pct != null) ? data.patch_compliance_pct.toFixed(1) : '100.0';
        document.getElementById('ep-stat-patch-comp').textContent = `%${pct}`;
        document.getElementById('ep-stat-comp-badge').textContent = `%${pct}`;
        document.getElementById('ep-stat-need-reboot').textContent = data.endpoints_need_reboot || 0;

        const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;

        // Render Top Vulnerable Agents
        const agentsTbody = document.getElementById('ep-dash-top-agents-body');
        if (agentsTbody) {
            if (!data.top_vulnerable_agents || data.top_vulnerable_agents.length === 0) {
                agentsTbody.innerHTML = `<tr><td colspan="4" class="text-center" style="color: var(--text-muted); padding: 20px;">${t('ep_no_top_risk_agents')}</td></tr>`;
            } else {
                agentsTbody.innerHTML = data.top_vulnerable_agents.map(a => `
                    <tr>
                        <td>
                            <strong>${escapeHtml(a.hostname || 'Unknown')}</strong>
                            <div style="font-size: 10.5px; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(a.ip_address || '')}</div>
                        </td>
                        <td>${renderOSBadge(a.os_type)}</td>
                        <td><span class="badge ${a.critical_count > 0 ? 'badge-danger' : 'badge-success'}">${a.critical_count}</span></td>
                        <td><span class="badge ${a.total_vulns > 0 ? 'badge-warning' : 'badge-secondary'}">${a.total_vulns}</span></td>
                    </tr>
                `).join('');
            }
        }

        // Render Top CVEs
        const cvesTbody = document.getElementById('ep-dash-top-cves-body');
        if (cvesTbody) {
            if (!data.top_cves || data.top_cves.length === 0) {
                cvesTbody.innerHTML = `<tr><td colspan="4" class="text-center" style="color: var(--text-muted); padding: 20px;">${t('ep_no_top_cves')}</td></tr>`;
            } else {
                cvesTbody.innerHTML = data.top_cves.map(c => `
                    <tr>
                        <td>
                            <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cve_id)}" target="_blank" rel="noopener" style="font-family: var(--font-mono); font-weight: 700; color: #ef4444; text-decoration: underline;">
                                ${escapeHtml(c.cve_id)}
                            </a>
                        </td>
                        <td><span class="badge ${c.cvss_score >= 9 ? 'badge-danger' : (c.cvss_score >= 7 ? 'badge-warning' : 'badge-info')}">${c.cvss_score ? c.cvss_score.toFixed(1) : '-'}</span></td>
                        <td>${c.cisa_kev ? '<span class="badge badge-danger" style="background: #9d174d;">KEV</span>' : '<span style="color: var(--text-muted);">-</span>'}</td>
                        <td>${c.affected_count} ${c.affected_count === 1 ? t('lbl_endpoint_single') : t('lbl_endpoint_plural')}</td>
                    </tr>
                `).join('');
            }
        }
    } catch (err) {
        console.error('Error loading endpoint dashboard:', err);
    }
}

async function loadEndpointAgents() {
    const tbody = document.getElementById('ep-agents-tbody');
    if (!tbody) return;

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const osType = document.getElementById('ep-agents-os-filter')?.value || '';
        const status = document.getElementById('ep-agents-status-filter')?.value || '';
        const search = document.getElementById('ep-agents-search')?.value || '';

        const url = `/api/v1/endpoint/agents?tenant=${encodeURIComponent(tenant)}&os=${encodeURIComponent(osType)}&status=${encodeURIComponent(status)}&search=${encodeURIComponent(search)}`;
        const res = await fetch(url);
        if (!res.ok) throw new Error('Ajanlar yüklenemedi');
        const data = await res.json();
        const agents = data.agents || [];

        const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
        if (agents.length === 0) {
            tbody.innerHTML = `<tr><td colspan="10" class="text-center" style="padding: 32px; color: var(--text-muted);">${t('ep_no_agents')}</td></tr>`;
            return;
        }

        tbody.innerHTML = agents.map(a => {
            const osBadge = renderOSBadge(a.os_type, a.os_name);
            const statusBadge = renderAgentStatusBadge(a.status, a.last_seen);
            const relativeTime = formatRelativeTime(a.last_seen);

            // Parse Hardware Telemetry
            let resUsage = {};
            try {
                if (typeof a.resource_usage === 'string') resUsage = JSON.parse(a.resource_usage);
                else if (a.resource_usage) resUsage = a.resource_usage;
            } catch(e) {}

            const cpuPct = (resUsage.cpu_percent != null) ? resUsage.cpu_percent.toFixed(1) : '0.0';
            let ramDisplay = '0%';
            if (resUsage.ram_percent != null && resUsage.ram_percent > 0) {
                ramDisplay = `${resUsage.ram_percent.toFixed(0)}%`;
            } else if (resUsage.ram_total_bytes > 0 && resUsage.ram_used_bytes > 0) {
                ramDisplay = `${Math.round((resUsage.ram_used_bytes / resUsage.ram_total_bytes) * 100)}%`;
            } else if (resUsage.ram_rss_bytes > 0) {
                ramDisplay = formatBytes(resUsage.ram_rss_bytes);
            }
            const diskPct = (resUsage.disk_percent != null && resUsage.disk_percent > 0) ? `${resUsage.disk_percent.toFixed(0)}%` : '0%';

            // Health Score badge
            const health = (a.health_score != null) ? a.health_score : 100;
            let healthBadge = `<span class="badge" style="background: rgba(16, 185, 129, 0.15); color: #10b981; font-weight: 700; border: 1px solid rgba(16, 185, 129, 0.3);">${health} / 100 🟢</span>`;
            if (health < 60) {
                healthBadge = `<span class="badge" style="background: rgba(239, 68, 68, 0.15); color: #ef4444; font-weight: 700; border: 1px solid rgba(239, 68, 68, 0.3);">${health} / 100 🔴</span>`;
            } else if (health < 80) {
                healthBadge = `<span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; font-weight: 700; border: 1px solid rgba(245, 158, 11, 0.3);">${health} / 100 🟡</span>`;
            }

            // Hardware telemetry pills
            const hwPills = `
                <div style="font-size: 11px; display: flex; flex-direction: column; gap: 2px;">
                    <div>CPU: <strong style="color: var(--accent);">${cpuPct}%</strong></div>
                    <div style="color: var(--text-muted);">RAM: <strong style="color: #3b82f6;">${ramDisplay}</strong> | Disk: <strong style="color: #10b981;">${diskPct}</strong></div>
                </div>
            `;

            // Version badge
            const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
            const agentVer = a.agent_version ? (a.agent_version.startsWith('v') ? a.agent_version : 'v' + a.agent_version) : 'v0.1.5';
            const verBadge = `<span class="badge badge-success" style="font-family: var(--font-mono); font-size: 10px;">${escapeHtml(agentVer)}</span>`;

            const critVulnBadge = a.critical_vulns_count > 0 
                ? `<span class="badge badge-danger" style="margin-right: 4px;">${a.critical_vulns_count} Crit</span>` 
                : '';
            const totalVulnBadge = a.open_vulns_count > 0
                ? `<span class="badge badge-secondary">${a.open_vulns_count} ${t('status_total')}</span>`
                : `<span style="color: var(--success); font-size: 11px;">${t('status_clean')}</span>`;
            const patchBadge = a.missing_patches_count > 0
                ? `<span class="badge badge-warning">${a.missing_patches_count} ${t('status_missing')}</span>`
                : `<span style="color: var(--success); font-size: 11px;">${t('status_updated')}</span>`;
            const rebootBadge = a.reboot_required
                ? `<span class="badge badge-warning" style="margin-left: 4px;" title="${t('status_reboot_pending')}">🔄 Reboot</span>`
                : '';

            const isolatedBadge = a.is_isolated
                ? `<span class="badge" style="background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); animation: pulse 2s infinite; font-weight: 700; font-size: 10px; margin-left: 6px;">🛡️ ${t('endpoint_isolated_badge')}</span>`
                : '';

            return `
                <tr>
                    <td>
                        <div style="font-weight: 600; display: flex; align-items: center; flex-wrap: wrap;">
                            <span>${escapeHtml(a.hostname || t('status_unknown'))}</span>
                            ${isolatedBadge}
                        </div>
                        <div style="font-size: 10.5px; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(a.ip_address || '-')} • ${escapeHtml(a.agent_uuid)}</div>
                    </td>
                    <td>${osBadge}</td>
                    <td>${verBadge}</td>
                    <td>${healthBadge}</td>
                    <td>${hwPills}</td>
                    <td>${statusBadge}</td>
                    <td>${critVulnBadge}${totalVulnBadge}</td>
                    <td>${patchBadge}${rebootBadge}</td>
                    <td style="font-size: 11.5px; color: var(--text-muted);">${relativeTime}</td>
                    <td style="white-space: nowrap;">
                        <button class="btn btn-sm btn-outline" onclick="inspectEndpointAgent('${a.id}')">${t('btn_inspect_agent')}</button>
                        <button class="btn btn-sm btn-outline" style="margin-left: 4px; color: #f59e0b; border-color: rgba(245, 158, 11, 0.4);" onclick="openActiveResponseModal('${a.id}', '${escapeHtml(a.hostname || a.ip_address)}', ${a.is_isolated ? 'true' : 'false'})" title="${t('endpoint_active_response_title')}">🛡️</button>
                        <button class="btn btn-sm btn-outline" style="margin-left: 4px;" onclick="openAssignPolicyModal('${a.agent_uuid}', '${escapeHtml(a.hostname || a.ip_address)}', '${a.policy_id || ''}')" title="${t('btn_assign_policy')}">📋</button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="10" class="text-center" style="padding: 24px; color: var(--danger);">${escapeHtml(err.message)}</td></tr>`;
    }
}

function renderOSBadge(osType, osName = '') {
    osType = (osType || '').toLowerCase();
    let icon = '💻';
    let label = osName || osType.toUpperCase();
    if (osType.includes('linux')) icon = '🐧';
    if (osType.includes('windows')) icon = '🪟';
    if (osType.includes('darwin') || osType.includes('mac')) icon = '🍏';

    return `<span title="${escapeHtml(label)}" style="display: inline-flex; align-items: center; gap: 4px;">
        <span style="font-size: 14px;">${icon}</span>
        <span style="font-size: 11.5px;">${escapeHtml(label.length > 20 ? label.substring(0, 18) + '...' : label)}</span>
    </span>`;
}

function renderAgentStatusBadge(status, lastSeen) {
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    status = (status || 'healthy').toLowerCase();
    
    // Dynamically evaluate connectivity via lastSeen
    if (lastSeen) {
        const diffSec = (Date.now() - new Date(lastSeen).getTime()) / 1000;
        if (diffSec > 900) { // > 15 minutes = Offline
            return `<span class="badge badge-secondary" style="display: inline-flex; align-items: center; gap: 4px;"><span class="live-dot" style="background: #64748b;"></span> ${t('ep_stat_offline')}</span>`;
        } else if (diffSec > 180) { // 3 to 15 minutes = Stale / Delayed
            return `<span class="badge badge-warning" style="display: inline-flex; align-items: center; gap: 4px;"><span class="live-dot" style="background: #f59e0b;"></span> ${t('ep_stat_stale')}</span>`;
        }
    } else {
        return `<span class="badge badge-secondary" style="display: inline-flex; align-items: center; gap: 4px;"><span class="live-dot" style="background: #64748b;"></span> ${t('ep_stat_offline')}</span>`;
    }

    if (status === 'healthy') {
        return `<span class="badge badge-success" style="display: inline-flex; align-items: center; gap: 4px;"><span class="live-dot" style="background: #22c55e;"></span> ${t('status_healthy')}</span>`;
    } else if (status === 'warning') {
        return `<span class="badge badge-warning" style="display: inline-flex; align-items: center; gap: 4px;"><span class="live-dot" style="background: #f59e0b;"></span> ${t('status_warning')}</span>`;
    } else {
        return `<span class="badge badge-secondary" style="display: inline-flex; align-items: center; gap: 4px;"><span class="live-dot" style="background: #64748b;"></span> ${t('ep_stat_offline')}</span>`;
    }
}

function formatDateTime(isoStr) {
    if (!isoStr) return '-';
    try {
        const d = new Date(isoStr);
        if (isNaN(d.getTime())) return String(isoStr);
        const lang = (window.i18n && window.i18n.currentLang === 'en') ? 'en-US' : 'tr-TR';
        return d.toLocaleString(lang);
    } catch (e) {
        return String(isoStr);
    }
}

function formatRelativeTime(dateStr) {
    const isEn = (window.i18n && window.i18n.currentLang === 'en');
    if (!dateStr) return isEn ? 'Never connected' : 'Hiç bağlanmadı';
    const diffMs = Date.now() - new Date(dateStr).getTime();
    const diffSec = Math.floor(diffMs / 1000);
    if (diffSec < 60) return isEn ? `${diffSec}s ago` : `${diffSec} sn önce`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return isEn ? `${diffMin}m ago` : `${diffMin} dk önce`;
    const diffHour = Math.floor(diffMin / 60);
    if (diffHour < 24) return isEn ? `${diffHour}h ago` : `${diffHour} sa önce`;
    const diffDay = Math.floor(diffHour / 24);
    return isEn ? `${diffDay}d ago` : `${diffDay} gün önce`;
}

async function loadEndpointTokens() {
    const tbody = document.getElementById('ep-tokens-tbody');
    if (!tbody) return;

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/enrollment/tokens?tenant=${encodeURIComponent(tenant)}`);
        if (!res.ok) throw new Error('Belirteçler yüklenemedi');
        const tokens = await res.json();
        const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;

        if (!tokens || tokens.length === 0) {
            tbody.innerHTML = `<tr><td colspan="9" class="text-center" style="padding: 24px; color: var(--text-muted);">${t('ep_no_tokens')}</td></tr>`;
            return;
        }

        tbody.innerHTML = tokens.map(tok => {
            const isRevoked = !!tok.revoked_at;
            const isExpired = tok.expires_at && new Date(tok.expires_at) < new Date();
            const isFullyUsed = tok.max_uses > 0 && tok.current_uses >= tok.max_uses;
            const isInactive = isRevoked || isExpired || isFullyUsed;

            let statusBadge = `<span class="badge badge-success">${t('status_active')}</span>`;
            if (isRevoked) statusBadge = `<span class="badge badge-danger">${t('status_revoked')}</span>`;
            else if (isExpired) statusBadge = `<span class="badge badge-secondary">${t('status_expired')}</span>`;
            else if (isFullyUsed) statusBadge = `<span class="badge badge-warning">${t('status_exhausted')}</span>`;

            const usesStr = `${tok.current_uses} / ${tok.max_uses > 0 ? tok.max_uses : '∞'}`;
            const platforms = (tok.allowed_os && tok.allowed_os.length > 0) ? tok.allowed_os.join(', ') : t('lbl_all_platforms');
            const expStr = tok.expires_at ? formatDateTime(tok.expires_at) : t('lbl_never_expires');

            return `
                <tr>
                    <td><strong>${escapeHtml(t.name)}</strong></td>
                    <td><code style="font-family: var(--font-mono); color: #86efac;">${escapeHtml(t.token_prefix)}...</code></td>
                    <td><span class="badge badge-secondary">${escapeHtml(t.tenant_slug)}</span></td>
                    <td>${usesStr}</td>
                    <td>${escapeHtml(platforms)}</td>
                    <td style="font-size: 11.5px; color: var(--text-muted);">${expStr}</td>
                    <td>${escapeHtml(t.created_by)}</td>
                    <td>${statusBadge}</td>
                    <td>
                        <div style="display: flex; gap: 6px; align-items: center;">
                            ${!isInactive ? `<button class="btn btn-sm btn-outline" style="color: var(--accent); border-color: rgba(59, 130, 246, 0.4); font-size: 11px;" onclick="openTokenInstallModal('${t.id}', '${escapeHtml(t.name)}', '${escapeHtml(t.token_prefix)}')" title="Kurulum Komutlarını Görüntüle">📋 Komut Al</button>` : ''}
                            ${!isRevoked ? `<button class="btn btn-sm btn-outline" style="color: var(--warning, #f59e0b); border-color: rgba(245, 158, 11, 0.4); font-size: 11px;" onclick="revokeEndpointToken('${t.id}')" title="Belirteci İptal Et">İptal Et</button>` : ''}
                            <button class="btn btn-sm btn-outline" style="color: var(--danger); border-color: rgba(239, 68, 68, 0.4); font-size: 11px;" onclick="deleteEndpointToken('${t.id}', '${escapeHtml(t.name)}')" title="Belirteci Kalıcı Olarak Sil">🗑️ Sil</button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        // Populate token selector in Guide if present
        const select = document.getElementById('guide-token-select');
        if (select && tokens) {
            const curVal = select.value;
            select.innerHTML = '<option value="<TOKEN>">-- Belirteç Seçiniz (Varsayılan Yer Tutucu) --</option>' + 
                tokens.filter(t => !t.revoked_at).map(t => `<option value="${escapeHtml(t.token_prefix)}...">🔑 ${escapeHtml(t.name)} (${escapeHtml(t.token_prefix)}...)</option>`).join('');
            if (curVal && curVal !== '<TOKEN>') select.value = curVal;
        }

        if (tokens && tokens.length > 0 && activeQuickToken === '<TOKEN>') {
            const firstActive = tokens.find(t => !t.revoked_at);
            if (firstActive) {
                activeQuickToken = `${firstActive.token_prefix}...`;
                switchQuickPlatform(currentQuickPlatform);
            }
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center" style="padding: 20px; color: var(--danger);">${escapeHtml(err.message)}</td></tr>`;
    }
}

function openNewTokenModal() {
    const modal = document.getElementById('modal-endpoint-new-token');
    if (!modal) return;
    const nameEl = document.getElementById('token-form-name');
    if (nameEl) nameEl.value = '';
    const maxUsesEl = document.getElementById('token-form-max-uses');
    if (maxUsesEl) maxUsesEl.value = '0';
    const expiresEl = document.getElementById('token-form-expires-h');
    if (expiresEl) expiresEl.value = '72';
    const oneTimeEl = document.getElementById('token-form-one-time');
    if (oneTimeEl) oneTimeEl.checked = false;
    const resBox = document.getElementById('token-result-container');
    if (resBox) resBox.style.display = 'none';
    modal.classList.add('active');
    modal.style.display = 'flex';
}

function closeNewTokenModal() {
    const modal = document.getElementById('modal-endpoint-new-token');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
}

async function submitCreateToken() {
    const name = (document.getElementById('token-form-name')?.value || '').trim();
    const maxUses = parseInt(document.getElementById('token-form-max-uses')?.value || '0', 10);
    const expiresInH = parseInt(document.getElementById('token-form-expires-h')?.value || '0', 10);
    const isOneTime = document.getElementById('token-form-one-time')?.checked || false;

    const btn = document.getElementById('btn-submit-create-token');
    if (btn) btn.disabled = true;

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/enrollment/tokens?tenant=${encodeURIComponent(tenant)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: name || 'Endpoint Enrollment Token',
                max_uses: maxUses,
                is_one_time: isOneTime,
                expires_in_hours: expiresInH,
            })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Belirteç oluşturulamadı');

        // Show token in result container
        const resBox = document.getElementById('token-result-container');
        const tokenVal = document.getElementById('token-result-val');
        if (resBox && tokenVal) {
            tokenVal.textContent = data.token;
            resBox.style.display = 'block';
        }

        // Update quick install commands on page with this token
        updateQuickInstallCommandTokens(data.token);

        showToast('✓ Belirteç başarıyla üretildi.', 'success');
        loadEndpointTokens();
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

function updateQuickInstallCommandTokens(token) {
    activeQuickToken = token;
    const host = window.location.origin;
    const linEl = document.getElementById('ep-code-linux');
    if (linEl) {
        linEl.textContent = `curl -sSL ${host}/static/scripts/install-agent.sh | sudo bash -s -- --token=${token} --server=${host}`;
    }
    const winEl = document.getElementById('ep-code-windows');
    if (winEl) {
        winEl.textContent = `iwr -useb ${host}/static/scripts/install-agent.ps1 | iex; Start-LoggerAgent -Token "${token}" -Server "${host}"`;
    }
    if (typeof switchQuickPlatform === 'function') {
        switchQuickPlatform(currentQuickPlatform);
    }
}

function copyTokenResult() {
    const val = document.getElementById('token-result-val')?.textContent;
    if (val) {
        navigator.clipboard.writeText(val);
        showToast('✓ Belirteç panoya kopyalandı.', 'success');
    }
}

function copyDeployCmd(elemId) {
    const val = document.getElementById(elemId)?.textContent;
    if (val) {
        navigator.clipboard.writeText(val);
        showToast('✓ Kurulum komutu panoya kopyalandı.', 'success');
    }
}

async function revokeEndpointToken(id) {
    if (!confirm('Bu kurulum belirtecini iptal etmek istediğinizden emin misiniz?')) return;
    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/enrollment/tokens/${encodeURIComponent(id)}?tenant=${encodeURIComponent(tenant)}`, {
            method: 'DELETE'
        });
        if (!res.ok) throw new Error('İptal işlemi başarısız');
        showToast('✓ Belirteç iptal edildi.', 'success');
        loadEndpointTokens();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function deleteEndpointToken(id, name) {
    if (!confirm(`"${name || 'Bu belirteç'}" kalıcı olarak silinecek. Onaylıyor musunuz?`)) return;
    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/enrollment/tokens/${encodeURIComponent(id)}?action=delete&tenant=${encodeURIComponent(tenant)}`, {
            method: 'DELETE'
        });
        if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            throw new Error(data.error || 'Silme işlemi başarısız');
        }
        showToast('✓ Belirteç kalıcı olarak silindi.', 'success');
        loadEndpointTokens();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function purgeInactiveEndpointTokens() {
    if (!confirm('Süresi dolmuş, iptal edilmiş veya limitine ulaşmış tüm pasif belirteçler kalıcı olarak silinecek. Onaylıyor musunuz?')) return;
    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/enrollment/tokens/purge-inactive?tenant=${encodeURIComponent(tenant)}`, {
            method: 'DELETE'
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || 'Pasif belirteçler temizlenemedi');
        showToast(`✓ ${data.count || 0} adet pasif belirteç başarıyla temizlendi.`, 'success');
        loadEndpointTokens();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function inspectEndpointAgent(agentId) {
    const modal = document.getElementById('modal-endpoint-agent-detail');
    if (!modal) return;

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/agents/${encodeURIComponent(agentId)}?tenant=${encodeURIComponent(tenant)}`);
        if (!res.ok) throw new Error('Ajan detayı alınamadı');
        const agent = await res.json();

        document.getElementById('agent-detail-hostname').textContent = agent.hostname || 'Uç Nokta';
        document.getElementById('agent-detail-uuid').textContent = `UUID: ${agent.agent_uuid} • Tenant: ${agent.tenant_slug}`;
        document.getElementById('detail-card-os').innerHTML = renderOSBadge(agent.os_type, agent.os_name);
        const cleanVer = agent.agent_version ? (agent.agent_version.startsWith('v') ? agent.agent_version : 'v' + agent.agent_version) : 'v0.1.5';
        document.getElementById('detail-card-ver').textContent = `${cleanVer} (${agent.architecture || 'amd64'})`;
        
        const health = agent.health_score != null ? agent.health_score : 100;
        document.getElementById('detail-card-health').textContent = `${health} / 100`;
        document.getElementById('detail-card-health').style.color = (health >= 80) ? '#10b981' : (health >= 60 ? '#f59e0b' : '#ef4444');

        document.getElementById('detail-card-policy').textContent = agent.policy_name || 'Default Balanced Policy';
        document.getElementById('detail-card-policy-rev').textContent = `Rev ${agent.policy_revision || 1}`;
        document.getElementById('detail-card-reboot').innerHTML = agent.reboot_required 
            ? '<span class="badge badge-danger">⚠️ Yeniden Başlatma Bekliyor</span>' 
            : '<span style="color: var(--success);">Gerekmiyor</span>';
        document.getElementById('detail-card-last-seen').textContent = formatRelativeTime(agent.last_seen);

        // Hardware Resource usage
        let resObj = {};
        if (agent.resource_usage) {
            resObj = (typeof agent.resource_usage === 'string') ? JSON.parse(agent.resource_usage) : agent.resource_usage;
        }

        const cpuPct = (resObj.cpu_percent != null) ? resObj.cpu_percent.toFixed(1) : '0.0';
        document.getElementById('detail-card-cpu-pct').textContent = `${cpuPct}%`;
        const cpuBar = document.getElementById('detail-card-cpu-bar');
        if (cpuBar) {
            cpuBar.style.width = `${Math.min(parseFloat(cpuPct), 100)}%`;
            cpuBar.style.background = (parseFloat(cpuPct) > 85) ? '#ef4444' : ((parseFloat(cpuPct) > 70) ? '#f59e0b' : 'var(--accent)');
        }

        const ramPct = (resObj.ram_percent != null) ? resObj.ram_percent.toFixed(0) : '0';
        document.getElementById('detail-card-ram-pct').textContent = `${ramPct}%`;
        const ramBar = document.getElementById('detail-card-ram-bar');
        if (ramBar) {
            ramBar.style.width = `${Math.min(parseFloat(ramPct), 100)}%`;
            ramBar.style.background = (parseFloat(ramPct) > 85) ? '#ef4444' : '#3b82f6';
        }
        if (resObj.ram_total_bytes > 0) {
            document.getElementById('detail-card-ram-details').textContent = `${formatBytes(resObj.ram_used_bytes)} / ${formatBytes(resObj.ram_total_bytes)}`;
        } else {
            document.getElementById('detail-card-ram-details').textContent = formatBytes(resObj.ram_rss_bytes || 0);
        }

        const diskPct = (resObj.disk_percent != null) ? resObj.disk_percent.toFixed(0) : '0';
        document.getElementById('detail-card-disk-pct').textContent = `${diskPct}%`;
        const diskBar = document.getElementById('detail-card-disk-bar');
        if (diskBar) {
            diskBar.style.width = `${Math.min(parseFloat(diskPct), 100)}%`;
            diskBar.style.background = (parseFloat(diskPct) > 85) ? '#ef4444' : '#10b981';
        }
        if (resObj.disk_total_bytes > 0) {
            document.getElementById('detail-card-disk-details').textContent = `${formatBytes(resObj.disk_used_bytes)} / ${formatBytes(resObj.disk_total_bytes)}`;
        } else {
            document.getElementById('detail-card-disk-details').textContent = '-';
        }

        if (resObj.uptime_seconds > 0) {
            const days = Math.floor(resObj.uptime_seconds / 86400);
            const hrs = Math.floor((resObj.uptime_seconds % 86400) / 3600);
            document.getElementById('detail-card-uptime').textContent = `${days} gün, ${hrs} saat`;
        } else {
            document.getElementById('detail-card-uptime').textContent = '-';
        }
        document.getElementById('detail-card-ram').textContent = formatBytes(resObj.ram_rss_bytes || 0);

        modal.classList.add('active');
        modal.style.display = 'flex';
    } catch (err) {
        showToast(err.message, 'error');
    }
}

function closeAgentDetailModal() {
    const modal = document.getElementById('modal-endpoint-agent-detail');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
}

// -----------------------------------------------------------------------------
// Endpoint Agent Installation Guide & Interactive Helpers
// -----------------------------------------------------------------------------

function initEndpointGuide() {
    const serverUrlInput = document.getElementById('guide-server-url');
    if (serverUrlInput && !serverUrlInput.value) {
        serverUrlInput.value = window.location.origin;
    }

    // Platform switcher tab buttons
    document.querySelectorAll('.ep-guide-tab-btn').forEach(btn => {
        btn.onclick = () => {
            const platform = btn.getAttribute('data-platform');
            document.querySelectorAll('.ep-guide-tab-btn').forEach(b => b.classList.toggle('active', b === btn));
            document.querySelectorAll('.ep-platform-pane').forEach(p => {
                p.style.display = (p.id === `ep-pane-${platform}`) ? 'block' : 'none';
            });
        };
    });

    const tokenSelect = document.getElementById('guide-token-select');
    if (tokenSelect) {
        tokenSelect.onchange = () => {
            if (tokenSelect.value) {
                activeQuickToken = tokenSelect.value;
                if (typeof switchQuickPlatform === 'function') switchQuickPlatform(currentQuickPlatform);
            }
            syncGuideCommands();
        };
    }
    if (serverUrlInput) {
        serverUrlInput.oninput = () => syncGuideCommands();
    }

    // Populate active tokens if empty
    loadEndpointTokens();
    syncGuideCommands();
}

function syncGuideCommands() {
    const serverUrl = (document.getElementById('guide-server-url')?.value || window.location.origin).replace(/\/$/, '');
    const token = document.getElementById('guide-token-select')?.value || '<TOKEN>';

    // Linux auto
    const linAuto = document.getElementById('code-linux-auto');
    if (linAuto) {
        linAuto.textContent = `curl -sSL ${serverUrl}/static/scripts/install-agent.sh | sudo bash -s -- --server "${serverUrl}" --token "${token}"`;
    }

    // Linux manual config
    const linCfg = document.getElementById('code-linux-config');
    if (linCfg) {
        linCfg.textContent = `sudo tee /etc/logger-agent/config.json > /dev/null << 'EOF'
{
  "server_url": "${serverUrl}",
  "enrollment_token": "${token}",
  "insecure_tls": false,
  "log_level": "info",
  "data_dir": "/opt/logger-agent/data",
  "heartbeat_interval_sec": 30,
  "identity_file": "/etc/logger-agent/identity.json"
}
EOF
sudo chmod 600 /etc/logger-agent/config.json`;
    }

    // Windows auto
    const winAuto = document.getElementById('code-win-auto');
    if (winAuto) {
        winAuto.textContent = `Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iwr -useb "${serverUrl}/static/scripts/install-agent.ps1" -OutFile "$env:TEMP\\install-agent.ps1"; & "$env:TEMP\\install-agent.ps1" -Server "${serverUrl}" -Token "${token}"`;
    }

    // Windows config
    const winCfg = document.getElementById('code-win-config');
    if (winCfg) {
        winCfg.textContent = `{
  "server_url": "${serverUrl}",
  "enrollment_token": "${token}",
  "insecure_tls": false,
  "log_level": "info",
  "data_dir": "C:\\\\Program Files\\\\LOGGER Agent\\\\data",
  "heartbeat_interval_sec": 30,
  "identity_file": "C:\\\\Program Files\\\\LOGGER Agent\\\\identity.json"
}`;
    }

    // macOS auto
    const macAuto = document.getElementById('code-mac-auto');
    if (macAuto) {
        macAuto.textContent = `curl -sSL ${serverUrl}/static/scripts/install-agent.sh | sudo bash -s -- --server "${serverUrl}" --token "${token}"`;
    }

    // Docker run
    const dockerRun = document.getElementById('code-docker-run');
    if (dockerRun) {
        dockerRun.textContent = `docker run -d \\
  --name logger-agent \\
  --restart unless-stopped \\
  --net=host \\
  --pid=host \\
  -v /etc/logger-agent:/etc/logger-agent \\
  -v /var/run/docker.sock:/var/run/docker.sock:ro \\
  logger-agent:latest \\
  -server "${serverUrl}" \\
  -token "${token}"`;
    }
}

function copyCodeFromBox(elemId) {
    const el = document.getElementById(elemId);
    if (!el) return;
    const text = el.textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('✓ Komut panoya kopyalandı.', 'success');
    }).catch(() => {
        showToast('Kopyalama başarısız oldu.', 'error');
    });
}

let activeModalToken = '<TOKEN>';

function openTokenInstallModal(tokenId, tokenName, tokenPrefix) {
    const modal = document.getElementById('modal-endpoint-token-install');
    if (!modal) return;

    activeModalToken = `${tokenPrefix}...`;
    document.getElementById('modal-token-install-title').textContent = `📋 Kurulum Komutları: ${tokenName}`;
    document.getElementById('modal-token-install-sub').textContent = `Önek: ${tokenPrefix}... • ID: ${tokenId}`;

    const serverUrlInput = document.getElementById('modal-token-server-url');
    if (serverUrlInput) {
        serverUrlInput.value = window.location.origin;
    }

    updateModalTokenCommands();
    modal.classList.add('active');
    modal.style.display = 'flex';
}

function closeTokenInstallModal() {
    const modal = document.getElementById('modal-endpoint-token-install');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
}

function updateModalTokenCommands() {
    const serverUrl = (document.getElementById('modal-token-server-url')?.value || window.location.origin).replace(/\/$/, '');
    const token = activeModalToken;

    const lin = document.getElementById('modal-token-cmd-linux');
    if (lin) lin.textContent = `curl -sSL ${serverUrl}/static/scripts/install-agent.sh | sudo bash -s -- --server "${serverUrl}" --token "${token}"`;

    const win = document.getElementById('modal-token-cmd-windows');
    if (win) win.textContent = `Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iwr -useb "${serverUrl}/static/scripts/install-agent.ps1" -OutFile "$env:TEMP\\install-agent.ps1"; & "$env:TEMP\\install-agent.ps1" -Server "${serverUrl}" -Token "${token}"`;

    const mac = document.getElementById('modal-token-cmd-macos');
    if (mac) mac.textContent = `curl -sSL ${serverUrl}/static/scripts/install-agent.sh | sudo bash -s -- --server "${serverUrl}" --token "${token}"`;

    const doc = document.getElementById('modal-token-cmd-docker');
    if (doc) doc.textContent = `docker run -d --name logger-agent --restart unless-stopped --net=host --pid=host -v /etc/logger-agent:/etc/logger-agent logger-agent:latest -server "${serverUrl}" -token "${token}"`;
}

// Quick 3-Step Agent Installation Banner Logic
let currentQuickPlatform = 'windows';
let activeQuickToken = '<TOKEN>';

function toggleQuickStepCard() {
    const card = document.getElementById('ep-quick-step-card');
    if (!card) return;
    const isHidden = card.style.display === 'none';
    card.style.display = isHidden ? 'block' : 'none';
    if (isHidden) {
        switchQuickPlatform(currentQuickPlatform);
    }
}

function switchQuickPlatform(platform) {
    currentQuickPlatform = platform || 'windows';

    // Update active state on platform switcher buttons
    document.querySelectorAll('.ep-quick-platform-btn').forEach(btn => {
        if (btn.getAttribute('data-quick-platform') === currentQuickPlatform) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    const isEn = (window.i18n && window.i18n.currentLang === 'en') || localStorage.getItem('logseal_lang') === 'en';
    const serverUrl = window.location.origin.replace(/\/$/, '');
    const token = activeQuickToken || '<TOKEN>';

    const s1Title = document.getElementById('quick-step1-title');
    const s1Desc = document.getElementById('quick-step1-desc');
    const s1Hint = document.getElementById('quick-step1-hint');
    const s2Title = document.getElementById('quick-step2-title');
    const s2Desc = document.getElementById('quick-step2-desc');
    const cmdBox = document.getElementById('quick-step-cmd-box');
    const s3Title = document.getElementById('quick-step3-title');
    const s3Sub = document.getElementById('quick-step3-sub');
    const verifyBox = document.getElementById('quick-step3-verify');
    const s3Desc = document.getElementById('quick-step3-desc');
    const installerBtn = document.getElementById('quick-step-installer-btn');
    const installerText = document.getElementById('quick-step-installer-text');

    if (currentQuickPlatform === 'windows') {
        if (installerBtn) {
            installerBtn.style.display = 'inline-flex';
            installerBtn.href = '/static/downloads/logger-agent-setup.exe';
            installerBtn.setAttribute('download', 'logger-agent-setup.exe');
            if (installerText) installerText.textContent = isEn ? '.exe Setup' : '.exe İndir';
        }

        if (s1Title) s1Title.textContent = isEn ? 'Open PowerShell as Administrator' : 'Yönetici PowerShell Açın';
        if (s1Desc) s1Desc.innerHTML = isEn ? 'Right-click the Windows Start button &gt; select <strong>Windows PowerShell (Admin)</strong> or <strong>Terminal (Admin)</strong>.' : 'Windows Başlat menüsüne sağ tıklayın &gt; <strong>Windows PowerShell (Yönetici)</strong> veya <strong>Terminal (Yönetici)</strong> seçeneğini çalıştırın.';
        if (s1Hint) s1Hint.textContent = isEn ? 'Privilege: Administrator' : 'Yetki: Administrator';

        if (s2Title) s2Title.textContent = isEn ? 'Copy & Run Command' : 'Komutu Kopyalayıp Çalıştırın';
        if (s2Desc) s2Desc.textContent = isEn ? 'Automatically installs to C:\\Program Files\\LOGGER Agent and registers the LoggerAgent Windows Service.' : 'Otomatik olarak C:\\Program Files\\LOGGER Agent dizinine kurulur ve LoggerAgent Windows Servisi başlatılır.';
        if (cmdBox) cmdBox.textContent = `Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iwr -useb "${serverUrl}/static/scripts/install-agent.ps1" -OutFile "$env:TEMP\\install-agent.ps1"; & "$env:TEMP\\install-agent.ps1" -Server "${serverUrl}" -Token "${token}"`;

        if (s3Title) s3Title.textContent = isEn ? 'Verify Status' : 'Durumu Doğrulayın';
        if (s3Sub) s3Sub.textContent = isEn ? 'Run the service verification command on the endpoint:' : 'Uç noktada servis kontrol komutunu çalıştırın:';
        if (verifyBox) verifyBox.textContent = 'Get-Service LoggerAgent';
        if (s3Desc) s3Desc.textContent = isEn ? '✓ Appears healthy (Online) in the table below.' : '✓ Aşağıdaki tabloda yeşil (Online) görünür.';
    } else if (currentQuickPlatform === 'macos') {
        if (installerBtn) {
            installerBtn.style.display = 'inline-flex';
            installerBtn.href = '/static/downloads/logger-agent-installer.dmg';
            installerBtn.setAttribute('download', 'logger-agent-installer.dmg');
            if (installerText) installerText.textContent = isEn ? '.dmg Installer' : '.dmg İndir';
        }

        if (s1Title) s1Title.textContent = isEn ? 'Open Terminal App' : 'Terminal Uygulamasını Açın';
        if (s1Desc) s1Desc.innerHTML = isEn ? 'Press Spotlight (Cmd + Space) and launch <strong>Terminal</strong> or iTerm2.' : 'Spotlight (Cmd + Boşluk) ile <strong>Terminal</strong> uygulamasını başlatın veya iTerm2 açın.';
        if (s1Hint) s1Hint.textContent = isEn ? 'Privilege: Sudo / Root' : 'Yetki: Sudo / Root';

        if (s2Title) s2Title.textContent = isEn ? 'Copy & Run Command' : 'Komutu Kopyalayıp Çalıştırın';
        if (s2Desc) s2Desc.textContent = isEn ? 'Automatically installs to /opt/logger-agent and starts the launchd daemon background service.' : 'Otomatik olarak /opt/logger-agent dizinine kurulur ve launchd Daemon servisi başlatılır.';
        if (cmdBox) cmdBox.textContent = `curl -sSL ${serverUrl}/static/scripts/install-agent.sh | sudo bash -s -- --server "${serverUrl}" --token "${token}"`;

        if (s3Title) s3Title.textContent = isEn ? 'Verify Status' : 'Durumu Doğrulayın';
        if (s3Sub) s3Sub.textContent = isEn ? 'Run the daemon check command in Terminal:' : 'Uç noktada daemon servis kontrol komutunu çalıştırın:';
        if (verifyBox) verifyBox.textContent = 'sudo launchctl list | grep logger';
        if (s3Desc) s3Desc.textContent = isEn ? '✓ Appears healthy (Online) in the table below.' : '✓ Aşağıdaki tabloda yeşil (Online) görünür.';
    } else if (currentQuickPlatform === 'linux') {
        if (installerBtn) {
            installerBtn.style.display = 'none';
        }

        if (s1Title) s1Title.textContent = isEn ? 'Open Root / Sudo Shell' : 'Kök / Sudo Terminali Açın';
        if (s1Desc) s1Desc.innerHTML = isEn ? 'Open a root shell or SSH into your Linux host with sudo privileges.' : 'Linux sunucu veya istemci konsoluna SSH yapın ya da terminal açın.';
        if (s1Hint) s1Hint.textContent = isEn ? 'Privilege: Root or sudo access' : 'Yetki: Root veya sudo ayrıcalığı';

        if (s2Title) s2Title.textContent = isEn ? 'Copy & Run Command' : 'Komutu Kopyalayıp Çalıştırın';
        if (s2Desc) s2Desc.textContent = isEn ? 'Automatically installs to /opt/logger-agent and starts the systemd logger-agent service.' : 'Otomatik olarak /opt/logger-agent dizinine kurulur ve systemd logger-agent servisi başlatılır.';
        if (cmdBox) cmdBox.textContent = `curl -sSL ${serverUrl}/static/scripts/install-agent.sh | sudo bash -s -- --server "${serverUrl}" --token "${token}"`;

        if (s3Title) s3Title.textContent = isEn ? 'Verify Status' : 'Durumu Doğrulayın';
        if (s3Sub) s3Sub.textContent = isEn ? 'Run the systemd service check command:' : 'Uç noktada systemd servis durumunu kontrol edin:';
        if (verifyBox) verifyBox.textContent = 'systemctl status logger-agent';
        if (s3Desc) s3Desc.textContent = isEn ? '✓ Appears healthy (Online) in the table below.' : '✓ Aşağıdaki tabloda yeşil (Online) görünür.';
    }
}

function copyQuickStepCmd() {
    const el = document.getElementById('quick-step-cmd-box');
    if (!el) return;
    const text = el.textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('✓ Komut panoya kopyalandı.', 'success');
    }).catch(() => {
        showToast('Kopyalama başarısız oldu.', 'error');
    });
}

// Global window aliases for Endpoint Security
window.switchEndpointSubSection = switchEndpointSubSection;
window.switchEndpointSubnav = switchEndpointSubSection;
window.openNewTokenModal = openNewTokenModal;
window.closeNewTokenModal = closeNewTokenModal;
window.closeAgentDetailModal = closeAgentDetailModal;
window.openTokenInstallModal = openTokenInstallModal;
window.closeTokenInstallModal = closeTokenInstallModal;
window.submitCreateToken = submitCreateToken;
window.inspectEndpointAgent = inspectEndpointAgent;
window.revokeEndpointToken = revokeEndpointToken;
window.loadEndpointInventory = loadEndpointInventory;
window.loadCVEStatus = loadCVEStatus;
window.saveCVESchedule = saveCVESchedule;
window.triggerCVESync = triggerCVESync;
window.loadEndpointVulnerabilities = loadEndpointVulnerabilities;
window.loadEndpointPatches = loadEndpointPatches;
window.triggerPatchScan = triggerPatchScan;
window.triggerAgentUpgradeAll = triggerAgentUpgradeAll;
window.cleanupDuplicateAgents = cleanupDuplicateAgents;

// --- Patch Management (Phase G) ---
async function loadEndpointPatches() {
    const tbody = document.getElementById('ep-patches-tbody');
    if (!tbody) return;

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const search = document.getElementById('ep-patches-search')?.value || '';
        const status = document.getElementById('ep-patches-status-filter')?.value || '';

        tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--text-muted); padding: 24px;">Yama kayıtları yükleniyor...</td></tr>`;

        let url = `/api/v1/endpoint/patches?tenant=${encodeURIComponent(tenant)}&search=${encodeURIComponent(search)}&limit=100`;
        if (status) url += `&status=${encodeURIComponent(status)}`;

        const res = await fetch(url);
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--accent-red); padding: 24px;">Yama verileri alınamadı (${res.status}).</td></tr>`;
            return;
        }

        const data = await res.json();
        const patches = data.patches || [];
        const summary = data.summary || {};

        // Update KPI Cards
        const compEl = document.getElementById('patch-stat-compliance');
        if (compEl) {
            const pct = (summary.compliance_pct != null) ? summary.compliance_pct.toFixed(1) : '100.0';
            compEl.textContent = `%${pct}`;
            compEl.style.color = (parseFloat(pct) >= 90) ? 'var(--success)' : (parseFloat(pct) >= 70 ? '#f59e0b' : '#ef4444');
        }

        const totalEl = document.getElementById('patch-stat-total');
        if (totalEl) totalEl.textContent = (summary.total_patches || patches.length).toLocaleString();

        const instEl = document.getElementById('patch-stat-installed');
        if (instEl) instEl.textContent = (summary.installed_count || 0).toLocaleString();

        const missEl = document.getElementById('patch-stat-missing');
        if (missEl) missEl.textContent = (summary.missing_count || 0).toLocaleString();

        const rebootEl = document.getElementById('patch-stat-reboot');
        if (rebootEl) rebootEl.textContent = (summary.endpoints_need_reboot || 0).toLocaleString();

        const countEl = document.getElementById('ep-patches-total-count');
        const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
        if (countEl) countEl.textContent = `${(data.total || patches.length).toLocaleString()} ${t('lbl_patch_count')}`;

        if (patches.length === 0) {
            tbody.innerHTML = `<tr><td colspan="9" class="text-center" style="color: var(--text-muted); padding: 28px;">${t('ep_no_patches')}</td></tr>`;
            return;
        }
        tbody.innerHTML = patches.map(p => {
            const isInstalled = (p.status === 'installed');
            const statusBadge = isInstalled
                ? `<span class="badge badge-success">🟢 ${t('patch_opt_installed')}</span>`
                : (p.status === 'pending_reboot' 
                    ? `<span class="badge badge-danger">🔄 ${t('patch_opt_reboot')}</span>` 
                    : `<span class="badge badge-warning">🟠 ${t('patch_opt_missing')}</span>`);

            const rebootBadge = p.requires_reboot
                ? `<span class="badge badge-danger" style="font-weight: 700;">${t('lbl_required')}</span>`
                : `<span style="color: var(--text-muted); font-size: 11px;">${t('lbl_no')}</span>`;

            const cves = (p.cve_ids && p.cve_ids.length > 0)
                ? p.cve_ids.map(c => `<span style="font-family: var(--font-mono); font-size: 10.5px; color: var(--accent); margin-right: 4px;">${escapeHtml(c)}</span>`).join('')
                : `<span style="color: var(--text-muted);">-</span>`;

            const patchTitle = (p.title && p.title.trim() && p.title !== '-')
                ? p.title
                : (`Security & Quality Update (${p.kb_id || p.patch_id})`);
            const patchVendor = (p.vendor && p.vendor.trim())
                ? p.vendor
                : (p.agent_os === 'windows' || (p.kb_id && p.kb_id.startsWith('KB')) || (p.patch_id && p.patch_id.startsWith('KB')) ? 'Microsoft Corporation' : 'System');

            let actionBtn = '';
            if (p.status === 'missing') {
                actionBtn = `<button class="btn btn-sm btn-primary" onclick="openDeployPatchModal('${escapeHtml(p.agent_id)}', '${escapeHtml(p.agent_hostname)}', '${escapeHtml(p.patch_id)}', '${escapeHtml(patchTitle)}', '${escapeHtml(p.agent_os || '')}')" style="font-size: 11px; padding: 4px 10px; font-weight: 600;"><i class="fas fa-satellite-dish"></i> ${t('btn_deploy_patch', 'Uzaktan Yama Yükle')}</button>`;
            } else if (p.status === 'pending_reboot') {
                actionBtn = `<button class="btn btn-sm btn-danger" onclick="rebootEndpoint('${escapeHtml(p.agent_id)}', '${escapeHtml(p.agent_hostname)}')" style="font-size: 11px; padding: 4px 10px; font-weight: 600;"><i class="fas fa-power-off"></i> ${t('btn_reboot_endpoint', 'Yeniden Başlat')}</button>`;
            } else {
                actionBtn = `
                    <div style="display: inline-flex; align-items: center; gap: 4px;">
                        <span class="badge badge-success" style="font-size: 11px; padding: 3px 6px;">✓ ${t('lbl_patched', 'Yüklü')}</span>
                        <button class="btn btn-sm btn-outline" onclick="openDeployPatchModal('${escapeHtml(p.agent_id)}', '${escapeHtml(p.agent_hostname)}', '${escapeHtml(p.patch_id)}', '${escapeHtml(patchTitle)}', '${escapeHtml(p.agent_os || '')}')" style="font-size: 10px; padding: 2px 6px;" title="${t('btn_redeploy_patch', 'Yeniden Uzaktan Yükle')}"><i class="fas fa-redo"></i></button>
                    </div>`;
            }

            return `
                <tr>
                    <td>
                        <div style="font-weight: 600;">${escapeHtml(p.agent_hostname || '-')}</div>
                        <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(p.agent_ip || '')}</div>
                    </td>
                    <td>
                        <strong style="font-family: var(--font-mono); color: var(--accent);">${escapeHtml(p.kb_id || p.patch_id)}</strong>
                    </td>
                    <td style="max-width: 320px; font-size: 12px; line-height: 1.4;">
                        <div style="font-weight: 600;">${escapeHtml(patchTitle)}</div>
                        <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(patchVendor)}</div>
                    </td>
                    <td>
                        <span class="badge" style="background: rgba(148, 163, 184, 0.2);">${escapeHtml(p.severity || 'UNKNOWN')}</span>
                    </td>
                    <td>${cves}</td>
                    <td>${statusBadge}</td>
                    <td>${rebootBadge}</td>
                    <td>
                        <span style="font-size: 11.5px; color: var(--text-muted);">
                            ${p.installed_at ? formatDateTime(p.installed_at) : (p.detected_at ? formatDateTime(p.detected_at) : '-')}
                        </span>
                    </td>
                    <td style="text-align: right; white-space: nowrap;">
                        ${actionBtn}
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        console.error('Error loading endpoint patches:', err);
        tbody.innerHTML = `<tr><td colspan="9" class="text-center" style="color: var(--accent-red); padding: 24px;">Bağlantı hatası: ${escapeHtml(err.message)}</td></tr>`;
    }
}

async function triggerPatchScan() {
    try {
        const res = await fetch('/api/v1/endpoint/patches/scan', { method: 'POST' });
        if (!res.ok) throw new Error('Yama taraması başlatılamadı');
        showToast('✓ Uç noktalara anlık yama tarama emri iletildi.', 'success');
        loadEndpointPatches();
    } catch (err) {
        showToast('Hata: ' + err.message, 'error');
    }
}

async function triggerAgentUpgradeAll() {
    if (!confirm('Tüm bağlı uç nokta ajanları en son sürüme (v0.1.3) otomatik olarak güncellenecek. Devam etmek istiyor musunuz?')) {
        return;
    }

    try {
        const res = await fetch('/api/v1/endpoint/agents/upgrade-all', { method: 'POST' });
        if (!res.ok) throw new Error('Ajan güncellemesi tetiklenemedi');
        const data = await res.json();
        showToast('🚀 ' + (data.message || 'Tüm ajanlar için otomatik güncelleme emri iletildi.'), 'success');
        loadEndpointAgents();
    } catch (err) {
        showToast('Hata: ' + err.message, 'error');
    }
}

async function cleanupDuplicateAgents() {
    if (!confirm('Aynı sunucu ve IP adresine ait eski ve pasif mükerrer ajan kayıtları birleştirilecek ve kaldırılacaktır. Devam etmek istiyor musunuz?')) {
        return;
    }

    try {
        const res = await fetch('/api/v1/endpoint/agents/cleanup-duplicates', { method: 'POST' });
        if (!res.ok) throw new Error('Mükerrer ajanlar temizlenemedi');
        const data = await res.json();
        showToast('🧹 ' + (data.message || 'Mükerrer ajanlar başarıyla birleştirildi.'), 'success');
        loadEndpointAgents();
        if (typeof loadEndpointOverview === 'function') loadEndpointOverview();
        if (typeof loadEndpointFIMSummary === 'function') loadEndpointFIMSummary();
    } catch (err) {
        showToast('Hata: ' + err.message, 'error');
    }
}


// --- Endpoint Software Inventory ---
async function loadEndpointInventory() {
    const tbody = document.getElementById('ep-inventory-tbody');
    if (!tbody) return;

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const search = document.getElementById('ep-inv-search')?.value || '';
        tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="color: var(--text-muted); padding: 24px;">Yazılım envanteri yükleniyor...</td></tr>`;

        const res = await fetch(`/api/v1/endpoint/inventory?tenant=${encodeURIComponent(tenant)}&search=${encodeURIComponent(search)}&limit=100`);
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="color: var(--accent-red); padding: 24px;">Envanter verisi alınamadı (${res.status}).</td></tr>`;
            return;
        }

        const data = await res.json();
        const items = data.software || [];
        const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
        const countEl = document.getElementById('ep-inv-total-count');
        if (countEl) countEl.textContent = `${(data.total || items.length).toLocaleString()} ${t('lbl_software_count')}`;

        if (items.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="color: var(--text-muted); padding: 28px;">${t('ep_no_inventory')}</td></tr>`;
            return;
        }

        tbody.innerHTML = items.map(item => `
            <tr>
                <td>
                    <div style="font-weight: 600;">${escapeHtml(item.agent_hostname || item.hostname || '-')}</div>
                    <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(item.agent_ip || item.ip_address || '')}</div>
                </td>
                <td>
                    <strong>${escapeHtml(item.name)}</strong>
                </td>
                <td>
                    <span style="font-family: var(--font-mono); font-size: 11.5px; background: rgba(59, 130, 246, 0.1); color: var(--accent); padding: 2px 6px; border-radius: 4px;">
                        ${escapeHtml(item.version || '-')}
                    </span>
                </td>
                <td>
                    <span style="color: var(--text-muted); font-size: 12px;">${escapeHtml(item.vendor || '-')}</span>
                </td>
                <td>
                    <span style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);" title="${escapeHtml(item.install_location || item.package_id || '')}">
                        ${escapeHtml(item.install_location || item.package_id || '-')}
                    </span>
                </td>
                <td>
                    <span style="font-size: 11.5px; color: var(--text-muted);">
                        ${item.last_seen ? formatDateTime(item.last_seen) : '-'}
                    </span>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        console.error('Error loading endpoint inventory:', err);
        tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="color: var(--accent-red); padding: 24px;">Bağlantı hatası: ${escapeHtml(err.message)}</td></tr>`;
    }
}

// --- CVE Intelligence Status & Scheduler ---
let cveSyncPollingInterval = null;

async function loadCVEStatus() {
    try {
        const res = await fetch('/api/v1/endpoint/cve/status');
        if (!res.ok) return;
        const data = await res.json();

        const totalEl = document.getElementById('cve-stat-total');
        if (totalEl) totalEl.textContent = (data.total_cves || 0).toLocaleString();

        const kevEl = document.getElementById('cve-stat-kev');
        if (kevEl) kevEl.textContent = (data.cisa_kev_count || 0).toLocaleString();

        const lastSyncEl = document.getElementById('cve-stat-last-sync');
        if (lastSyncEl) {
            lastSyncEl.textContent = data.last_sync ? formatDateTime(data.last_sync) : 'Henüz güncellenmedi';
        }

        const nextSyncEl = document.getElementById('cve-stat-next-sync');
        if (nextSyncEl) {
            if (data.schedule_mode === 'manual') {
                nextSyncEl.textContent = 'Otomatik Kapalı (Manuel)';
            } else if (data.next_sync) {
                nextSyncEl.textContent = formatDateTime(data.next_sync);
            } else {
                nextSyncEl.textContent = 'Planlanıyor';
            }
        }

        const schedSelect = document.getElementById('cve-schedule-select');
        if (schedSelect && data.schedule_mode) {
            schedSelect.value = data.schedule_mode;
        }

        // Syncing button state
        const syncBtn = document.getElementById('btn-cve-sync-now');
        const syncLabel = document.getElementById('cve-sync-label');
        const syncIcon = document.getElementById('cve-sync-icon');

        if (data.is_syncing) {
            if (syncBtn) syncBtn.disabled = true;
            if (syncLabel) syncLabel.textContent = 'CVE İndiriliyor & Analiz Ediliyor...';
            if (syncIcon) {
                syncIcon.textContent = '⏳';
                syncIcon.style.animation = 'spin 1.5s linear infinite';
            }
            if (!cveSyncPollingInterval) {
                cveSyncPollingInterval = setInterval(loadCVEStatus, 4000);
            }
        } else {
            if (syncBtn) syncBtn.disabled = false;
            if (syncLabel) syncLabel.textContent = 'CVE Veritabanını Şimdi Güncelle';
            if (syncIcon) {
                syncIcon.textContent = '🔄';
                syncIcon.style.animation = 'none';
            }
            if (cveSyncPollingInterval) {
                clearInterval(cveSyncPollingInterval);
                cveSyncPollingInterval = null;
                // Refresh vulnerabilities findings when sync completes
                loadEndpointVulnerabilities();
            }
        }
    } catch (err) {
        console.error('Error loading CVE status:', err);
    }
}

async function saveCVESchedule() {
    const sel = document.getElementById('cve-schedule-select');
    if (!sel) return;
    const mode = sel.value;

    try {
        const res = await fetch('/api/v1/endpoint/cve/schedule', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ schedule_mode: mode })
        });
        if (!res.ok) {
            const err = await res.json();
            showToast('Hata: ' + (err.error || 'Plan kaydedilemedi'), 'error');
            return;
        }
        showToast('✓ CVE otomatik güncelleme planı kaydedildi.', 'success');
        loadCVEStatus();
    } catch (err) {
        console.error('Error saving CVE schedule:', err);
        showToast('Bağlantı hatası: ' + err.message, 'error');
    }
}

async function triggerCVESync() {
    const syncBtn = document.getElementById('btn-cve-sync-now');
    const syncLabel = document.getElementById('cve-sync-label');
    const syncIcon = document.getElementById('cve-sync-icon');

    if (syncBtn) syncBtn.disabled = true;
    if (syncLabel) syncLabel.textContent = 'Senkronizasyon Başlatılıyor...';
    if (syncIcon) syncIcon.textContent = '⏳';

    try {
        const res = await fetch('/api/v1/endpoint/cve/sync', { method: 'POST' });
        if (!res.ok) {
            const err = await res.json();
            showToast('Hata: ' + (err.error || 'Güncelleme başlatılamadı'), 'error');
            if (syncBtn) syncBtn.disabled = false;
            return;
        }

        showToast('✓ CISA KEV ve CVE veritabanı senkronizasyonu başlatıldı.', 'success');
        loadCVEStatus();
    } catch (err) {
        console.error('Error triggering CVE sync:', err);
        showToast('Bağlantı hatası: ' + err.message, 'error');
        if (syncBtn) syncBtn.disabled = false;
    }
}

// --- Vulnerability Findings Table ---
async function loadEndpointVulnerabilities() {
    const tbody = document.getElementById('ep-vulns-tbody');
    if (!tbody) return;

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const search = document.getElementById('ep-vuln-search')?.value || '';
        const severity = document.getElementById('ep-vuln-severity-filter')?.value || '';

        tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--text-muted); padding: 24px;">Zafiyet tespitleri taranıyor...</td></tr>`;

        let url = `/api/v1/endpoint/vulnerabilities?tenant=${encodeURIComponent(tenant)}&search=${encodeURIComponent(search)}&limit=100`;
        if (severity) url += `&severity=${encodeURIComponent(severity)}`;

        const res = await fetch(url);
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--accent-red); padding: 24px;">Zafiyet verileri alınamadı (${res.status}).</td></tr>`;
            return;
        }

        const data = await res.json();
        const findings = data.findings || [];
        const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
        const countEl = document.getElementById('ep-vulns-total-count');
        if (countEl) countEl.textContent = `${(data.total || findings.length).toLocaleString()} ${t('lbl_vuln_count')}`;

        if (findings.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--text-muted); padding: 28px;">
                ${t('ep_no_vulns')}
            </td></tr>`;
            return;
        }

        tbody.innerHTML = findings.map(f => {
            let sevBadge = `<span class="badge" style="background: rgba(148, 163, 184, 0.2); color: #94a3b8;">${escapeHtml(f.severity)}</span>`;
            if (f.severity === 'CRITICAL') {
                sevBadge = `<span class="badge" style="background: #991b1b; color: #fff; font-weight: 700;">${t('lbl_crit_badge')}</span>`;
            } else if (f.severity === 'HIGH') {
                sevBadge = `<span class="badge" style="background: #ea580c; color: #fff; font-weight: 600;">${t('lbl_high_badge')}</span>`;
            } else if (f.severity === 'MEDIUM') {
                sevBadge = `<span class="badge" style="background: #ca8a04; color: #fff;">${t('lbl_medium_badge')}</span>`;
            } else if (f.severity === 'LOW') {
                sevBadge = `<span class="badge" style="background: #2563eb; color: #fff;">${t('lbl_low_badge')}</span>`;
            }

            const cvssScore = (f.cvss_score != null) ? f.cvss_score.toFixed(1) : '-';
            const kevBadge = f.is_exploited ?
                `<span class="badge" style="background: #b91c1c; color: #fff; font-weight: 700;" title="CISA Known Exploited Vulnerability">${t('lbl_kev_badge')}</span>` :
                `<span style="color: var(--text-muted); font-size: 11px;">-</span>`;

            return `
                <tr>
                    <td>
                        <div style="font-weight: 600;">${escapeHtml(f.agent_hostname || f.hostname || '-')}</div>
                        <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(f.agent_ip || f.ip_address || '')}</div>
                    </td>
                    <td>
                        <strong>${escapeHtml(f.software_name || '-')}</strong>
                        <div style="font-size: 11px; font-family: var(--font-mono); color: var(--accent);">${escapeHtml(f.detected_version || f.installed_version || '-')}</div>
                    </td>
                    <td>
                        <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.cve_id)}" target="_blank" rel="noopener" style="font-family: var(--font-mono); font-weight: 700; color: #ef4444; text-decoration: underline;">
                            ${escapeHtml(f.cve_id)}
                        </a>
                    </td>
                    <td>
                        <span style="font-family: var(--font-mono); font-weight: 700; font-size: 12.5px;">${cvssScore}</span>
                    </td>
                    <td>${sevBadge}</td>
                    <td>${kevBadge}</td>
                    <td style="max-width: 300px; font-size: 11.5px; line-height: 1.4; color: var(--text-muted);">
                        ${escapeHtml(f.title || f.cve_title || f.remediation || '-')}
                    </td>
                    <td>
                        <span style="font-size: 11.5px; color: var(--text-muted);">
                            ${f.first_detected ? formatDateTime(f.first_detected) : '-'}
                        </span>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        console.error('Error loading endpoint vulnerabilities:', err);
        tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--accent-red); padding: 24px;">Bağlantı hatası: ${escapeHtml(err.message)}</td></tr>`;
    }
}

// --- Endpoint Policy Management Suite ---

let currentEndpointPolicies = [];

async function loadEndpointPolicies() {
    const tbody = document.getElementById('ep-policies-tbody');
    if (!tbody) return;

    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/policies?tenant=${encodeURIComponent(tenant)}`);
        if (!res.ok) throw new Error('İlkeler yüklenemedi');
        const data = await res.json();
        const policies = data.policies || [];
        currentEndpointPolicies = policies;

        // Update Stat Cards
        const totalEl = document.getElementById('ep-stat-total-policies');
        const defaultEl = document.getElementById('ep-stat-default-policy');
        const governedEl = document.getElementById('ep-stat-governed-agents');

        if (totalEl) totalEl.textContent = policies.length;

        let defaultPolicy = policies.find(p => p.is_default);
        if (defaultEl) {
            defaultEl.textContent = defaultPolicy ? defaultPolicy.name : '-';
            defaultEl.title = defaultPolicy ? defaultPolicy.name : '';
        }

        let totalGoverned = policies.reduce((acc, p) => acc + (p.agent_count || 0), 0);
        if (governedEl) governedEl.textContent = totalGoverned;

        if (policies.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="padding: 32px; color: var(--text-muted);">${t('ep_no_policies')}</td></tr>`;
            return;
        }

        tbody.innerHTML = policies.map(p => {
            const cfg = p.policy_config || (typeof p.config === 'object' ? p.config : {});
            const isDef = p.is_default;
            const defBadge = isDef 
                ? `<span class="badge badge-success" style="font-size: 10px; margin-left: 6px;">${t('badge_default_policy')}</span>` 
                : '';

            const hbSec = cfg.heartbeat_interval_sec || 30;
            const invSec = cfg.inventory_interval_sec || 3600;
            const patchSec = cfg.patch_scan_interval_sec || 14400;

            const intervalsHtml = `
                <div style="font-size: 11.5px; line-height: 1.4;">
                    <div>HB: <strong style="color: var(--accent);">${hbSec}s</strong> | Inv: <strong>${Math.round(invSec / 60)}m</strong></div>
                    <div style="color: var(--text-muted); font-size: 10.5px;">Patch/CVE: <strong>${Math.round(patchSec / 3600)}h</strong></div>
                </div>
            `;

            const maxCpu = cfg.max_cpu_percent || 10;
            const maxRam = cfg.max_ram_mb || 150;
            const spoolDisk = cfg.spool_max_disk_mb || 500;

            const limitsHtml = `
                <div style="font-size: 11.5px; line-height: 1.4;">
                    <div>CPU: <strong style="color: var(--accent);">${maxCpu}%</strong> | RAM: <strong style="color: #3b82f6;">${maxRam} MB</strong></div>
                    <div style="color: var(--text-muted); font-size: 10.5px;">Spool: <strong>${spoolDisk} MB</strong> (${cfg.spool_max_age_hours || 72}h)</div>
                </div>
            `;

            const channels = (cfg.event_channels && cfg.event_channels.length > 0)
                ? cfg.event_channels.map(c => `<span class="badge badge-secondary" style="font-size: 10px; font-family: var(--font-mono); margin: 1px;">${escapeHtml(c)}</span>`).join(' ')
                : `<span style="color: var(--text-muted); font-size: 11px;">Default</span>`;

            const logCollectionStatus = cfg.log_collection_enabled !== false
                ? `<div>${channels}</div>`
                : `<div style="color: var(--danger); font-size: 11px;">❌ Disabled</div>`;

            const fleetCount = p.agent_count || 0;
            const fleetBadge = `<span class="badge" style="background: rgba(139, 92, 246, 0.15); color: #a78bfa; font-weight: 700; border: 1px solid rgba(139, 92, 246, 0.3); font-size: 11px;">${fleetCount} ${t('lbl_endpoint_single')}</span>`;

            const revBadge = `<span class="badge badge-outline" style="font-family: var(--font-mono); font-size: 10.5px;">r${p.revision}</span>`;

            const actionsHtml = `
                <div style="display: flex; gap: 4px;">
                    <button class="btn btn-sm btn-outline" onclick="openEditPolicyModal('${p.id}')" title="Düzenle">✏️</button>
                    ${!isDef ? `<button class="btn btn-sm btn-outline" style="color: var(--danger); border-color: rgba(239, 68, 68, 0.4);" onclick="deleteEndpointPolicy('${p.id}', '${escapeHtml(p.name)}')" title="Sil">🗑️</button>` : ''}
                </div>
            `;

            return `
                <tr>
                    <td>
                        <div style="font-weight: 600; display: flex; align-items: center;">
                            <span>${escapeHtml(p.name)}</span>
                            ${defBadge}
                        </div>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px; max-width: 260px;">${escapeHtml(p.description || '-')}</div>
                    </td>
                    <td>
                        <span class="badge badge-outline" style="font-size: 10.5px; font-family: var(--font-mono);">${escapeHtml(p.tenant_slug || 'default')}</span>
                    </td>
                    <td>${intervalsHtml}</td>
                    <td>${limitsHtml}</td>
                    <td>${logCollectionStatus}</td>
                    <td>${fleetBadge}</td>
                    <td>${revBadge}</td>
                    <td>${actionsHtml}</td>
                </tr>
            `;
        }).join('');

    } catch (err) {
        console.error('Error loading policies:', err);
        tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--danger); padding: 24px;">Bağlantı hatası: ${escapeHtml(err.message)}</td></tr>`;
    }
}

function openCreatePolicyModal() {
    document.getElementById('policy-form-id').value = '';
    document.getElementById('policy-form-name').value = '';
    document.getElementById('policy-form-desc').value = '';
    document.getElementById('policy-form-default').checked = false;
    document.getElementById('policy-form-heartbeat').value = 30;
    document.getElementById('policy-form-inventory').value = 3600;
    document.getElementById('policy-form-patch-scan').value = 14400;
    document.getElementById('policy-form-vuln-scan').value = 14400;
    document.getElementById('policy-form-cpu').value = 10;
    document.getElementById('policy-form-ram').value = 150;
    document.getElementById('policy-form-spool-disk').value = 500;
    document.getElementById('policy-form-spool-age').value = 72;
    document.getElementById('policy-form-log-enabled').checked = true;
    document.getElementById('policy-form-channels').value = 'System, Application, Security';
    document.getElementById('policy-form-channel').value = 'stable';
    if (document.getElementById('policy-form-usb-enabled')) document.getElementById('policy-form-usb-enabled').checked = true;
    if (document.getElementById('policy-form-usb-storage-mode')) document.getElementById('policy-form-usb-storage-mode').value = 'allow';
    if (document.getElementById('policy-form-usb-interval')) document.getElementById('policy-form-usb-interval').value = 30;
    if (document.getElementById('policy-form-usb-whitelist')) document.getElementById('policy-form-usb-whitelist').checked = false;
    if (document.getElementById('policy-form-usb-alert')) document.getElementById('policy-form-usb-alert').checked = true;
    if (document.getElementById('policy-form-edr-enabled')) document.getElementById('policy-form-edr-enabled').checked = true;
    if (document.getElementById('policy-form-edr-kill-critical')) document.getElementById('policy-form-edr-kill-critical').checked = true;
    if (document.getElementById('policy-form-edr-monitor-scripts')) document.getElementById('policy-form-edr-monitor-scripts').checked = true;
    if (document.getElementById('policy-form-edr-block-lolbins')) document.getElementById('policy-form-edr-block-lolbins').checked = true;
    if (document.getElementById('policy-form-edr-interval')) document.getElementById('policy-form-edr-interval').value = 15;
    if (document.getElementById('policy-form-edr-threshold')) document.getElementById('policy-form-edr-threshold').value = 'MEDIUM';

    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const titleEl = document.getElementById('modal-policy-title');
    if (titleEl) titleEl.textContent = t('btn_new_policy');

    const modal = document.getElementById('modal-endpoint-policy');
    if (modal) modal.style.display = 'flex';
}

function openEditPolicyModal(policyId) {
    const policy = currentEndpointPolicies.find(p => p.id === policyId);
    if (!policy) return;

    const cfg = policy.policy_config || (typeof policy.config === 'object' ? policy.config : {});

    document.getElementById('policy-form-id').value = policy.id;
    document.getElementById('policy-form-name').value = policy.name || '';
    document.getElementById('policy-form-desc').value = policy.description || '';
    document.getElementById('policy-form-default').checked = !!policy.is_default;
    document.getElementById('policy-form-heartbeat').value = cfg.heartbeat_interval_sec || 30;
    document.getElementById('policy-form-inventory').value = cfg.inventory_interval_sec || 3600;
    document.getElementById('policy-form-patch-scan').value = cfg.patch_scan_interval_sec || 14400;
    document.getElementById('policy-form-vuln-scan').value = cfg.vuln_scan_interval_sec || 14400;
    document.getElementById('policy-form-cpu').value = cfg.max_cpu_percent || 10;
    document.getElementById('policy-form-ram').value = cfg.max_ram_mb || 150;
    document.getElementById('policy-form-spool-disk').value = cfg.spool_max_disk_mb || 500;
    document.getElementById('policy-form-spool-age').value = cfg.spool_max_age_hours || 72;
    document.getElementById('policy-form-log-enabled').checked = cfg.log_collection_enabled !== false;
    document.getElementById('policy-form-channels').value = (cfg.event_channels && cfg.event_channels.length > 0) ? cfg.event_channels.join(', ') : 'System, Application, Security';
    document.getElementById('policy-form-channel').value = cfg.update_channel || 'stable';
    if (document.getElementById('policy-form-usb-enabled')) document.getElementById('policy-form-usb-enabled').checked = cfg.usb_control_enabled !== false;
    if (document.getElementById('policy-form-usb-storage-mode')) document.getElementById('policy-form-usb-storage-mode').value = cfg.usb_storage_mode || 'allow';
    if (document.getElementById('policy-form-usb-interval')) document.getElementById('policy-form-usb-interval').value = cfg.usb_scan_interval_sec || 30;
    if (document.getElementById('policy-form-usb-whitelist')) document.getElementById('policy-form-usb-whitelist').checked = !!cfg.usb_enforce_whitelist;
    if (document.getElementById('policy-form-usb-alert')) document.getElementById('policy-form-usb-alert').checked = cfg.usb_alert_on_insertion !== false;
    if (document.getElementById('policy-form-edr-enabled')) document.getElementById('policy-form-edr-enabled').checked = cfg.edr_behavior_enabled !== false;
    if (document.getElementById('policy-form-edr-kill-critical')) document.getElementById('policy-form-edr-kill-critical').checked = cfg.edr_kill_on_critical !== false;
    if (document.getElementById('policy-form-edr-monitor-scripts')) document.getElementById('policy-form-edr-monitor-scripts').checked = cfg.edr_monitor_script_engines !== false;
    if (document.getElementById('policy-form-edr-block-lolbins')) document.getElementById('policy-form-edr-block-lolbins').checked = cfg.edr_block_lolbins !== false;
    if (document.getElementById('policy-form-edr-interval')) document.getElementById('policy-form-edr-interval').value = cfg.edr_scan_interval_sec || 15;
    if (document.getElementById('policy-form-edr-threshold')) document.getElementById('policy-form-edr-threshold').value = cfg.edr_severity_threshold || 'MEDIUM';

    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const titleEl = document.getElementById('modal-policy-title');
    if (titleEl) titleEl.textContent = `${t('modal_policy_title')} (r${policy.revision})`;

    const modal = document.getElementById('modal-endpoint-policy');
    if (modal) modal.style.display = 'flex';
}

function closePolicyModal() {
    const modal = document.getElementById('modal-endpoint-policy');
    if (modal) modal.style.display = 'none';
}

async function savePolicyModal() {
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const id = document.getElementById('policy-form-id').value;
    const name = document.getElementById('policy-form-name').value.trim();
    if (!name) {
        alert(t('lbl_policy_name'));
        return;
    }

    const desc = document.getElementById('policy-form-desc').value.trim();
    const isDefault = document.getElementById('policy-form-default').checked;

    const channelsRaw = document.getElementById('policy-form-channels').value;
    const channels = channelsRaw.split(',').map(s => s.trim()).filter(s => s.length > 0);

    const payload = {
        name: name,
        description: desc,
        is_default: isDefault,
        config: {
            heartbeat_interval_sec: parseInt(document.getElementById('policy-form-heartbeat').value) || 30,
            inventory_interval_sec: parseInt(document.getElementById('policy-form-inventory').value) || 3600,
            patch_scan_interval_sec: parseInt(document.getElementById('policy-form-patch-scan').value) || 14400,
            vuln_scan_interval_sec: parseInt(document.getElementById('policy-form-vuln-scan').value) || 14400,
            max_cpu_percent: parseInt(document.getElementById('policy-form-cpu').value) || 10,
            max_ram_mb: parseInt(document.getElementById('policy-form-ram').value) || 150,
            spool_max_disk_mb: parseInt(document.getElementById('policy-form-spool-disk').value) || 500,
            spool_max_age_hours: parseInt(document.getElementById('policy-form-spool-age').value) || 72,
            log_collection_enabled: document.getElementById('policy-form-log-enabled').checked,
            event_channels: channels,
            update_channel: document.getElementById('policy-form-channel').value || 'stable',
            usb_control_enabled: document.getElementById('policy-form-usb-enabled')?.checked !== false,
            usb_storage_mode: document.getElementById('policy-form-usb-storage-mode')?.value || 'allow',
            usb_scan_interval_sec: parseInt(document.getElementById('policy-form-usb-interval')?.value) || 30,
            usb_enforce_whitelist: !!document.getElementById('policy-form-usb-whitelist')?.checked,
            usb_alert_on_insertion: document.getElementById('policy-form-usb-alert')?.checked !== false,
            edr_behavior_enabled: document.getElementById('policy-form-edr-enabled')?.checked !== false,
            edr_kill_on_critical: document.getElementById('policy-form-edr-kill-critical')?.checked !== false,
            edr_monitor_script_engines: document.getElementById('policy-form-edr-monitor-scripts')?.checked !== false,
            edr_block_lolbins: document.getElementById('policy-form-edr-block-lolbins')?.checked !== false,
            edr_scan_interval_sec: parseInt(document.getElementById('policy-form-edr-interval')?.value) || 15,
            edr_severity_threshold: document.getElementById('policy-form-edr-threshold')?.value || 'MEDIUM'
        }
    };

    try {
        const url = id ? `/api/v1/endpoint/policies/${encodeURIComponent(id)}` : '/api/v1/endpoint/policies';
        const method = id ? 'PUT' : 'POST';

        const res = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || 'İlke kaydedilemedi');
        }

        closePolicyModal();
        await loadEndpointPolicies();
        if (typeof showNotification === 'function') {
            showNotification(t('msg_policy_saved'), 'success');
        }
    } catch (err) {
        alert('Hata: ' + err.message);
    }
}

async function deleteEndpointPolicy(policyId, policyName) {
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    if (!confirm(`${t('confirm_delete_policy')}\n\n"${policyName}"`)) return;

    try {
        const res = await fetch(`/api/v1/endpoint/policies/${encodeURIComponent(policyId)}`, {
            method: 'DELETE'
        });
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || 'İlke silinemedi');
        }
        await loadEndpointPolicies();
        if (typeof showNotification === 'function') {
            showNotification(t('msg_policy_deleted'), 'success');
        }
    } catch (err) {
        alert('Hata: ' + err.message);
    }
}

async function openAssignPolicyModal(agentUUID, hostname, currentPolicyId) {
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    document.getElementById('assign-agent-uuid').value = agentUUID;
    const nameEl = document.getElementById('modal-assign-agent-name');
    if (nameEl) nameEl.textContent = `${t('lbl_endpoint_single')}: ${hostname} (${agentUUID})`;

    const select = document.getElementById('assign-policy-select');
    if (!select) return;

    // Fetch policies if not loaded
    if (currentEndpointPolicies.length === 0) {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/policies?tenant=${encodeURIComponent(tenant)}`);
        if (res.ok) {
            const data = await res.json();
            currentEndpointPolicies = data.policies || [];
        }
    }

    select.innerHTML = currentEndpointPolicies.map(p => {
        const isSelected = (p.id === currentPolicyId || (p.is_default && !currentPolicyId));
        return `<option value="${p.id}" ${isSelected ? 'selected' : ''}>${escapeHtml(p.name)} ${p.is_default ? `(${t('badge_default_policy')})` : ''} - r${p.revision}</option>`;
    }).join('');

    const modal = document.getElementById('modal-endpoint-assign-policy');
    if (modal) modal.style.display = 'flex';
}

function closeAssignPolicyModal() {
    const modal = document.getElementById('modal-endpoint-assign-policy');
    if (modal) modal.style.display = 'none';
}

async function submitAssignPolicy() {
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const agentUUID = document.getElementById('assign-agent-uuid').value;
    const policyID = document.getElementById('assign-policy-select').value;

    if (!agentUUID || !policyID) return;

    try {
        const res = await fetch('/api/v1/endpoint/policies/assign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ agent_uuid: agentUUID, policy_id: policyID })
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || 'İlke atanamadı');
        }

        closeAssignPolicyModal();
        if (typeof showNotification === 'function') {
            showNotification(t('msg_policy_assigned'), 'success');
        }
        if (typeof loadEndpointAgents === 'function') loadEndpointAgents();
        if (typeof loadEndpointPolicies === 'function') loadEndpointPolicies();
    } catch (err) {
        alert('Hata: ' + err.message);
    }
}

// Window exports
window.loadEndpointPolicies = loadEndpointPolicies;
window.openCreatePolicyModal = openCreatePolicyModal;
window.openEditPolicyModal = openEditPolicyModal;
window.closePolicyModal = closePolicyModal;
window.savePolicyModal = savePolicyModal;
window.deleteEndpointPolicy = deleteEndpointPolicy;
window.openAssignPolicyModal = openAssignPolicyModal;
window.closeAssignPolicyModal = closeAssignPolicyModal;
window.submitAssignPolicy = submitAssignPolicy;

// --- Patch Remediation & Dispatcher UI Functions ---

function openDeployPatchModal(agentId, hostname, patchId, title, os) {
    document.getElementById('deploy-patch-agent-id').value = agentId;
    document.getElementById('deploy-patch-id').value = patchId;
    document.getElementById('deploy-patch-hostname').textContent = hostname || '-';
    document.getElementById('deploy-patch-kbid').textContent = patchId;
    document.getElementById('deploy-patch-title-text').textContent = title || '-';
    document.getElementById('deploy-patch-os').textContent = os || '-';
    document.getElementById('deploy-patch-reboot').checked = false;
    document.getElementById('modal-deploy-patch-subtitle').textContent = (hostname || 'Agent') + ' (' + (os || 'OS') + ')';
    
    const modal = document.getElementById('modal-deploy-patch');
    if (modal) {
        modal.classList.add('active');
        modal.style.display = 'flex';
    }
}

function closeDeployPatchModal() {
    const modal = document.getElementById('modal-deploy-patch');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
}

async function submitDeployPatch() {
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const agentId = document.getElementById('deploy-patch-agent-id').value;
    const patchId = document.getElementById('deploy-patch-id').value;
    const title = document.getElementById('deploy-patch-title-text').textContent;
    const rebootAfter = document.getElementById('deploy-patch-reboot').checked;

    if (!agentId || !patchId) return;

    try {
        const res = await fetch('/api/v1/endpoint/patches/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                agent_id: agentId,
                patch_id: patchId,
                title: title,
                reboot_after: rebootAfter
            })
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || 'Yama dağıtılamadı');
        }

        closeDeployPatchModal();
        if (typeof showToast === 'function') {
            showToast('✓ ' + t('msg_patch_queued', 'Yama yükleme görevi uç noktaya başarıyla iletildi.'), 'success');
        } else if (typeof showNotification === 'function') {
            showNotification(t('msg_patch_queued', 'Yama yükleme görevi uç noktaya başarıyla iletildi.'), 'success');
        }
        loadEndpointPatches();
    } catch (err) {
        alert('Hata: ' + err.message);
    }
}

function openBatchPatchDeployModal() {
    const modal = document.getElementById('modal-batch-patch-deploy');
    if (modal) {
        modal.classList.add('active');
        modal.style.display = 'flex';
    }
}

function closeBatchPatchDeployModal() {
    const modal = document.getElementById('modal-batch-patch-deploy');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
}

// --- Remote Microsoft Patch Deployment Modal Controller ---
async function openRemotePatchModal() {
    const modal = document.getElementById('modal-remote-patch');
    if (!modal) return;
    
    // Populate agent select
    const select = document.getElementById('remote-patch-agent-select');
    if (select) {
        select.innerHTML = '<option value="">Uç noktalar yükleniyor...</option>';
        try {
            const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
            const res = await fetch(`/api/v1/endpoint/agents?tenant=${encodeURIComponent(tenant)}&limit=100`);
            if (res.ok) {
                const data = await res.json();
                const agents = data.agents || [];
                if (agents.length === 0) {
                    select.innerHTML = '<option value="">Kayıtlı uç nokta bulunamadı</option>';
                } else {
                    select.innerHTML = agents.map(a => {
                        const os = (a.os_type || 'OS').toUpperCase();
                        const isWin = (a.os_type === 'windows' || (a.hostname && a.hostname.toLowerCase().includes('forti')));
                        const icon = isWin ? '🪟' : (a.os_type === 'darwin' ? '🍎' : '🐧');
                        return `<option value="${escapeHtml(a.id)}" data-os="${escapeHtml(a.os_type || '')}" ${isWin ? 'selected' : ''}>${icon} ${escapeHtml(a.hostname || a.ip_address)} (${escapeHtml(a.ip_address || '-')} - ${os})</option>`;
                    }).join('');
                }
            }
        } catch (e) {
            console.error('Error fetching agents for remote patch modal:', e);
            select.innerHTML = '<option value="">Uç nokta listesi alınamadı</option>';
        }
    }

    // Reset inputs
    const patchSel = document.getElementById('remote-patch-select');
    if (patchSel) patchSel.selectedIndex = 0;
    const customWrap = document.getElementById('remote-patch-custom-wrap');
    if (customWrap) customWrap.style.display = 'none';
    const customInp = document.getElementById('remote-patch-custom-kb');
    if (customInp) customInp.value = '';
    const rebootChk = document.getElementById('remote-patch-reboot');
    if (rebootChk) rebootChk.checked = true;

    modal.classList.add('active');
    modal.style.display = 'flex';
}

function closeRemotePatchModal() {
    const modal = document.getElementById('modal-remote-patch');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
}

function handleRemotePatchSelectChange(val) {
    const customWrap = document.getElementById('remote-patch-custom-wrap');
    if (customWrap) {
        customWrap.style.display = (val === 'custom') ? 'block' : 'none';
    }
}

async function submitRemotePatch() {
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const agentSelect = document.getElementById('remote-patch-agent-select');
    const agentId = agentSelect?.value;
    if (!agentId) {
        alert('Lütfen bir hedef uç nokta seçin.');
        return;
    }

    const patchSel = document.getElementById('remote-patch-select');
    let patchId = patchSel?.value;
    let title = '';
    if (patchId === 'custom') {
        patchId = document.getElementById('remote-patch-custom-kb')?.value?.trim();
        if (!patchId) {
            alert('Lütfen geçerli bir KB veya paket numarası girin.');
            return;
        }
        title = `Security & Quality Update (${patchId})`;
    } else {
        const selectedOpt = patchSel?.options[patchSel.selectedIndex];
        title = selectedOpt?.getAttribute('data-title') || `Security Update (${patchId})`;
    }

    const rebootAfter = document.getElementById('remote-patch-reboot')?.checked || false;

    try {
        const res = await fetch('/api/v1/endpoint/patches/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                agent_id: agentId,
                patch_id: patchId,
                title: title,
                reboot_after: rebootAfter
            })
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || 'Uzaktan yama görevi iletilemedi');
        }

        closeRemotePatchModal();
        const successMsg = `✓ ${patchId} yama yükleme görevi uç noktaya başarıyla iletildi.`;
        if (typeof showToast === 'function') {
            showToast(successMsg, 'success');
        } else if (typeof showNotification === 'function') {
            showNotification(successMsg, 'success');
        }
        loadEndpointPatches();
    } catch (err) {
        alert('Hata: ' + err.message);
    }
}

window.openDeployPatchModal = openDeployPatchModal;
window.closeDeployPatchModal = closeDeployPatchModal;
window.openBatchPatchDeployModal = openBatchPatchDeployModal;
window.closeBatchPatchDeployModal = closeBatchPatchDeployModal;
window.openRemotePatchModal = openRemotePatchModal;
window.closeRemotePatchModal = closeRemotePatchModal;
window.handleRemotePatchSelectChange = handleRemotePatchSelectChange;
window.submitRemotePatch = submitRemotePatch;

async function submitBatchPatchDeploy() {
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const severity = document.getElementById('batch-deploy-severity').value;
    const rebootAfter = document.getElementById('batch-deploy-reboot').checked;

    try {
        const res = await fetch('/api/v1/endpoint/patches/batch-deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                severity_filter: severity,
                reboot_after: rebootAfter
            })
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || 'Toplu yama dağıtımı başlatılamadı');
        }

        const data = await res.json();
        closeBatchPatchDeployModal();
        const msg = `${data.queued_count || 0} ${t('msg_batch_queued')}`;
        if (typeof showToast === 'function') {
            showToast('🚀 ' + msg, 'success');
        } else if (typeof showNotification === 'function') {
            showNotification(msg, 'success');
        }
        loadEndpointPatches();
    } catch (err) {
        alert('Hata: ' + err.message);
    }
}

async function rebootEndpoint(agentId, hostname) {
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    if (!confirm(`${hostname || 'Uç nokta'}: ${t('confirm_reboot')}`)) {
        return;
    }

    try {
        const res = await fetch('/api/v1/endpoint/agents/reboot', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ agent_id: agentId })
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || 'Reboot komutu gönderilemedi');
        }

        if (typeof showToast === 'function') {
            showToast('⚡ ' + t('msg_reboot_queued'), 'success');
        } else if (typeof showNotification === 'function') {
            showNotification(t('msg_reboot_queued'), 'success');
        }
        loadEndpointPatches();
    } catch (err) {
        alert('Hata: ' + err.message);
    }
}

function openEndpointTasksModal() {
    const modal = document.getElementById('modal-endpoint-tasks');
    if (modal) modal.style.display = 'flex';
    loadEndpointTasks();
}

function closeEndpointTasksModal() {
    const modal = document.getElementById('modal-endpoint-tasks');
    if (modal) modal.style.display = 'none';
}

async function loadEndpointTasks() {
    const tbody = document.getElementById('ep-tasks-tbody');
    if (!tbody) return;

    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const status = document.getElementById('ep-tasks-status-filter')?.value || '';
    const taskType = document.getElementById('ep-tasks-type-filter')?.value || '';
    const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';

    tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="color: var(--text-muted); padding: 24px;">Görev kayıtları yükleniyor...</td></tr>`;

    try {
        const res = await fetch(`/api/v1/endpoint/tasks?tenant=${encodeURIComponent(tenant)}&status=${encodeURIComponent(status)}&task_type=${encodeURIComponent(taskType)}&limit=100`);
        if (!res.ok) throw new Error('Görevler yüklenemedi (' + res.status + ')');

        const data = await res.json();
        const tasks = data.tasks || [];

        if (tasks.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="color: var(--text-muted); padding: 28px;">${t('ep_no_tasks')}</td></tr>`;
            return;
        }

        tbody.innerHTML = tasks.map(task => {
            let statusBadge = '';
            if (task.status === 'completed') {
                statusBadge = `<span class="badge badge-success">✓ Completed</span>`;
            } else if (task.status === 'failed') {
                statusBadge = `<span class="badge badge-danger">✕ Failed</span>`;
            } else if (task.status === 'running') {
                statusBadge = `<span class="badge badge-info" style="animation: pulse 1.5s infinite;">⚙️ Running...</span>`;
            } else {
                statusBadge = `<span class="badge badge-warning">⏳ Pending</span>`;
            }

            const shortId = (task.id || '').substring(0, 8);
            const duration = task.execution_duration_ms ? `${task.execution_duration_ms} ms` : '-';
            const dateStr = task.created_at ? formatDateTime(task.created_at) : '-';

            return `
                <tr>
                    <td><strong style="font-family: var(--font-mono); font-size: 11.5px; color: var(--accent);">${escapeHtml(shortId)}</strong></td>
                    <td>
                        <div style="font-weight: 600;">${escapeHtml(task.agent_hostname || '-')}</div>
                        <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(task.agent_ip || '')} (${escapeHtml(task.agent_os || '')})</div>
                    </td>
                    <td><span class="badge" style="background: rgba(148, 163, 184, 0.2); font-family: var(--font-mono); font-size: 11px;">${escapeHtml(task.task_type)}</span></td>
                    <td>${statusBadge}</td>
                    <td style="font-size: 12px; color: var(--text-muted);">${duration}</td>
                    <td style="font-size: 11.5px; color: var(--text-muted);">${dateStr}</td>
                    <td style="text-align: right;">
                        <button class="btn btn-sm btn-outline" onclick="openTaskLogModal('${escapeHtml(task.id)}')" style="font-size: 11px; padding: 2px 8px;"><i class="fas fa-terminal"></i> Log</button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="color: var(--accent-red); padding: 24px;">Hata: ${escapeHtml(err.message)}</td></tr>`;
    }
}

async function openTaskLogModal(taskId) {
    const modal = document.getElementById('modal-task-log-view');
    if (modal) {
        modal.classList.add('active');
        modal.style.display = 'flex';
    }

    document.getElementById('task-log-header-info').textContent = 'Görev: ' + taskId;
    document.getElementById('task-log-meta-status').innerHTML = '<span class="badge badge-secondary">Yükleniyor...</span>';
    document.getElementById('task-log-meta-duration').textContent = '';
    document.getElementById('task-log-stdout').textContent = 'Çıktı yükleniyor...';
    document.getElementById('task-log-stderr').textContent = '';

    try {
        const res = await fetch(`/api/v1/endpoint/tasks/${encodeURIComponent(taskId)}`);
        if (!res.ok) throw new Error('Görev ayrıntısı alınamadı');

        const task = await res.json();
        const resObj = task.result || {};
        
        let statusBadge = `<span class="badge badge-info">${escapeHtml(task.status)}</span>`;
        if (task.status === 'completed') statusBadge = `<span class="badge badge-success">✓ Completed (Exit 0)</span>`;
        if (task.status === 'failed') statusBadge = `<span class="badge badge-danger">✕ Failed (Exit ${resObj.exit_code || 1})</span>`;
        
        document.getElementById('task-log-meta-status').innerHTML = statusBadge;
        document.getElementById('task-log-meta-duration').textContent = `Çalışma Süresi: ${task.execution_duration_ms || resObj.execution_duration_ms || 0} ms`;

        document.getElementById('task-log-stdout').textContent = resObj.stdout || '(Standart çıktı üretilmedi)';
        document.getElementById('task-log-stderr').textContent = resObj.stderr || task.error_message || '(Hata çıktısı yok)';
    } catch (err) {
        document.getElementById('task-log-stdout').textContent = 'Hata: ' + err.message;
    }
}

function closeTaskLogModal() {
    const modal = document.getElementById('modal-task-log-view');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
}

// -----------------------------------------------------------------------------
// Endpoint Active Response, EDR Host Isolation & OSQuery (Phase J.3 & J.4)
// -----------------------------------------------------------------------------
let currentARAgentID = null;
let currentARHostname = '';
let currentARIsIsolated = false;

function openActiveResponseModal(agentId, hostname, isIsolated) {
    currentARAgentID = agentId;
    currentARHostname = hostname || 'Uç Nokta';
    currentARIsIsolated = !!isIsolated;

    const modal = document.getElementById('modal-endpoint-active-response');
    if (!modal) return;

    document.getElementById('ar-target-hostname').textContent = currentARHostname;
    updateARIsolationUI();
    switchARTab('isolation');
    loadQuarantinedFiles(agentId);

    modal.style.display = 'flex';
}

function closeActiveResponseModal() {
    const modal = document.getElementById('modal-endpoint-active-response');
    if (modal) modal.style.display = 'none';
    currentARAgentID = null;
}

function updateARIsolationUI() {
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const titleEl = document.getElementById('ar-iso-card-title');
    const descEl = document.getElementById('ar-iso-card-desc');
    const pillEl = document.getElementById('ar-iso-card-pill');
    const statusBadgeEl = document.getElementById('ar-target-status-badge');
    const btnIsolate = document.getElementById('btn-ar-trigger-isolate');
    const btnUnisolate = document.getElementById('btn-ar-trigger-unisolate');
    const statusCard = document.getElementById('ar-isolation-status-card');

    if (currentARIsIsolated) {
        if (titleEl) titleEl.textContent = 'Ağ Durumu: İZOLASYON AKTİF (Containment Active)';
        if (descEl) descEl.textContent = 'Bu uç nokta ağdan izole edilmiştir. Sadece LogSeal yönetim telemetrisi açıktır.';
        if (pillEl) pillEl.innerHTML = '<span class="badge badge-danger" style="animation: pulse 2s infinite; font-weight: 700;">🛡️ İZOLASYONDA</span>';
        if (statusBadgeEl) statusBadgeEl.innerHTML = '<span class="badge badge-danger">🛡️ İZOLASYONDA</span>';
        if (btnIsolate) btnIsolate.style.display = 'none';
        if (btnUnisolate) btnUnisolate.style.display = 'inline-flex';
        if (statusCard) {
            statusCard.style.borderLeftColor = '#ef4444';
            statusCard.style.background = 'rgba(239, 68, 68, 0.08)';
        }
    } else {
        if (titleEl) titleEl.textContent = 'Ağ Durumu: Normal Bağlantı (Online)';
        if (descEl) descEl.textContent = 'Uç nokta tüm iç ve dış ağlara erişebilir durumdadır.';
        if (pillEl) pillEl.innerHTML = '<span class="badge badge-success">BAĞLI / ONLINE</span>';
        if (statusBadgeEl) statusBadgeEl.innerHTML = '<span class="badge badge-success">BAĞLI / ONLINE</span>';
        if (btnIsolate) btnIsolate.style.display = 'inline-flex';
        if (btnUnisolate) btnUnisolate.style.display = 'none';
        if (statusCard) {
            statusCard.style.borderLeftColor = 'var(--accent)';
            statusCard.style.background = 'rgba(255, 255, 255, 0.02)';
        }
    }
}

function switchARTab(tab) {
    document.querySelectorAll('.ar-tab-btn').forEach(b => {
        b.classList.toggle('active', b.id === `btn-tab-ar-${tab}`);
        if (b.id === `btn-tab-ar-${tab}`) {
            b.style.background = 'var(--panel-bg)';
            b.style.color = 'var(--accent)';
            b.style.borderBottom = '2px solid var(--accent)';
        } else {
            b.style.background = 'transparent';
            b.style.color = 'var(--text-muted)';
            b.style.borderBottom = 'none';
        }
    });

    document.querySelectorAll('.ar-tab-pane').forEach(p => {
        p.style.display = (p.id === `ar-pane-${tab}`) ? 'block' : 'none';
    });
}

async function submitHostIsolation(isolate) {
    if (!currentARAgentID) return;
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const confirmMsg = isolate ? t('confirm_isolate') : t('confirm_unisolate');

    if (!confirm(`${currentARHostname}: ${confirmMsg}`)) return;

    try {
        const endpoint = isolate ? '/api/v1/endpoint/agents/isolate' : '/api/v1/endpoint/agents/unisolate';
        const reason = document.getElementById('ar-isolation-reason')?.value || 'EDR Active Response Containment';
        
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                agent_id: currentARAgentID,
                reason: reason
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'İzolasyon komutu gönderilemedi');
        }

        const successMsg = isolate ? t('msg_isolate_queued') : t('msg_unisolate_queued');
        showToast('🛡️ ' + successMsg, 'success');
        currentARIsIsolated = isolate;
        updateARIsolationUI();
        if (typeof loadEndpointAgents === 'function') loadEndpointAgents();
    } catch (err) {
        alert('Hata: ' + err.message);
    }
}

async function submitProcessKill() {
    if (!currentARAgentID) return;
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const pidVal = parseInt(document.getElementById('ar-proc-pid')?.value, 10);
    const nameVal = document.getElementById('ar-proc-name')?.value?.trim() || '';
    const forceVal = document.getElementById('ar-proc-force')?.checked ?? true;

    if (!pidVal && !nameVal) {
        alert('Lütfen bir PID veya Süreç Adı belirtin.');
        return;
    }

    if (!confirm(`${currentARHostname}: ${t('confirm_kill_proc')} (${pidVal ? 'PID: ' + pidVal : nameVal})`)) return;

    try {
        const res = await fetch('/api/v1/endpoint/agents/kill-process', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                agent_id: currentARAgentID,
                pid: pidVal || 0,
                process_name: nameVal,
                force: forceVal
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'Süreç sonlandırma komutu iletilemedi');
        }

        showToast('⚡ ' + t('msg_proc_kill_queued'), 'success');
        document.getElementById('ar-proc-pid').value = '';
        document.getElementById('ar-proc-name').value = '';
    } catch (err) {
        alert('Hata: ' + err.message);
    }
}

async function submitFileQuarantine() {
    if (!currentARAgentID) return;
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const pathVal = document.getElementById('ar-quarantine-path')?.value?.trim() || '';
    const reasonVal = document.getElementById('ar-quarantine-reason')?.value?.trim() || '';

    if (!pathVal) {
        alert('Lütfen karantinaya alınacak dosya yolunu girin.');
        return;
    }

    if (!confirm(`${currentARHostname}: ${t('confirm_quarantine')} (${pathVal})`)) return;

    try {
        const res = await fetch('/api/v1/endpoint/agents/quarantine-file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                agent_id: currentARAgentID,
                file_path: pathVal,
                reason: reasonVal
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'Dosya karantina komutu iletilemedi');
        }

        showToast('☣️ ' + t('msg_quarantine_queued'), 'success');
        document.getElementById('ar-quarantine-path').value = '';
        document.getElementById('ar-quarantine-reason').value = '';
        setTimeout(() => loadQuarantinedFiles(currentARAgentID), 2000);
    } catch (err) {
        alert('Hata: ' + err.message);
    }
}

async function loadQuarantinedFiles(agentId) {
    const tbody = document.getElementById('ar-quarantine-tbody');
    if (!tbody) return;

    try {
        const res = await fetch(`/api/v1/endpoint/agents/quarantined-files?agent_id=${encodeURIComponent(agentId || '')}`);
        if (!res.ok) throw new Error('Karantina listesi alınamadı');
        const data = await res.json();
        const files = data.files || [];

        if (files.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center" style="color: var(--text-muted); padding: 14px;">Bu uç noktada karantinaya alınmış dosya bulunmuyor.</td></tr>';
            return;
        }

        tbody.innerHTML = files.map(f => `
            <tr>
                <td style="font-family: var(--font-mono);">${escapeHtml(f.original_path)}</td>
                <td style="font-family: var(--font-mono); color: var(--text-muted);">${escapeHtml(f.quarantine_path)}</td>
                <td style="font-family: var(--font-mono); font-size: 10px;">${escapeHtml((f.sha256 || '').substring(0, 16))}...</td>
                <td>${formatBytes(f.size_bytes || 0)}</td>
                <td style="color: var(--text-muted);">${formatRelativeTime(f.quarantined_at)}</td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center" style="color: var(--danger); padding: 10px;">${escapeHtml(err.message)}</td></tr>`;
    }
}

function setOSQuery(sql) {
    const textarea = document.getElementById('ar-osquery-sql');
    if (textarea) textarea.value = sql;
}

async function submitOSQuery() {
    if (!currentARAgentID) return;
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const sql = document.getElementById('ar-osquery-sql')?.value?.trim();
    const timeout = parseInt(document.getElementById('ar-osquery-timeout')?.value, 10) || 15;
    const resultBox = document.getElementById('ar-osquery-result');
    const runBtn = document.getElementById('btn-ar-run-osquery');

    if (!sql) {
        alert('Lütfen çalıştırılacak adli SQL sorgusunu yazın.');
        return;
    }

    if (resultBox) {
        resultBox.textContent = '⏳ Sorgu uç noktaya iletildi, adli sonuçlar alınıyor (Timeout: ' + timeout + 's)...';
        resultBox.style.color = '#58a6ff';
    }
    if (runBtn) runBtn.disabled = true;

    try {
        const res = await fetch('/api/v1/endpoint/agents/osquery', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                agent_id: currentARAgentID,
                query: sql,
                timeout_sec: timeout
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'Sorgu iletilemedi');
        }

        const data = await res.json();
        const taskId = data.task_id;
        showToast('🔍 ' + t('msg_osquery_queued'), 'success');

        // Poll task result for up to timeout seconds
        let attempts = 0;
        const maxAttempts = timeout + 2;
        const pollInterval = setInterval(async () => {
            attempts++;
            try {
                const tRes = await fetch(`/api/v1/endpoint/tasks/${taskId}`);
                if (tRes.ok) {
                    const task = await tRes.json();
                    if (task.status === 'completed') {
                        clearInterval(pollInterval);
                        if (runBtn) runBtn.disabled = false;
                        
                        let formattedOutput = task.stdout;
                        try {
                            const parsed = JSON.parse(task.stdout);
                            formattedOutput = JSON.stringify(parsed, null, 2);
                        } catch(e) {}

                        if (resultBox) {
                            resultBox.textContent = formattedOutput || '(Sorgu tamamlandı, sonuç döndürülmedi)';
                            resultBox.style.color = '#3fb950';
                        }
                        return;
                    } else if (task.status === 'failed') {
                        clearInterval(pollInterval);
                        if (runBtn) runBtn.disabled = false;
                        if (resultBox) {
                            resultBox.textContent = '✕ Sorgu başarısız:\n' + (task.stderr || task.error_message || 'Bilinmeyen hata');
                            resultBox.style.color = '#f85149';
                        }
                        return;
                    }
                }
            } catch(e) {}

            if (attempts >= maxAttempts) {
                clearInterval(pollInterval);
                if (runBtn) runBtn.disabled = false;
                if (resultBox) {
                    resultBox.textContent = '⚠️ Zaman aşımı: Uç noktadan beklenen sürede yanıt alınamadı. Görev kayıtlarından çıktıyı kontrol edebilirsiniz.';
                    resultBox.style.color = '#f59e0b';
                }
            }
        }, 1000);

    } catch (err) {
        if (runBtn) runBtn.disabled = false;
        if (resultBox) {
            resultBox.textContent = 'Hata: ' + err.message;
            resultBox.style.color = '#f85149';
        }
    }
}

window.openDeployPatchModal = openDeployPatchModal;
window.closeDeployPatchModal = closeDeployPatchModal;
window.submitDeployPatch = submitDeployPatch;
window.openBatchPatchDeployModal = openBatchPatchDeployModal;
window.closeBatchPatchDeployModal = closeBatchPatchDeployModal;
window.submitBatchPatchDeploy = submitBatchPatchDeploy;
window.rebootEndpoint = rebootEndpoint;
window.openEndpointTasksModal = openEndpointTasksModal;
window.closeEndpointTasksModal = closeEndpointTasksModal;
window.loadEndpointTasks = loadEndpointTasks;
window.openTaskLogModal = openTaskLogModal;
window.closeTaskLogModal = closeTaskLogModal;
window.openActiveResponseModal = openActiveResponseModal;
window.closeActiveResponseModal = closeActiveResponseModal;
window.switchARTab = switchARTab;
window.submitHostIsolation = submitHostIsolation;
window.submitProcessKill = submitProcessKill;
window.submitFileQuarantine = submitFileQuarantine;
window.loadQuarantinedFiles = loadQuarantinedFiles;
window.setOSQuery = setOSQuery;
window.submitOSQuery = submitOSQuery;

/* ========================================================================
   SOAR PLAYBOOKS & AUTOMATED INCIDENT RESPONSE ENGINE
   ======================================================================== */
let currentSOARPlaybooks = [];
let currentSOARExecutions = [];
let soarHistoryFilter = 'ALL';

async function openSOARModal() {
    const modal = document.getElementById('modal-soar-playbooks');
    if (!modal) return;
    modal.classList.add('active');
    modal.style.display = 'flex';
    switchSOARTab('catalog');
    await loadSOARPlaybooks();
    await loadSOARExecutions();
}

function closeSOARModal() {
    const modal = document.getElementById('modal-soar-playbooks');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
}

function switchSOARTab(tab) {
    const catPane = document.getElementById('soar-pane-catalog');
    const histPane = document.getElementById('soar-pane-history');
    const editPane = document.getElementById('soar-pane-editor');
    if (catPane) catPane.style.display = (tab === 'catalog') ? 'block' : 'none';
    if (histPane) histPane.style.display = (tab === 'history') ? 'block' : 'none';
    if (editPane) editPane.style.display = (tab === 'editor') ? 'block' : 'none';

    const btnCat = document.getElementById('btn-soar-tab-catalog');
    const btnHist = document.getElementById('btn-soar-tab-history');
    const btnEdit = document.getElementById('btn-soar-tab-editor');
    if (btnCat) btnCat.classList.toggle('active', tab === 'catalog');
    if (btnHist) btnHist.classList.toggle('active', tab === 'history');
    if (btnEdit) btnEdit.classList.toggle('active', tab === 'editor');

    if (tab === 'catalog') loadSOARPlaybooks();
    if (tab === 'history') loadSOARExecutions();
}

async function loadSOARPlaybooks() {
    try {
        const [pbRes, statsRes] = await Promise.all([
            fetch('/api/v1/soar/playbooks'),
            fetch('/api/v1/soar/stats')
        ]);
        if (!pbRes.ok) throw new Error('Playbooklar alınamadı');
        const pbData = await pbRes.json();
        currentSOARPlaybooks = pbData.playbooks || [];

        if (statsRes.ok) {
            const stats = await statsRes.json();
            const elTotal = document.getElementById('soar-stat-total');
            const elActive = document.getElementById('soar-stat-active');
            const elPending = document.getElementById('soar-stat-pending');
            const elContained = document.getElementById('soar-stat-contained');
            if (elTotal) elTotal.textContent = stats.total_playbooks || currentSOARPlaybooks.length;
            if (elActive) elActive.textContent = stats.active_playbooks || 0;
            if (elPending) elPending.textContent = stats.pending_approvals || 0;
            if (elContained) elContained.textContent = stats.contained_hosts || 0;

            const pendingBadge = document.getElementById('soar-pending-badge');
            if (pendingBadge) {
                if (stats.pending_approvals > 0) {
                    pendingBadge.textContent = stats.pending_approvals;
                    pendingBadge.style.display = 'inline-block';
                } else {
                    pendingBadge.style.display = 'none';
                }
            }
        }

        renderSOARPlaybooksTable();
    } catch (e) {
        showToast('SOAR yüklenemedi: ' + e.message, 'error');
    }
}

function renderSOARPlaybooksTable() {
    const tbody = document.getElementById('tbody-soar-playbooks');
    if (!tbody) return;

    if (currentSOARPlaybooks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted" style="padding: 24px;">Tanımlı SOAR playbook senaryosu bulunamadı.</td></tr>';
        return;
    }

    tbody.innerHTML = currentSOARPlaybooks.map(pb => {
        const modeBadge = pb.execution_mode === 'autonomous'
            ? '<span class="badge" style="background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3);">⚡ Otonom (Auto)</span>'
            : '<span class="badge" style="background: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3);">👤 Analist Onaylı</span>';

        const trigBadges = [];
        if (pb.trigger_conditions) {
            if (pb.trigger_conditions.severities && pb.trigger_conditions.severities.length > 0) {
                trigBadges.push(pb.trigger_conditions.severities.map(s => getSeverityBadgeHTML(s)).join(' '));
            }
            if (pb.trigger_conditions.min_risk_score) {
                trigBadges.push(`<span class="badge badge-outline" style="font-size: 10.5px;">Skor &ge; ${pb.trigger_conditions.min_risk_score}</span>`);
            }
            if (pb.trigger_conditions.mitre_tactics && pb.trigger_conditions.mitre_tactics.length > 0) {
                trigBadges.push(`<span class="badge badge-mitre" style="font-size: 10.5px;">${pb.trigger_conditions.mitre_tactics.join(', ')}</span>`);
            }
        }
        const trigHTML = trigBadges.length > 0 ? trigBadges.join(' ') : '<span class="text-muted">Tüm Uyarılar</span>';

        const actionBadges = (pb.actions || []).map(a => {
            switch (a.type) {
                case 'isolate_host': return '<span class="badge badge-danger" style="font-size: 10.5px;">🛑 İzolasyon</span>';
                case 'osquery_run': return '<span class="badge" style="font-size: 10.5px; background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3);">🔍 OSQuery</span>';
                case 'kill_process': return '<span class="badge badge-warning" style="font-size: 10.5px;">⚡ Process Kill</span>';
                case 'file_quarantine': return '<span class="badge badge-warning" style="font-size: 10.5px;">📦 Quarantine</span>';
                case 'webhook_notify': return '<span class="badge" style="font-size: 10.5px; background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3);">🌐 Webhook</span>';
                default: return `<span class="badge badge-outline" style="font-size: 10.5px;">${escapeHtml(a.type)}</span>`;
            }
        }).join(' ');

        const lastExecStr = pb.last_executed_at ? formatRelativeTime(pb.last_executed_at) : 'Hiç çalışmadı';

        return `
            <tr>
                <td>
                    <label class="switch" style="margin: 0;" title="Etkinleştir / Devre Dışı Bırak">
                        <input type="checkbox" ${pb.is_enabled ? 'checked' : ''} onchange="toggleSOARPlaybook('${pb.id}')">
                        <span class="slider round"></span>
                    </label>
                </td>
                <td>
                    <div style="font-weight: 600; color: var(--text-main); font-size: 13px;">${escapeHtml(pb.name)}</div>
                    <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.4; margin-top: 2px;">${escapeHtml(pb.description || '')}</div>
                </td>
                <td>${modeBadge}</td>
                <td><div style="display: flex; flex-wrap: wrap; gap: 4px;">${trigHTML}</div></td>
                <td><div style="display: flex; flex-wrap: wrap; gap: 4px;">${actionBadges || '<span class="text-muted">-</span>'}</div></td>
                <td>
                    <div style="font-size: 12px; font-weight: 600;">${pb.total_executions || 0} kez</div>
                    <div style="font-size: 11px; color: var(--text-muted);">${lastExecStr}</div>
                </td>
                <td style="text-align: right;">
                    <div style="display: flex; gap: 6px; justify-content: flex-end;">
                        <button class="btn btn-outline btn-sm" onclick="openSOARRunModal('${pb.id}')" title="Manuel Çalıştır">⚡</button>
                        <button class="btn btn-outline btn-sm" onclick="openSOAREditor('${pb.id}')" title="Düzenle">✏️</button>
                        <button class="btn btn-outline btn-sm text-red" onclick="deleteSOARPlaybook('${pb.id}', '${escapeHtml(pb.name)}')" title="Sil">🗑️</button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

async function toggleSOARPlaybook(id) {
    try {
        const res = await fetch('/api/v1/soar/playbooks/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id })
        });
        if (!res.ok) throw new Error('Durum güncellenemedi');
        const data = await res.json();
        showToast(`Playbook durumu: ${data.is_enabled ? 'Aktif' : 'Pasif'}`, 'info');
        loadSOARPlaybooks();
    } catch (e) {
        showToast(e.message, 'error');
        loadSOARPlaybooks();
    }
}

function openSOAREditor(pbId = null) {
    const catPane = document.getElementById('soar-pane-catalog');
    const histPane = document.getElementById('soar-pane-history');
    const editPane = document.getElementById('soar-pane-editor');
    if (catPane) catPane.style.display = 'none';
    if (histPane) histPane.style.display = 'none';
    if (editPane) editPane.style.display = 'block';

    const btnCat = document.getElementById('btn-soar-tab-catalog');
    const btnHist = document.getElementById('btn-soar-tab-history');
    const btnEdit = document.getElementById('btn-soar-tab-editor');
    if (btnCat) btnCat.classList.remove('active');
    if (btnHist) btnHist.classList.remove('active');
    if (btnEdit) btnEdit.classList.add('active');

    if (pbId) {
        const pb = currentSOARPlaybooks.find(p => p.id === pbId);
        if (pb) {
            document.getElementById('soar-edit-id').value = pb.id;
            document.getElementById('soar-edit-name').value = pb.name || '';
            document.getElementById('soar-edit-desc').value = pb.description || '';
            document.getElementById('soar-edit-mode').value = pb.execution_mode || 'autonomous';
            document.getElementById('soar-edit-cooldown').value = pb.cooldown_minutes || 15;
            document.getElementById('soar-edit-enabled').checked = pb.is_enabled !== false;

            const tc = pb.trigger_conditions || {};
            const sevs = tc.severities || [];
            document.getElementById('soar-trig-sev-crit').checked = sevs.includes('CRITICAL');
            document.getElementById('soar-trig-sev-high').checked = sevs.includes('HIGH');
            document.getElementById('soar-trig-sev-med').checked = sevs.includes('MEDIUM');
            document.getElementById('soar-trig-sev-low').checked = sevs.includes('LOW');
            document.getElementById('soar-trig-risk').value = tc.min_risk_score || 0;
            document.getElementById('soar-trig-tactics').value = (tc.mitre_tactics || []).join(', ');
            document.getElementById('soar-trig-cats').value = (tc.categories || []).join(', ');

            const acts = pb.actions || [];
            const isoAct = acts.find(a => a.type === 'isolate_host');
            const osqAct = acts.find(a => a.type === 'osquery_run');
            const webAct = acts.find(a => a.type === 'webhook_notify');

            document.getElementById('soar-act-isolate').checked = !!isoAct;
            document.getElementById('soar-act-osquery').checked = !!osqAct;
            if (osqAct && osqAct.parameters && osqAct.parameters.query) {
                document.getElementById('soar-act-osquery-sql').value = osqAct.parameters.query;
            }
            document.getElementById('soar-act-webhook').checked = !!webAct;
            if (webAct && webAct.parameters && webAct.parameters.url) {
                document.getElementById('soar-act-webhook-url').value = webAct.parameters.url;
            }
            return;
        }
    }

    // Reset Form for New Playbook
    document.getElementById('soar-edit-id').value = '';
    document.getElementById('soar-edit-name').value = '';
    document.getElementById('soar-edit-desc').value = '';
    document.getElementById('soar-edit-mode').value = 'autonomous';
    document.getElementById('soar-edit-cooldown').value = '15';
    document.getElementById('soar-edit-enabled').checked = true;
    document.getElementById('soar-trig-sev-crit').checked = true;
    document.getElementById('soar-trig-sev-high').checked = true;
    document.getElementById('soar-trig-sev-med').checked = false;
    document.getElementById('soar-trig-sev-low').checked = false;
    document.getElementById('soar-trig-risk').value = '70';
    document.getElementById('soar-trig-tactics').value = '';
    document.getElementById('soar-trig-cats').value = '';
    document.getElementById('soar-act-isolate').checked = true;
    document.getElementById('soar-act-osquery').checked = true;
    document.getElementById('soar-act-osquery-sql').value = 'SELECT pid, name, path, cmdline FROM processes ORDER BY pid LIMIT 50;';
    document.getElementById('soar-act-webhook').checked = false;
    document.getElementById('soar-act-webhook-url').value = '';
}

async function submitSaveSOARPlaybook() {
    const id = document.getElementById('soar-edit-id').value;
    const name = document.getElementById('soar-edit-name').value.trim();
    if (!name) {
        showToast('Lütfen playbook adını belirtin.', 'error');
        return;
    }

    const desc = document.getElementById('soar-edit-desc').value.trim();
    const mode = document.getElementById('soar-edit-mode').value;
    const cooldown = parseInt(document.getElementById('soar-edit-cooldown').value, 10) || 15;
    const isEnabled = document.getElementById('soar-edit-enabled').checked;

    const severities = [];
    if (document.getElementById('soar-trig-sev-crit').checked) severities.push('CRITICAL');
    if (document.getElementById('soar-trig-sev-high').checked) severities.push('HIGH');
    if (document.getElementById('soar-trig-sev-med').checked) severities.push('MEDIUM');
    if (document.getElementById('soar-trig-sev-low').checked) severities.push('LOW');

    const minRisk = parseInt(document.getElementById('soar-trig-risk').value, 10) || 0;
    const tacticsStr = document.getElementById('soar-trig-tactics').value.trim();
    const tactics = tacticsStr ? tacticsStr.split(',').map(s => s.trim()).filter(Boolean) : [];
    const catsStr = document.getElementById('soar-trig-cats').value.trim();
    const cats = catsStr ? catsStr.split(',').map(s => s.trim()).filter(Boolean) : [];

    const actions = [];
    if (document.getElementById('soar-act-isolate').checked) {
        actions.push({
            id: 'act-isolate',
            type: 'isolate_host',
            parameters: { reason: 'Automated SOAR Containment: ' + name }
        });
    }
    if (document.getElementById('soar-act-osquery').checked) {
        const sql = document.getElementById('soar-act-osquery-sql').value.trim() || 'SELECT * FROM listening_ports;';
        actions.push({
            id: 'act-osquery',
            type: 'osquery_run',
            parameters: { query: sql }
        });
    }
    if (document.getElementById('soar-act-webhook').checked) {
        const url = document.getElementById('soar-act-webhook-url').value.trim();
        actions.push({
            id: 'act-webhook',
            type: 'webhook_notify',
            parameters: { url }
        });
    }

    const payload = {
        name,
        description: desc,
        execution_mode: mode,
        cooldown_minutes: cooldown,
        is_enabled: isEnabled,
        trigger_conditions: {
            severities,
            min_risk_score: minRisk,
            mitre_tactics: tactics,
            categories: cats
        },
        actions
    };

    try {
        const url = id ? `/api/v1/soar/playbooks/${id}` : '/api/v1/soar/playbooks';
        const method = id ? 'PUT' : 'POST';
        const res = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || `HTTP ${res.status}`);
        }
        showToast(`Playbook başarıyla ${id ? 'güncellendi' : 'kaydedildi'}!`, 'success');
        switchSOARTab('catalog');
    } catch (e) {
        showToast('Playbook kaydedilemedi: ' + e.message, 'error');
    }
}

async function deleteSOARPlaybook(id, name) {
    if (!confirm(`'${name}' başlıklı playbook silinsin mi?`)) return;
    try {
        const res = await fetch(`/api/v1/soar/playbooks/${id}`, { method: 'DELETE' });
        if (!res.ok) throw new Error('Silinemedi');
        showToast('Playbook silindi', 'info');
        loadSOARPlaybooks();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function loadSOARExecutions() {
    try {
        const params = new URLSearchParams();
        if (soarHistoryFilter && soarHistoryFilter !== 'ALL') {
            params.append('status', soarHistoryFilter);
        }
        const res = await fetch(`/api/v1/soar/executions?${params.toString()}`);
        if (!res.ok) throw new Error('Çalıştırma geçmişi alınamadı');
        const data = await res.json();
        currentSOARExecutions = data.executions || [];
        renderSOARHistoryTable();
    } catch (e) {
        showToast('Geçmiş yüklenemedi: ' + e.message, 'error');
    }
}

function filterSOARHistory(status) {
    soarHistoryFilter = status;
    document.querySelectorAll('#soar-history-filters .btn-filter').forEach(b => {
        b.classList.toggle('active', b.getAttribute('data-status') === status);
    });
    loadSOARExecutions();
}

function renderSOARHistoryTable() {
    const tbody = document.getElementById('tbody-soar-history');
    if (!tbody) return;

    if (currentSOARExecutions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted" style="padding: 24px;">Kayıtlı çalıştırma geçmişi bulunamadı.</td></tr>';
        return;
    }

    tbody.innerHTML = currentSOARExecutions.map(ex => {
        let statusBadge = '';
        switch (ex.status) {
            case 'COMPLETED':
                statusBadge = '<span class="badge" style="background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3);">✅ TAMAMLANDI</span>';
                break;
            case 'PENDING_APPROVAL':
                statusBadge = '<span class="badge pulsing-alert" style="background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4);">⚠️ ONAY BEKLİYOR</span>';
                break;
            case 'RUNNING':
                statusBadge = '<span class="badge badge-info pulsing-alert">⚡ ÇALIŞIYOR</span>';
                break;
            case 'FAILED':
                statusBadge = '<span class="badge badge-danger">❌ BAŞARISIZ</span>';
                break;
            case 'REJECTED':
                statusBadge = '<span class="badge badge-secondary">🚫 REDDEDİLDİ</span>';
                break;
            default:
                statusBadge = `<span class="badge badge-outline">${escapeHtml(ex.status)}</span>`;
        }

        const actionsBtn = (ex.status === 'PENDING_APPROVAL')
            ? `
                <div style="display: flex; gap: 4px; justify-content: flex-end;">
                    <button class="btn btn-sm btn-primary" style="background: #22c55e; border-color: #22c55e; padding: 2px 8px; font-size: 11px;" onclick="approveSOARExecution('${ex.id}')">Onayla</button>
                    <button class="btn btn-sm btn-outline text-red" style="padding: 2px 8px; font-size: 11px;" onclick="rejectSOARExecution('${ex.id}')">Reddet</button>
                    <button class="btn btn-sm btn-outline" style="padding: 2px 8px; font-size: 11px;" onclick="openSOARExecDetail('${ex.id}')">Detay</button>
                </div>
              `
            : `
                <button class="btn btn-sm btn-outline" style="padding: 2px 8px; font-size: 11px;" onclick="openSOARExecDetail('${ex.id}')">🔍 İncele</button>
              `;

        return `
            <tr>
                <td style="font-size: 11.5px; color: var(--text-muted);">${formatRelativeTime(ex.created_at)}</td>
                <td style="font-weight: 600; color: var(--text-main); font-size: 12.5px;">${escapeHtml(ex.playbook_name)}</td>
                <td><span class="mono-code" style="font-size: 12px;">${escapeHtml(ex.target_host || '-')}</span></td>
                <td style="font-size: 12px; color: var(--text-muted);">${escapeHtml(ex.triggered_by)}</td>
                <td style="font-size: 12px;"><span class="badge badge-outline">${ex.actions_executed || 0} adım</span></td>
                <td>${statusBadge}</td>
                <td style="text-align: right;">${actionsBtn}</td>
            </tr>
        `;
    }).join('');
}

async function approveSOARExecution(id) {
    try {
        const res = await fetch('/api/v1/soar/executions/approve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id })
        });
        if (!res.ok) throw new Error('Onaylanamadı');
        showToast('Playbook müdahalesi onaylandı ve derhal yürütülmeye başlandı!', 'success');
        loadSOARExecutions();
        loadSOARPlaybooks();
        const pendingCard = document.getElementById('siem-inv-pending-approval-card');
        if (pendingCard) pendingCard.style.display = 'none';
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function rejectSOARExecution(id) {
    try {
        const res = await fetch('/api/v1/soar/executions/reject', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id })
        });
        if (!res.ok) throw new Error('Reddedilemedi');
        showToast('Playbook çalıştırma talebi reddedildi.', 'info');
        loadSOARExecutions();
        loadSOARPlaybooks();
        const pendingCard = document.getElementById('siem-inv-pending-approval-card');
        if (pendingCard) pendingCard.style.display = 'none';
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function openSOARExecDetail(id) {
    const modal = document.getElementById('modal-soar-exec-detail');
    if (!modal) return;
    modal.classList.add('active');
    modal.style.display = 'flex';

    try {
        const res = await fetch(`/api/v1/soar/executions/${id}`);
        if (!res.ok) throw new Error('Kayıt bulunamadı');
        const ex = await res.json();

        document.getElementById('soar-detail-title').textContent = ex.playbook_name || 'Playbook Detayı';
        document.getElementById('soar-detail-sub').textContent = `${formatRelativeTime(ex.created_at)} • Hedef: ${ex.target_host || '-'}`;

        const summaryEl = document.getElementById('soar-detail-summary');
        summaryEl.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; background: rgba(255,255,255,0.02); padding: 12px; border-radius: 6px; font-size: 12px;">
                <div><strong>Durum:</strong> <span class="badge badge-outline">${escapeHtml(ex.status)}</span></div>
                <div><strong>Tetikleyen:</strong> <span>${escapeHtml(ex.triggered_by)}</span></div>
                <div><strong>Hedef Host:</strong> <span class="mono-code">${escapeHtml(ex.target_host || '-')}</span></div>
                <div><strong>Uygulanan Eylem:</strong> <span>${ex.actions_executed || 0}</span></div>
            </div>
            ${ex.error_msg ? `<div style="margin-top: 8px; color: #ef4444; font-size: 11.5px; background: rgba(239, 68, 68, 0.1); padding: 8px; border-radius: 4px;">Hata Detayı: ${escapeHtml(ex.error_msg)}</div>` : ''}
        `;

        const stepsEl = document.getElementById('soar-detail-steps');
        const logs = ex.execution_log || [];
        if (logs.length === 0) {
            stepsEl.innerHTML = '<div class="text-muted" style="font-size: 12px;">Henüz kaydedilmiş adım telemetrisi yok.</div>';
        } else {
            stepsEl.innerHTML = logs.map((log, i) => `
                <div style="background: rgba(0,0,0,0.2); border: 1px solid var(--border-color); border-radius: 6px; padding: 10px 12px;">
                    <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px;">
                        <span style="font-weight: 600; color: var(--primary);">Adım ${i+1}: ${escapeHtml(log.action_type)}</span>
                        <span style="color: var(--text-muted);">${log.duration_ms || 0} ms • <span class="badge ${log.status === 'success' ? 'badge-success' : 'badge-danger'}">${escapeHtml(log.status)}</span></span>
                    </div>
                    <div style="font-size: 12px; color: var(--text-main);">${escapeHtml(log.message || '')}</div>
                </div>
            `).join('');
        }

    } catch (e) {
        showToast('Detay yüklenemedi: ' + e.message, 'error');
    }
}

function closeSOARExecDetail() {
    const modal = document.getElementById('modal-soar-exec-detail');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
}

async function openSOARRunModal(pbId = null, agentId = null, alertId = null) {
    const modal = document.getElementById('modal-soar-run-manual');
    if (!modal) return;
    modal.classList.add('active');
    modal.style.display = 'flex';

    const pbSelect = document.getElementById('soar-run-pb-select');
    const agSelect = document.getElementById('soar-run-agent-select');
    const alertInfo = document.getElementById('soar-run-alert-info');

    // Populate playbooks
    pbSelect.innerHTML = '<option value="">Playbook Seçin...</option>' + currentSOARPlaybooks.map(p =>
        `<option value="${p.id}" ${p.id === pbId ? 'selected' : ''}>${escapeHtml(p.name)} (${p.execution_mode})</option>`
    ).join('');

    // Populate agents
    try {
        const res = await fetch('/api/v1/endpoint/agents');
        if (res.ok) {
            const data = await res.json();
            const agents = data.agents || [];
            agSelect.innerHTML = '<option value="">Hedef Uç Nokta Seçin...</option>' + agents.map(a =>
                `<option value="${a.id}" ${a.id === agentId ? 'selected' : ''}>${escapeHtml(a.hostname)} (${escapeHtml(a.ip_address || '-')}) [${a.is_isolated ? 'ISOLATED' : 'NORMAL'}]</option>`
            ).join('');
        }
    } catch (_) {}

    if (alertId) {
        alertInfo.style.display = 'block';
        alertInfo.textContent = `🚨 Olay ID: ${alertId} ile ilişkilendirilecek`;
        alertInfo.setAttribute('data-alert-id', alertId);
    } else {
        alertInfo.style.display = 'none';
        alertInfo.removeAttribute('data-alert-id');
    }
}

function closeSOARRunModal() {
    const modal = document.getElementById('modal-soar-run-manual');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
}

async function submitSOARManualRun() {
    const pbId = document.getElementById('soar-run-pb-select').value;
    const agId = document.getElementById('soar-run-agent-select').value;
    const alertInfo = document.getElementById('soar-run-alert-info');
    const alertId = alertInfo ? alertInfo.getAttribute('data-alert-id') : null;

    if (!pbId) {
        showToast('Lütfen çalıştırılacak playbook seçin.', 'error');
        return;
    }

    const btn = document.getElementById('btn-submit-soar-run');
    if (btn) btn.disabled = true;

    try {
        const res = await fetch('/api/v1/soar/playbooks/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                playbook_id: pbId,
                agent_id: agId || undefined,
                alert_id: alertId || undefined
            })
        });
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || `HTTP ${res.status}`);
        }
        showToast('Playbook başarıyla tetiklendi ve adımlar yürütüldü!', 'success');
        closeSOARRunModal();
        loadSOARExecutions();
    } catch (e) {
        showToast('Çalıştırma hatası: ' + e.message, 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

window.openSOARModal = openSOARModal;
window.closeSOARModal = closeSOARModal;
window.switchSOARTab = switchSOARTab;
window.loadSOARPlaybooks = loadSOARPlaybooks;
window.toggleSOARPlaybook = toggleSOARPlaybook;
window.openSOAREditor = openSOAREditor;
window.submitSaveSOARPlaybook = submitSaveSOARPlaybook;
window.deleteSOARPlaybook = deleteSOARPlaybook;
window.loadSOARExecutions = loadSOARExecutions;
window.filterSOARHistory = filterSOARHistory;
window.openSOARExecDetail = openSOARExecDetail;
window.closeSOARExecDetail = closeSOARExecDetail;
window.approveSOARExecution = approveSOARExecution;
window.rejectSOARExecution = rejectSOARExecution;
window.openSOARRunModal = openSOARRunModal;
window.closeSOARRunModal = closeSOARRunModal;
window.submitSOARManualRun = submitSOARManualRun;

// --- Endpoint File & Registry Integrity Monitoring (FIM - Phase L) ---

let currentFIMEventDetail = null;

async function loadEndpointFIM() {
    await Promise.allSettled([
        loadEndpointFIMSummary(),
        loadEndpointFIMEvents()
    ]);
}

async function loadEndpointFIMSummary() {
    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/fim/summary?tenant=${encodeURIComponent(tenant)}`);
        if (!res.ok) return;
        const data = await res.json();

        const totalEl = document.getElementById('ep-fim-stat-total');
        if (totalEl) totalEl.textContent = Number(data.total_events || 0).toLocaleString();

        const crit = Number(data.critical_deviations !== undefined ? data.critical_deviations : (data.critical_events || 0)) + Number(data.high_deviations || 0);
        const critEl = document.getElementById('ep-fim-stat-critical');
        if (critEl) critEl.textContent = crit.toLocaleString();

        const critBadge = document.getElementById('ep-fim-crit-badge');
        if (critBadge) {
            critBadge.textContent = `${crit} CRIT`;
            critBadge.className = crit > 0 ? 'badge badge-danger' : 'badge badge-success';
        }

        const monitored = Number(data.monitored_paths_count !== undefined ? data.monitored_paths_count : (data.monitored_items || 0));
        const monEl = document.getElementById('ep-fim-stat-monitored');
        if (monEl) monEl.textContent = monitored.toLocaleString();

        const impacted = Number(data.impacted_agents_count !== undefined ? data.impacted_agents_count : (data.affected_agents || 0));
        const agentsEl = document.getElementById('ep-fim-stat-agents');
        if (agentsEl) agentsEl.textContent = impacted.toLocaleString();
    } catch (e) {
        console.warn('loadEndpointFIMSummary error:', e);
    }
}

async function simulateFIMEvent() {
    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/fim/simulate?tenant=${encodeURIComponent(tenant)}`, {
            method: 'POST'
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        showToast(data.message || 'FIM simülasyon olayı oluşturuldu!', 'success');
        await loadEndpointFIM();
    } catch (e) {
        showToast('Simülasyon hatası: ' + e.message, 'error');
    }
}

async function loadEndpointFIMEvents() {
    const tbody = document.getElementById('ep-fim-tbody');
    if (!tbody) return;

    const isTr = (window.i18n && window.i18n.currentLang === 'tr');

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const searchInput = document.getElementById('ep-fim-search');
        const search = searchInput ? searchInput.value.trim() : '';
        const changeTypeSelect = document.getElementById('ep-fim-filter-change-type');
        const changeType = changeTypeSelect ? changeTypeSelect.value : '';
        const severitySelect = document.getElementById('ep-fim-filter-severity');
        const severity = severitySelect ? severitySelect.value : '';

        const params = new URLSearchParams({
            tenant: tenant,
            limit: '100',
            offset: '0'
        });
        if (search) params.append('search', search);
        if (changeType) params.append('event_type', changeType);
        if (severity) params.append('severity', severity);

        tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--text-muted); padding: 24px;">${t('fim_loading', isTr ? 'Bütünlük izleme kayıtları taranıyor...' : 'Scanning integrity monitoring records...')}</td></tr>`;

        const res = await fetch(`/api/v1/endpoint/fim/events?${params.toString()}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const events = data.events || [];

        const countEl = document.getElementById('ep-fim-total-count');
        if (countEl) countEl.textContent = `${(data.total || events.length).toLocaleString()} ${t('fim_unit_events', isTr ? 'Olay' : 'Events')}`;

        if (events.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--text-muted); padding: 24px;">${t('fim_empty', isTr ? 'Henüz kayıtlı dosya veya bütünlük sapması bulunmuyor.' : 'No file or integrity deviations recorded yet.')}</td></tr>`;
            return;
        }

        tbody.innerHTML = events.map(ev => {
            // Severity badge
            let sevBadge = '<span class="badge badge-secondary">LOW</span>';
            const sev = (ev.severity || 'low').toLowerCase();
            if (sev === 'critical') sevBadge = '<span class="badge badge-danger">CRITICAL</span>';
            else if (sev === 'high') sevBadge = '<span class="badge badge-warning" style="background:#ea580c;color:#fff;">HIGH</span>';
            else if (sev === 'medium') sevBadge = '<span class="badge badge-warning">MEDIUM</span>';

            // Event Type badge
            let typeBadge = '<span class="badge badge-secondary">' + escapeHtml(ev.event_type || '') + '</span>';
            const et = (ev.event_type || '').toLowerCase();
            if (et === 'modified') typeBadge = '<span class="badge badge-warning">MODIFIED</span>';
            else if (et === 'created') typeBadge = '<span class="badge badge-success">CREATED</span>';
            else if (et === 'deleted') typeBadge = '<span class="badge badge-danger">DELETED</span>';
            else if (et === 'attribute_changed') typeBadge = '<span class="badge badge-info">ATTRIB</span>';

            // Hash deviation display
            let hashDev = '-';
            if (ev.previous_hash || ev.current_hash) {
                const prevShort = ev.previous_hash ? ev.previous_hash.substring(0, 7) + '..' : '∅';
                const currShort = ev.current_hash ? ev.current_hash.substring(0, 7) + '..' : t('fim_deleted_label', isTr ? 'silindi' : 'deleted');
                hashDev = `<span class="mono-code" style="font-size:11px; color:var(--text-muted);">${escapeHtml(prevShort)}</span> &rarr; <span class="mono-code" style="font-size:11px; font-weight:600; color:var(--danger);">${escapeHtml(currShort)}</span>`;
            }

            // MITRE badge
            let mitreHtml = '-';
            if (ev.mitre_technique || ev.mitre_tactic) {
                mitreHtml = `<span class="badge badge-secondary mono-code" style="font-size:10.5px;" title="${escapeHtml(ev.mitre_tactic || '')}">${escapeHtml(ev.mitre_technique || ev.mitre_tactic || '')}</span>`;
            }

            // Time formatted
            const dt = ev.timestamp ? new Date(ev.timestamp).toLocaleString(isTr ? 'tr-TR' : 'en-US') : '-';

            // Host info
            const hostDisplay = escapeHtml(ev.agent_hostname || t('fim_unknown_endpoint', isTr ? 'Uç Nokta' : 'Endpoint'));
            const ipDisplay = ev.agent_ip ? `<span style="font-size:11px; color:var(--text-muted); display:block;">${escapeHtml(ev.agent_ip)}</span>` : '';

            return `
                <tr>
                    <td>
                        <div style="font-weight: 600; font-size: 13px;">${hostDisplay}</div>
                        ${ipDisplay}
                    </td>
                    <td>${typeBadge}</td>
                    <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(ev.target_path || '')}">
                        <span class="mono-code" style="font-size: 12px; color: var(--accent);">${escapeHtml(ev.target_path || '')}</span>
                    </td>
                    <td>${hashDev}</td>
                    <td>${sevBadge}</td>
                    <td>${mitreHtml}</td>
                    <td style="font-size: 11.5px; color: var(--text-muted);">${dt}</td>
                    <td style="text-align: right;">
                        <button class="btn btn-sm btn-outline" onclick="openFIMDetail('${escapeHtml(ev.id)}')" title="${t('btn_inspect_detail', isTr ? 'Detaylı İnceleme' : 'Detailed Inspection')}">
                            <i class="fas fa-search-plus"></i> ${t('btn_edr_inspect', isTr ? 'İncele' : 'Inspect')}
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.error('loadEndpointFIMEvents error:', e);
        tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--danger); padding: 24px;">${isTr ? 'Hata' : 'Error'}: ${escapeHtml(e.message)}</td></tr>`;
    }
}


async function openFIMDetail(eventId) {
    if (!eventId) return;
    const isTr = (window.i18n && window.i18n.currentLang === 'tr');
    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/fim/events/${encodeURIComponent(eventId)}?tenant=${encodeURIComponent(tenant)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const ev = await res.json();
        currentFIMEventDetail = ev;

        // Populate modal fields
        const sevBadge = document.getElementById('fim-detail-severity-badge');
        if (sevBadge) {
            const sev = (ev.severity || 'low').toLowerCase();
            sevBadge.textContent = (ev.severity || 'LOW').toUpperCase();
            sevBadge.className = sev === 'critical' ? 'badge badge-danger' : (sev === 'high' ? 'badge badge-warning' : 'badge badge-secondary');
        }

        const typeBadge = document.getElementById('fim-detail-type-badge');
        if (typeBadge) typeBadge.textContent = (ev.event_type || 'MODIFIED').toUpperCase();

        const targetTypeBadge = document.getElementById('fim-detail-target-type-badge');
        if (targetTypeBadge) targetTypeBadge.textContent = (ev.target_type || 'FILE').toUpperCase();

        const timeEl = document.getElementById('fim-detail-timestamp');
        if (timeEl) timeEl.textContent = ev.timestamp ? new Date(ev.timestamp).toLocaleString(isTr ? 'tr-TR' : 'en-US') : '-';

        const pathEl = document.getElementById('fim-detail-target-path');
        if (pathEl) pathEl.textContent = ev.target_path || '-';

        const hostEl = document.getElementById('fim-detail-hostname');
        if (hostEl) hostEl.textContent = ev.agent_hostname || ev.agent_id || '-';

        const ipEl = document.getElementById('fim-detail-ip');
        if (ipEl) ipEl.textContent = ev.agent_ip || '-';

        const osEl = document.getElementById('fim-detail-os');
        if (osEl) osEl.textContent = ev.agent_os || 'Cross-Platform';

        const procEl = document.getElementById('fim-detail-process');
        if (procEl) procEl.textContent = ev.process_name ? `${ev.process_name} (PID: ${ev.process_pid || 0})` : (isTr ? 'Bilinmiyor / Arka Plan' : 'Unknown / Background');

        const userEl = document.getElementById('fim-detail-user');
        if (userEl) userEl.textContent = ev.user_name ? `${isTr ? 'Kullanıcı: ' : 'User: '}${ev.user_name}` : '';

        const prevHashEl = document.getElementById('fim-detail-prev-hash');
        if (prevHashEl) prevHashEl.textContent = ev.previous_hash || (isTr ? '(Referans hash yok / Yeni dosya)' : '(No baseline hash / New file)');

        const currHashEl = document.getElementById('fim-detail-curr-hash');
        if (currHashEl) currHashEl.textContent = ev.current_hash || (isTr ? '(Dosya silindi / Hash yok)' : '(File deleted / No hash)');

        const sizeEl = document.getElementById('fim-detail-size');
        if (sizeEl) sizeEl.textContent = ev.file_size_bytes ? `${Number(ev.file_size_bytes).toLocaleString()} ${isTr ? 'bayt' : 'bytes'}` : '-';

        const permsEl = document.getElementById('fim-detail-perms');
        if (permsEl) permsEl.textContent = ev.permissions || '-';

        const mitreTacticEl = document.getElementById('fim-detail-mitre-tactic');
        if (mitreTacticEl) mitreTacticEl.textContent = ev.mitre_tactic || 'Security Drift';

        const mitreTechEl = document.getElementById('fim-detail-mitre-technique');
        if (mitreTechEl) mitreTechEl.textContent = ev.mitre_technique || 'N/A';

        const extraDescEl = document.getElementById('fim-detail-extra-desc');
        if (extraDescEl) extraDescEl.textContent = ev.details || (isTr ? 'Kriptografik bütünlük sapması tespit edildi. Dosya içeriği veya metaverileri referans durumundan farklılık gösteriyor.' : 'Cryptographic integrity deviation detected. File contents or metadata differ from baseline state.');

        const modal = document.getElementById('modal-fim-detail');
        if (modal) {
            modal.classList.add('active');
            modal.style.display = 'flex';
        }
    } catch (e) {
        showToast((isTr ? 'FIM detay yükleme hatası: ' : 'FIM detail load error: ') + e.message, 'error');
    }
}

function closeFIMDetail() {
    const modal = document.getElementById('modal-fim-detail');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
}

function triggerFIMSOARAction() {
    if (!currentFIMEventDetail) return;
    const agId = currentFIMEventDetail.agent_id;
    closeFIMDetail();
    if (typeof openSOARRunModal === 'function') {
        openSOARRunModal(null, agId);
    } else {
        const isTr = (window.i18n && window.i18n.currentLang === 'tr');
        showToast(isTr ? 'SOAR modülü hazır değil.' : 'SOAR module is not ready.', 'warning');
    }
}

async function openFIMBaselines(agentId) {
    const isTr = (window.i18n && window.i18n.currentLang === 'tr');
    const modal = document.getElementById('modal-fim-baselines');
    if (modal) modal.style.display = 'flex';

    // Populate agent select dropdown
    const select = document.getElementById('fim-baseline-agent-select');
    if (select) {
        select.innerHTML = `<option value="">${isTr ? 'Yükleniyor...' : 'Loading...'}</option>`;
        try {
            const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
            const res = await fetch(`/api/v1/endpoint/agents?tenant=${encodeURIComponent(tenant)}`);
            if (res.ok) {
                const agents = await res.json();
                select.innerHTML = `<option value="">-- ${isTr ? 'Uç Nokta Seçin' : 'Select Endpoint'} --</option>` + 
                    agents.map(a => `<option value="${escapeHtml(a.id)}" ${agentId && a.id === agentId ? 'selected' : ''}>${escapeHtml(a.hostname)} (${escapeHtml(a.ip_address || a.os_type || '')})</option>`).join('');
                if (agentId) {
                    select.value = agentId;
                    loadFIMBaselinesForSelectedAgent();
                } else if (agents.length > 0) {
                    select.value = agents[0].id;
                    loadFIMBaselinesForSelectedAgent();
                }
            }
        } catch (e) {
            console.warn('Error loading agents for FIM baselines:', e);
        }
    }
}

async function loadFIMBaselinesForSelectedAgent() {
    const isTr = (window.i18n && window.i18n.currentLang === 'tr');
    const select = document.getElementById('fim-baseline-agent-select');
    const tbody = document.getElementById('ep-fim-baselines-tbody');
    if (!select || !tbody) return;

    const agentId = select.value;
    if (!agentId) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="color: var(--text-muted); padding: 20px;">${isTr ? 'Lütfen bir uç nokta seçin.' : 'Please select an endpoint.'}</td></tr>`;
        return;
    }

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="color: var(--text-muted); padding: 20px;">${isTr ? 'Kriptografik referanslar alınıyor...' : 'Fetching cryptographic baselines...'}</td></tr>`;
        const res = await fetch(`/api/v1/endpoint/fim/baselines?tenant=${encodeURIComponent(tenant)}&agent_id=${encodeURIComponent(agentId)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const baselines = await res.json();

        if (!baselines || baselines.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="color: var(--text-muted); padding: 20px;">${isTr ? 'Bu uç nokta için henüz referans verisi kaydedilmemiş. Ajan FIM tarama döngüsünü tamamladığında referanslar buraya otomatik işlenecektir.' : 'No baseline data recorded for this endpoint yet. Baselines will automatically appear here once the agent completes its FIM scan cycle.'}</td></tr>`;
            return;
        }

        tbody.innerHTML = baselines.map(b => {
            const shortHash = b.sha256_hash ? b.sha256_hash.substring(0, 16) + '...' : '-';
            const dt = b.last_seen ? new Date(b.last_seen).toLocaleString(isTr ? 'tr-TR' : 'en-US') : '-';
            return `
                <tr>
                    <td class="mono-code" style="font-size: 12px; color: var(--accent);">${escapeHtml(b.target_path || '')}</td>
                    <td><span class="badge badge-secondary">${escapeHtml((b.target_type || 'file').toUpperCase())}</span></td>
                    <td class="mono-code" style="font-size: 11px;" title="${escapeHtml(b.sha256_hash || '')}">${escapeHtml(shortHash)}</td>
                    <td style="font-size: 11.5px;">${b.file_size_bytes ? Number(b.file_size_bytes).toLocaleString() + ' B' : '-'}</td>
                    <td class="mono-code" style="font-size: 11px;">${escapeHtml(b.permissions || '-')}</td>
                    <td style="font-size: 11.5px; color: var(--text-muted);">${dt}</td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="color: var(--danger); padding: 20px;">${isTr ? 'Hata' : 'Error'}: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function closeFIMBaselines() {
    const modal = document.getElementById('modal-fim-baselines');
    if (modal) modal.style.display = 'none';
}

window.loadEndpointFIM = loadEndpointFIM;
window.loadEndpointFIMSummary = loadEndpointFIMSummary;
window.loadEndpointFIMEvents = loadEndpointFIMEvents;
window.openFIMDetail = openFIMDetail;
window.closeFIMDetail = closeFIMDetail;
window.triggerFIMSOARAction = triggerFIMSOARAction;
window.openFIMBaselines = openFIMBaselines;
window.closeFIMBaselines = closeFIMBaselines;
window.loadFIMBaselinesForSelectedAgent = loadFIMBaselinesForSelectedAgent;
window.simulateFIMEvent = simulateFIMEvent;

// ==========================================
// PHASE M: USB & PERIPHERAL STORAGE DLP
// ==========================================

let activeUSBSubTab = 'devices';

function switchUSBSubTab(tab) {
    activeUSBSubTab = tab;
    const btnDevices = document.getElementById('btn-usb-tab-devices');
    const btnEvents = document.getElementById('btn-usb-tab-events');
    const viewDevices = document.getElementById('usb-subview-devices');
    const viewEvents = document.getElementById('usb-subview-events');

    if (btnDevices && btnEvents && viewDevices && viewEvents) {
        if (tab === 'devices') {
            btnDevices.className = 'btn btn-sm btn-primary';
            btnEvents.className = 'btn btn-sm btn-outline';
            viewDevices.style.display = 'block';
            viewEvents.style.display = 'none';
            loadEndpointUSBDevices();
        } else {
            btnDevices.className = 'btn btn-sm btn-outline';
            btnEvents.className = 'btn btn-sm btn-primary';
            viewDevices.style.display = 'none';
            viewEvents.style.display = 'block';
            loadEndpointUSBEvents();
        }
    }
}

async function loadEndpointUSB() {
    loadEndpointUSBStats();
    if (activeUSBSubTab === 'devices') {
        loadEndpointUSBDevices();
    } else {
        loadEndpointUSBEvents();
    }
}

async function loadEndpointUSBStats() {
    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/usb/stats?tenant=${encodeURIComponent(tenant)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const elTotal = document.getElementById('ep-usb-stat-total');
        if (elTotal) elTotal.textContent = Number(data.total_devices || 0).toLocaleString();

        const elConn = document.getElementById('ep-usb-stat-connected');
        if (elConn) elConn.textContent = Number(data.connected_devices || 0).toLocaleString();

        const elConnBadge = document.getElementById('ep-usb-conn-badge');
        if (elConnBadge) elConnBadge.textContent = `${data.connected_devices || 0} Online`;

        const elBlock = document.getElementById('ep-usb-stat-blocked');
        if (elBlock) elBlock.textContent = Number(data.blocked_devices || 0).toLocaleString();

        const elBlockBadge = document.getElementById('ep-usb-block-badge');
        if (elBlockBadge) elBlockBadge.textContent = `${data.blocked_devices || 0} BLOCKED`;

        const elEvents = document.getElementById('ep-usb-stat-events');
        if (elEvents) elEvents.textContent = Number(data.total_events_24h || 0).toLocaleString();
    } catch (e) {
        console.error('loadEndpointUSBStats error:', e);
    }
}

async function loadEndpointUSBDevices() {
    const tbody = document.getElementById('ep-usb-dev-tbody');
    const totalCountEl = document.getElementById('ep-usb-dev-total-count');
    if (!tbody) return;

    try {
        const isTr = (window.i18n && window.i18n.currentLang === 'tr') || (!window.i18n && (navigator.language || '').toLowerCase().startsWith('tr'));
        const t = (key, fallback) => (window.i18n && typeof window.i18n.t === 'function') ? window.i18n.t(key) : fallback;

        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const connOnly = document.getElementById('ep-usb-filter-connected') ? document.getElementById('ep-usb-filter-connected').checked : false;
        const search = (document.getElementById('ep-usb-dev-search')?.value || '').trim();

        let url = `/api/v1/endpoint/usb/devices?tenant=${encodeURIComponent(tenant)}&connected_only=${connOnly}`;
        if (search) url += `&search=${encodeURIComponent(search)}`;

        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const devices = Array.isArray(data) ? data : (data && Array.isArray(data.devices) ? data.devices : []);
        const total = (data && data.total !== undefined) ? data.total : devices.length;

        const devUnit = t('usb_unit_devices', isTr ? 'Cihaz' : 'Devices');
        if (totalCountEl) totalCountEl.textContent = `${total} ${devUnit}`;

        if (devices.length === 0) {
            tbody.innerHTML = `<tr><td colspan="10" class="text-center" style="color: var(--text-muted); padding: 24px;">${escapeHtml(t('usb_no_devices', 'Kayıtlı USB depolama aygıtı bulunamadı.'))}</td></tr>`;
            return;
        }

        tbody.innerHTML = devices.map(d => {
            const isConn = d.is_connected;
            let statusText = t('usb_badge_allowed', isTr ? 'İZİN VERİLDİ' : 'ALLOWED');
            let statusClass = 'badge badge-success';
            if (d.access_status === 'blocked') {
                statusText = t('usb_badge_blocked', isTr ? 'ENGELLENDİ' : 'BLOCKED');
                statusClass = 'badge badge-danger';
            } else if (d.access_status === 'read_only') {
                statusText = t('usb_badge_readonly', isTr ? 'SALT OKUNUR' : 'READ-ONLY');
                statusClass = 'badge badge-warning';
            }
            const statusBadge = `<span class="${statusClass}">${escapeHtml(statusText)}</span>`;

            const wlBadge = d.is_whitelisted ? `<span class="badge badge-primary"><i class="fas fa-check"></i> ${escapeHtml(t('usb_badge_whitelisted', isTr ? 'Onaylı' : 'Approved'))}</span>` :
                                                `<span class="badge badge-secondary">${escapeHtml(t('usb_badge_unknown', isTr ? 'Bilinmiyor' : 'Unknown'))}</span>`;

            const connTitle = isConn ? t('usb_tooltip_connected', isTr ? 'Şu an Takılı' : 'Currently Plugged In') :
                                       t('usb_tooltip_disconnected', isTr ? 'Çıkarıldı' : 'Disconnected');
            const connDot = isConn ? `<span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--success); margin-right:5px;" title="${escapeHtml(connTitle)}"></span>` :
                                     `<span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--text-muted); margin-right:5px;" title="${escapeHtml(connTitle)}"></span>`;

            const lastSeen = d.last_seen ? (isTr ? new Date(d.last_seen).toLocaleString('tr-TR') : new Date(d.last_seen).toLocaleString('en-US')) : '-';
            const hwId = (d.vendor_id || d.product_id) ? `${d.vendor_id || '????'}:${d.product_id || '????'}` : '-';
            const capStr = d.capacity_bytes ? (d.capacity_bytes / (1024*1024*1024)).toFixed(1) + ' GB' : '-';
            const btnApproveText = t('usb_btn_approve', isTr ? 'Onayla' : 'Approve');
            const btnApprovedText = t('usb_btn_approved', isTr ? 'Onaylı' : 'Approved');

            return `
                <tr>
                    <td>
                        <div style="font-weight: 600; font-size: 12.5px;">${connDot}${escapeHtml(d.agent_hostname || d.agent_id || (isTr ? 'Bilinmiyor' : 'Unknown'))}</div>
                        <div style="font-size: 11px; color: var(--text-muted); margin-left: 13px;">${escapeHtml(d.agent_ip || '-')}</div>
                    </td>
                    <td>
                        <div style="font-weight: 500; font-size: 12.5px;">${escapeHtml(d.product_name || d.device_name || 'USB Disk')}</div>
                        <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(d.manufacturer || '-')}</div>
                    </td>
                    <td class="mono-code" style="font-size: 11.5px; font-weight: 600; color: var(--accent);">${escapeHtml(hwId)}</td>
                    <td class="mono-code" style="font-size: 11.5px;">${escapeHtml(d.serial_number || '-')}</td>
                    <td style="font-size: 12px; font-weight: 500;">${escapeHtml(d.mount_point || d.drive_letter || '-')}</td>
                    <td style="font-size: 12px;">${capStr}</td>
                    <td>${statusBadge}</td>
                    <td>${wlBadge}</td>
                    <td style="font-size: 11.5px; color: var(--text-muted);">${lastSeen}</td>
                    <td style="text-align: right; white-space: nowrap;">
                        ${!d.is_whitelisted ? `
                            <button class="btn btn-sm btn-outline" style="font-size: 11px; padding: 3px 8px;" onclick="quickAddUSBToWhitelist('${escapeHtml(d.vendor_id || '')}', '${escapeHtml(d.product_id || '')}', '${escapeHtml(d.serial_number || '')}', '${escapeHtml(d.product_name || d.device_name || '')}')" title="${escapeHtml(btnApproveText)}">
                                <i class="fas fa-shield-alt"></i> ${escapeHtml(btnApproveText)}
                            </button>
                        ` : `
                            <span style="font-size: 11px; color: var(--success);"><i class="fas fa-check-circle"></i> ${escapeHtml(btnApprovedText)}</span>
                        `}
                    </td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.error('loadEndpointUSBDevices error:', e);
        tbody.innerHTML = `<tr><td colspan="10" class="text-center" style="color: var(--danger); padding: 24px;">Hata: ${escapeHtml(e.message)}</td></tr>`;
    }
}

async function loadEndpointUSBEvents() {
    const tbody = document.getElementById('ep-usb-evt-tbody');
    const totalCountEl = document.getElementById('ep-usb-evt-total-count');
    if (!tbody) return;

    try {
        const isTr = (window.i18n && window.i18n.currentLang === 'tr') || (!window.i18n && (navigator.language || '').toLowerCase().startsWith('tr'));
        const t = (key, fallback) => (window.i18n && typeof window.i18n.t === 'function') ? window.i18n.t(key) : fallback;

        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const eventType = document.getElementById('ep-usb-filter-event-type')?.value || '';
        const search = (document.getElementById('ep-usb-evt-search')?.value || '').trim();

        let url = `/api/v1/endpoint/usb/events?tenant=${encodeURIComponent(tenant)}&limit=100`;
        if (eventType) url += `&event_type=${encodeURIComponent(eventType)}`;
        if (search) url += `&search=${encodeURIComponent(search)}`;

        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const events = Array.isArray(data) ? data : (data && Array.isArray(data.events) ? data.events : []);
        const total = (data && data.total !== undefined) ? data.total : events.length;

        const evtUnit = t('usb_unit_events', isTr ? 'Olay' : 'Events');
        if (totalCountEl) totalCountEl.textContent = `${total} ${evtUnit}`;

        if (events.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--text-muted); padding: 24px;">${escapeHtml(t('usb_no_events', 'DLP denetim olayı bulunamadı.'))}</td></tr>`;
            return;
        }

        tbody.innerHTML = events.map(ev => {
            const dt = ev.timestamp ? (isTr ? new Date(ev.timestamp).toLocaleString('tr-TR') : new Date(ev.timestamp).toLocaleString('en-US')) : '-';
            let typeBadge = `<span class="badge badge-secondary">${escapeHtml(t('usb_badge_other', isTr ? 'DİĞER' : 'OTHER'))}</span>`;
            if (ev.event_type === 'inserted') typeBadge = `<span class="badge badge-info"><i class="fas fa-plug"></i> ${escapeHtml(t('usb_badge_inserted', isTr ? 'TAKILDI' : 'INSERTED'))}</span>`;
            else if (ev.event_type === 'removed') typeBadge = `<span class="badge badge-secondary"><i class="fas fa-eject"></i> ${escapeHtml(t('usb_badge_removed', isTr ? 'ÇIKARILDI' : 'REMOVED'))}</span>`;
            else if (ev.event_type === 'blocked') typeBadge = `<span class="badge badge-danger"><i class="fas fa-ban"></i> ${escapeHtml(t('usb_badge_blocked', isTr ? 'ENGELLENDİ' : 'BLOCKED'))}</span>`;
            else if (ev.event_type === 'write_denied') typeBadge = `<span class="badge badge-warning"><i class="fas fa-pen-slash"></i> ${escapeHtml(t('usb_badge_write_denied', isTr ? 'YAZMA REDDİ' : 'WRITE DENIED'))}</span>`;
            else if (ev.event_type === 'unauthorized_whitelist') typeBadge = `<span class="badge badge-danger"><i class="fas fa-shield-virus"></i> ${escapeHtml(t('usb_badge_unauthorized', isTr ? 'YETKİSİZ LİSTE' : 'UNAUTHORIZED'))}</span>`;

            const hwId = (ev.vendor_id || ev.product_id) ? `${ev.vendor_id || '????'}:${ev.product_id || '????'}` : '';

            let mitreHtml = '<span class="badge badge-dark">T1052.001</span>';
            if (ev.mitre_technique) {
                mitreHtml = `<span class="badge badge-dark" title="${escapeHtml(ev.mitre_tactic || '')}">${escapeHtml(ev.mitre_technique)}</span>`;
            }

            return `
                <tr>
                    <td style="font-size: 11.5px; color: var(--text-muted); white-space: nowrap;">${dt}</td>
                    <td>
                        <div style="font-weight: 600; font-size: 12px;">${escapeHtml(ev.agent_hostname || ev.agent_id || (isTr ? 'Bilinmiyor' : 'Unknown'))}</div>
                        <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(ev.agent_ip || '-')}</div>
                    </td>
                    <td>${typeBadge}</td>
                    <td>
                        <div style="font-size: 12px; font-weight: 500;">${escapeHtml(ev.device_name || 'USB Disk')}</div>
                        <div class="mono-code" style="font-size: 11px; color: var(--accent);">${escapeHtml(hwId)} ${ev.serial_number ? '(' + escapeHtml(ev.serial_number) + ')' : ''}</div>
                    </td>
                    <td style="font-size: 12px; font-weight: 500;">${escapeHtml(ev.mount_point || ev.drive_letter || '-')}</td>
                    <td style="font-size: 12px; font-weight: 600;">${escapeHtml(ev.action_taken || 'audited')}</td>
                    <td>${mitreHtml}</td>
                    <td style="font-size: 11.5px; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(ev.details || '')}">
                        ${escapeHtml(ev.details || '-')}
                    </td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.error('loadEndpointUSBEvents error:', e);
        tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--danger); padding: 24px;">Hata: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function openUSBWhitelistModal() {
    const modal = document.getElementById('modal-usb-whitelist');
    if (modal) {
        modal.style.display = 'flex';
        loadUSBWhitelist();
    }
}

function closeUSBWhitelistModal() {
    const modal = document.getElementById('modal-usb-whitelist');
    if (modal) modal.style.display = 'none';
}

async function loadUSBWhitelist() {
    const tbody = document.getElementById('ep-usb-wl-tbody');
    if (!tbody) return;

    try {
        const isTr = (window.i18n && window.i18n.currentLang === 'tr') || (!window.i18n && (navigator.language || '').toLowerCase().startsWith('tr'));
        const t = (key, fallback) => (window.i18n && typeof window.i18n.t === 'function') ? window.i18n.t(key) : fallback;

        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/usb/whitelist?tenant=${encodeURIComponent(tenant)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const list = Array.isArray(data) ? data : (data && Array.isArray(data.whitelist) ? data.whitelist : []);

        if (list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="color: var(--text-muted); padding: 20px;">${escapeHtml(t('usb_no_whitelist', 'Tanımlı beyaz liste kaydı bulunmamaktadır. Tüm cihazlar uygulanan genel ilkeye göre değerlendirilir.'))}</td></tr>`;
            return;
        }

        const removeTitle = t('usb_btn_remove_whitelist', isTr ? 'Listeden Çıkar' : 'Remove from Whitelist');

        tbody.innerHTML = list.map(item => {
            const hwId = (item.vendor_id || item.product_id) ? `${item.vendor_id || '????'}:${item.product_id || '????'}` : '-';
            const dt = item.created_at ? (isTr ? new Date(item.created_at).toLocaleDateString('tr-TR') : new Date(item.created_at).toLocaleDateString('en-US')) : '-';
            return `
                <tr>
                    <td style="font-weight: 600; font-size: 12.5px;">${escapeHtml(item.device_name || '-')}</td>
                    <td class="mono-code" style="font-size: 11.5px; color: var(--accent); font-weight: 600;">${escapeHtml(hwId)}</td>
                    <td class="mono-code" style="font-size: 11.5px;">${escapeHtml(item.serial_number || '*')}</td>
                    <td style="font-size: 12px; color: var(--text-muted);">${escapeHtml(item.description || '-')}</td>
                    <td style="font-size: 12px;">${escapeHtml(item.approved_by || 'Admin')}</td>
                    <td style="font-size: 11.5px; color: var(--text-muted);">${dt}</td>
                    <td style="text-align: right;">
                        <button class="btn btn-sm btn-danger" style="padding: 2px 8px; font-size: 11px;" onclick="deleteUSBWhitelistEntry('${escapeHtml(item.id)}')" title="${escapeHtml(removeTitle)}">
                            <i class="fas fa-trash-alt"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.error('loadUSBWhitelist error:', e);
        tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="color: var(--danger); padding: 20px;">Hata: ${escapeHtml(e.message)}</td></tr>`;
    }
}

async function submitAddUSBWhitelist() {
    const name = (document.getElementById('wl-form-name')?.value || '').trim();
    const vid = (document.getElementById('wl-form-vid')?.value || '').trim().toUpperCase();
    const pid = (document.getElementById('wl-form-pid')?.value || '').trim().toUpperCase();
    const serial = (document.getElementById('wl-form-serial')?.value || '').trim();
    const desc = (document.getElementById('wl-form-desc')?.value || '').trim();

    if (!name) {
        showToast('Lütfen cihaz için bir ad veya tanım giriniz', 'warning');
        return;
    }
    if (!vid && !pid && !serial) {
        showToast('En az bir Vendor ID, Product ID veya Seri Numarası belirtmelisiniz', 'warning');
        return;
    }

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/usb/whitelist?tenant=${encodeURIComponent(tenant)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                device_name: name,
                vendor_id: vid,
                product_id: pid,
                serial_number: serial,
                description: desc
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${res.status}`);
        }

        showToast('✓ Cihaz kurumsal beyaz listeye eklendi', 'success');

        // Clear form
        if (document.getElementById('wl-form-name')) document.getElementById('wl-form-name').value = '';
        if (document.getElementById('wl-form-vid')) document.getElementById('wl-form-vid').value = '';
        if (document.getElementById('wl-form-pid')) document.getElementById('wl-form-pid').value = '';
        if (document.getElementById('wl-form-serial')) document.getElementById('wl-form-serial').value = '';
        if (document.getElementById('wl-form-desc')) document.getElementById('wl-form-desc').value = '';

        loadUSBWhitelist();
        loadEndpointUSBDevices();
    } catch (e) {
        showToast(`Hata: ${e.message}`, 'error');
    }
}

function quickAddUSBToWhitelist(vid, pid, serial, name) {
    const isTr = (window.i18n && window.i18n.currentLang === 'tr') || (!window.i18n && (navigator.language || '').toLowerCase().startsWith('tr'));
    openUSBWhitelistModal();
    if (document.getElementById('wl-form-name')) document.getElementById('wl-form-name').value = name || (isTr ? 'Onaylı USB Disk' : 'Approved USB Storage');
    if (document.getElementById('wl-form-vid')) document.getElementById('wl-form-vid').value = vid || '';
    if (document.getElementById('wl-form-pid')) document.getElementById('wl-form-pid').value = pid || '';
    if (document.getElementById('wl-form-serial')) document.getElementById('wl-form-serial').value = serial || '';
    if (document.getElementById('wl-form-desc')) document.getElementById('wl-form-desc').value = isTr ? 'Uç nokta tespitinden hızlı onaylandı' : 'Quick approved from endpoint discovery';
}

async function deleteUSBWhitelistEntry(id) {
    if (!id) return;
    const isTr = (window.i18n && window.i18n.currentLang === 'tr') || (!window.i18n && (navigator.language || '').toLowerCase().startsWith('tr'));
    const confirmMsg = isTr ? 'Bu USB cihazını onaylı beyaz listeden çıkarmak istediğinize emin misiniz?' : 'Are you sure you want to remove this USB device from the approved whitelist?';
    if (!confirm(confirmMsg)) return;

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/usb/whitelist/${encodeURIComponent(id)}?tenant=${encodeURIComponent(tenant)}`, {
            method: 'DELETE'
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${res.status}`);
        }

        showToast(isTr ? 'Cihaz beyaz listeden çıkarıldı' : 'Device removed from whitelist', 'info');
        loadUSBWhitelist();
        loadEndpointUSBDevices();
    } catch (e) {
        showToast(`${isTr ? 'Silme hatası' : 'Delete error'}: ${e.message}`, 'error');
    }
}

async function simulateUSBEvent() {
    try {
        showToast('USB DLP test olayı simüle ediliyor...', 'info');
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/usb/simulate?tenant=${encodeURIComponent(tenant)}`, {
            method: 'POST'
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${res.status}`);
        }

        const data = await res.json();
        showToast(`✓ Test USB olayı oluşturuldu ve SIEM alarmı tetiklendi!`, 'success');
        loadEndpointUSB();
    } catch (e) {
        showToast(`Simülasyon hatası: ${e.message}`, 'error');
    }
}

window.switchUSBSubTab = switchUSBSubTab;
window.loadEndpointUSB = loadEndpointUSB;
window.loadEndpointUSBStats = loadEndpointUSBStats;
window.loadEndpointUSBDevices = loadEndpointUSBDevices;
window.loadEndpointUSBEvents = loadEndpointUSBEvents;
window.openUSBWhitelistModal = openUSBWhitelistModal;
window.closeUSBWhitelistModal = closeUSBWhitelistModal;
window.loadUSBWhitelist = loadUSBWhitelist;
window.submitAddUSBWhitelist = submitAddUSBWhitelist;
window.quickAddUSBToWhitelist = quickAddUSBToWhitelist;
window.deleteUSBWhitelistEntry = deleteUSBWhitelistEntry;
window.simulateUSBEvent = simulateUSBEvent;

// =========================================================================
// 5.7. BEHAVIORAL ANOMALY & MALICIOUS SCRIPT EDR (PHASE N)
// =========================================================================
let currentEDRAnomalies = [];
let activeEDRDetail = null;

async function loadEndpointEDR() {
    loadEndpointEDRStats();
    loadEndpointEDRAnomalies();
}

async function loadEndpointEDRStats() {
    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/edr/stats?tenant=${encodeURIComponent(tenant)}`);
        if (!res.ok) return;
        const stats = await res.json();

        const totalEl = document.getElementById('ep-edr-stat-total');
        const critEl = document.getElementById('ep-edr-stat-critical');
        const critBadge = document.getElementById('ep-edr-stat-crit-badge');
        const scriptsEl = document.getElementById('ep-edr-stat-scripts');
        const termEl = document.getElementById('ep-edr-stat-terminated');
        const agentsEl = document.getElementById('ep-edr-stat-agents');

        if (totalEl) totalEl.textContent = Number(stats.total_detections || 0).toLocaleString();
        if (critEl) critEl.textContent = Number(stats.critical_threats || 0).toLocaleString();
        if (critBadge) critBadge.textContent = `${stats.critical_threats || 0} CRITICAL`;
        if (scriptsEl) scriptsEl.textContent = Number(stats.suspicious_scripts || 0).toLocaleString();
        if (termEl) termEl.textContent = Number(stats.processes_terminated || 0).toLocaleString();
        if (agentsEl) agentsEl.textContent = Number(stats.monitored_agents_count || 0).toLocaleString();
    } catch (e) {
        console.error('loadEndpointEDRStats error:', e);
    }
}

async function loadEndpointEDRAnomalies() {
    const tbody = document.getElementById('ep-edr-tbody');
    if (!tbody) return;

    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const isTr = !window.i18n || window.i18n.currentLang === 'tr';

    tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--text-muted); padding: 24px;">${t('edr_loading')}</td></tr>`;

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const searchInput = document.getElementById('ep-edr-search');
        const search = searchInput ? searchInput.value.trim() : '';
        const sevSelect = document.getElementById('ep-edr-filter-severity');
        const severity = sevSelect ? sevSelect.value : 'all';

        let url = `/api/v1/endpoint/edr/anomalies?tenant=${encodeURIComponent(tenant)}&limit=100`;
        if (severity && severity !== 'all') url += `&severity=${encodeURIComponent(severity)}`;
        if (search) url += `&search=${encodeURIComponent(search)}`;

        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        currentEDRAnomalies = data.anomalies || [];
        const totalCountEl = document.getElementById('ep-edr-total-count');
        if (totalCountEl) totalCountEl.textContent = `${data.total || 0} ${isTr ? 'Olay' : 'Events'}`;

        if (currentEDRAnomalies.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--text-muted); padding: 28px;">${t('edr_no_data')}</td></tr>`;
            return;
        }

        tbody.innerHTML = currentEDRAnomalies.map(a => {
            const timeStr = a.timestamp ? new Date(a.timestamp).toLocaleString(isTr ? 'tr-TR' : 'en-US') : '-';
            const sev = (a.severity || 'medium').toLowerCase();
            let sevBadge = '<span class="badge badge-info">MEDIUM</span>';
            if (sev === 'critical') sevBadge = '<span class="badge badge-danger">CRITICAL</span>';
            else if (sev === 'high') sevBadge = '<span class="badge badge-warning">HIGH</span>';
            else if (sev === 'low') sevBadge = '<span class="badge badge-secondary">LOW</span>';

            const action = (a.action_taken || 'audited').toLowerCase();
            let actionBadge = '<span class="badge badge-outline">AUDITED</span>';
            if (action === 'terminated') actionBadge = '<span class="badge badge-success">TERMINATED</span>';
            else if (action === 'kill_failed') actionBadge = '<span class="badge badge-danger">KILL FAILED</span>';

            const mitreBadge = a.mitre_technique ? `<span class="badge badge-secondary mono-code" style="font-size: 10px; margin-left: 4px;">${escapeHtml(a.mitre_technique)}</span>` : '';
            const parentDisplay = a.parent_name ? `<div style="font-weight: 600; font-size: 12px;">${escapeHtml(a.parent_name)}</div><div class="mono-code" style="font-size: 10.5px; color: var(--text-muted);">PPID: ${a.parent_pid}</div>` : '<span style="color: var(--text-muted);">-</span>';

            return `
                <tr style="border-bottom: 1px solid var(--border-color);">
                    <td style="white-space: nowrap; font-size: 12px; color: var(--text-muted);">${timeStr}</td>
                    <td>
                        <div style="font-weight: 600; font-size: 13px;">${escapeHtml(a.agent_hostname || 'Unknown')}</div>
                        <div class="mono-code" style="font-size: 11px; color: var(--text-muted);">${escapeHtml(a.agent_ip || '')}</div>
                    </td>
                    <td>${sevBadge}</td>
                    <td>
                        <div style="font-weight: 600; font-size: 12.5px; color: var(--text-primary);">${escapeHtml(a.rule_name || a.rule_id)}</div>
                        <div style="display: flex; gap: 4px; align-items: center; margin-top: 2px;">
                            <span class="mono-code" style="font-size: 11px; color: var(--text-muted);">${escapeHtml(a.rule_id)}</span>
                            ${mitreBadge}
                        </div>
                    </td>
                    <td>
                        <div style="font-weight: 700; font-size: 13px; color: ${sev === 'critical' ? 'var(--danger)' : 'var(--text-primary)'};">${escapeHtml(a.process_name)}</div>
                        <div class="mono-code" style="font-size: 11px; color: var(--text-muted);">PID: ${a.pid}</div>
                    </td>
                    <td>${parentDisplay}</td>
                    <td>${actionBadge}</td>
                    <td style="text-align: right; white-space: nowrap;">
                        <button class="btn btn-sm btn-outline" onclick="openEDRDetail('${a.id}')" title="${t('btn_edr_inspect')}">
                            <i class="fas fa-eye"></i> ${t('btn_edr_inspect')}
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="killEDRProcess('${a.agent_id}', ${a.pid}, '${escapeHtml(a.process_name)}', '${escapeHtml(a.agent_hostname)}')" title="${t('btn_edr_kill')}" style="margin-left: 4px;">
                            <i class="fas fa-skull"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.error('loadEndpointEDRAnomalies error:', e);
        tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--danger); padding: 24px;">Hata: ${escapeHtml(e.message)}</td></tr>`;
    }
}

async function openEDRDetail(anomalyId) {
    if (!anomalyId) return;
    const isTr = !window.i18n || window.i18n.currentLang === 'tr';
    const modal = document.getElementById('modal-edr-detail');
    if (!modal) return;

    try {
        let a = (currentEDRAnomalies || []).find(x => String(x.id).toLowerCase() === String(anomalyId).toLowerCase());
        if (!a) {
            const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
            const res = await fetch(`/api/v1/endpoint/edr/anomalies/${encodeURIComponent(anomalyId)}?tenant=${encodeURIComponent(tenant)}`);
            if (res.ok) {
                const data = await res.json();
                a = data.anomaly || data;
            }
        }

        if (!a) {
            showToast(isTr ? 'EDR anomali detayı bulunamadı.' : 'EDR anomaly detail not found.', 'error');
            return;
        }

        activeEDRDetail = a;

        // Badges
        const sevBadge = document.getElementById('edr-detail-severity-badge');
        if (sevBadge) {
            const sev = (a.severity || 'medium').toLowerCase();
            sevBadge.className = `badge badge-${sev === 'critical' ? 'danger' : (sev === 'high' ? 'warning' : 'info')}`;
            sevBadge.textContent = (a.severity || 'MEDIUM').toUpperCase();
        }

        const actionBadge = document.getElementById('edr-detail-action-badge');
        if (actionBadge) {
            const act = (a.action_taken || 'audited').toLowerCase();
            actionBadge.className = `badge badge-${act === 'terminated' ? 'success' : 'warning'}`;
            actionBadge.textContent = (a.action_taken || 'AUDITED').toUpperCase();
        }

        const ruleBadge = document.getElementById('edr-detail-rule-badge');
        if (ruleBadge) ruleBadge.textContent = a.rule_id || 'EDR';

        const timeEl = document.getElementById('edr-detail-timestamp');
        if (timeEl) timeEl.textContent = a.timestamp ? new Date(a.timestamp).toLocaleString(isTr ? 'tr-TR' : 'en-US') : '-';

        // Overview
        const hostEl = document.getElementById('edr-detail-hostname');
        if (hostEl) hostEl.textContent = a.agent_hostname || 'Unknown';
        const ipEl = document.getElementById('edr-detail-ip');
        if (ipEl) ipEl.textContent = a.agent_ip || '';
        const userEl = document.getElementById('edr-detail-username');
        if (userEl) userEl.textContent = a.username || 'SYSTEM / ROOT';
        const ruleNameEl = document.getElementById('edr-detail-rulename');
        if (ruleNameEl) ruleNameEl.textContent = a.rule_name || a.rule_id || '-';
        const ruleIdEl = document.getElementById('edr-detail-ruleid');
        if (ruleIdEl) ruleIdEl.textContent = a.rule_id || '';

        // Process Tree
        const pNameEl = document.getElementById('edr-detail-process-name');
        if (pNameEl) pNameEl.textContent = a.process_name || 'unknown';
        const pidEl = document.getElementById('edr-detail-pid');
        if (pidEl) pidEl.textContent = `PID: ${a.pid || 0}`;
        const cmdEl = document.getElementById('edr-detail-commandline');
        if (cmdEl) cmdEl.textContent = a.command_line || a.process_name || '-';

        const parentNameEl = document.getElementById('edr-detail-parent-name');
        if (parentNameEl) parentNameEl.textContent = a.parent_name || 'System / init (0)';
        const parentPidEl = document.getElementById('edr-detail-parent-pid');
        if (parentPidEl) parentPidEl.textContent = `PPID: ${a.parent_pid || 0}`;
        const parentCmdEl = document.getElementById('edr-detail-parent-cmd');
        if (parentCmdEl) parentCmdEl.textContent = a.parent_command_line || a.parent_name || 'No command line recorded';

        // MITRE
        const mitreTacticEl = document.getElementById('edr-detail-mitre-tactic');
        if (mitreTacticEl) mitreTacticEl.textContent = a.mitre_tactic || 'Execution';
        const mitreTechEl = document.getElementById('edr-detail-mitre-technique');
        if (mitreTechEl) mitreTechEl.textContent = a.mitre_technique || 'T1059';
        const descEl = document.getElementById('edr-detail-full-desc');
        if (descEl) descEl.textContent = a.details || 'Behavioral anomaly detected on endpoint.';

        modal.classList.add('active');
        modal.style.display = 'flex';
    } catch (err) {
        console.error('openEDRDetail error:', err);
        showToast((isTr ? 'EDR Detayı açılırken hata: ' : 'Error opening EDR detail: ') + err.message, 'error');
    }
}

function closeEDRDetail() {
    const modal = document.getElementById('modal-edr-detail');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
    activeEDRDetail = null;
}

async function executeModalEDRKill() {
    if (!activeEDRDetail) return;
    const { agent_id, pid, process_name, agent_hostname } = activeEDRDetail;
    closeEDRDetail();
    await killEDRProcess(agent_id, pid, process_name, agent_hostname);
}

async function killEDRProcess(agentId, pid, processName, hostname) {
    const t = window.i18n ? window.i18n.t.bind(window.i18n) : (k) => k;
    const isTr = !window.i18n || window.i18n.currentLang === 'tr';

    const confirmMsg = isTr
        ? `PID ${pid} (${processName}) sürecini uç noktada (${hostname || 'ajan'}) zorla sonlandırmak istediğinizden emin misiniz?`
        : `Are you sure you want to forcibly terminate PID ${pid} (${processName}) on endpoint (${hostname || 'agent'})?`;

    if (!confirm(confirmMsg)) return;

    try {
        showToast(isTr ? 'Süreç sonlandırma görevi ajana iletiliyor...' : 'Dispatching process termination task...', 'info');

        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/edr/kill?tenant=${encodeURIComponent(tenant)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                agent_id: agentId,
                pid: pid,
                process_name: processName,
                force: true
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${res.status}`);
        }

        showToast(`✓ ${t('edr_kill_dispatched')}`, 'success');
        setTimeout(() => loadEndpointEDRAnomalies(), 1200);
    } catch (e) {
        showToast(`Hata: ${e.message}`, 'error');
    }
}

async function simulateEDREvent() {
    try {
        const isTr = !window.i18n || window.i18n.currentLang === 'tr';
        showToast(isTr ? '⚡ EDR Web Shell & LOLBin saldırı senaryosu simüle ediliyor...' : '⚡ Simulating EDR Web Shell & LOLBin attack scenario...', 'info');
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/edr/simulate?tenant=${encodeURIComponent(tenant)}`, {
            method: 'POST'
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${res.status}`);
        }

        const data = await res.json();
        showToast(isTr ? '✓ Simüle edilmiş saldırı tespiti oluşturuldu ve SIEM alarmı tetiklendi!' : '✓ Simulated attack event generated and SIEM alert dispatched!', 'success');
        loadEndpointEDR();
    } catch (e) {
        showToast(`Simülasyon hatası: ${e.message}`, 'error');
    }
}

window.loadEndpointEDR = loadEndpointEDR;
window.loadEndpointEDRStats = loadEndpointEDRStats;
window.loadEndpointEDRAnomalies = loadEndpointEDRAnomalies;
window.openEDRDetail = openEDRDetail;
window.closeEDRDetail = closeEDRDetail;
window.executeModalEDRKill = executeModalEDRKill;
window.killEDRProcess = killEDRProcess;
window.simulateEDREvent = simulateEDREvent;

// ==========================================
// PHASE O: ENDPOINT NETWORK TRAFFIC, DNS AUDITING & MICRO-SEGMENTATION
// ==========================================

let activeNetworkSubtab = 'conns';

function switchNetworkSubtab(tab) {
    activeNetworkSubtab = tab;
    const connsBtn = document.getElementById('tab-net-conns-btn');
    const dnsBtn = document.getElementById('tab-net-dns-btn');
    const connsDiv = document.getElementById('subtab-net-conns');
    const dnsDiv = document.getElementById('subtab-net-dns');

    if (tab === 'conns') {
        if (connsBtn) {
            connsBtn.classList.add('active');
            connsBtn.style.color = 'var(--accent)';
            connsBtn.style.borderBottom = '2px solid var(--accent)';
        }
        if (dnsBtn) {
            dnsBtn.classList.remove('active');
            dnsBtn.style.color = 'var(--text-muted)';
            dnsBtn.style.borderBottom = '2px solid transparent';
        }
        if (connsDiv) connsDiv.style.display = 'block';
        if (dnsDiv) dnsDiv.style.display = 'none';
        loadEndpointNetworkConnections();
    } else {
        if (dnsBtn) {
            dnsBtn.classList.add('active');
            dnsBtn.style.color = 'var(--accent)';
            dnsBtn.style.borderBottom = '2px solid var(--accent)';
        }
        if (connsBtn) {
            connsBtn.classList.remove('active');
            connsBtn.style.color = 'var(--text-muted)';
            connsBtn.style.borderBottom = '2px solid transparent';
        }
        if (connsDiv) connsDiv.style.display = 'none';
        if (dnsDiv) dnsDiv.style.display = 'block';
        loadEndpointNetworkDNS();
    }
}

async function loadEndpointNetwork() {
    loadEndpointNetworkStats();
    if (activeNetworkSubtab === 'conns') {
        loadEndpointNetworkConnections();
    } else {
        loadEndpointNetworkDNS();
    }
}

async function loadEndpointNetworkStats() {
    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/network/stats?tenant=${encodeURIComponent(tenant)}`);
        if (!res.ok) return;
        const data = await res.json();

        const elConns = document.getElementById('ep-net-stat-conns');
        const elSusp = document.getElementById('ep-net-stat-suspicious');
        const elC2 = document.getElementById('ep-net-stat-c2');
        const elDga = document.getElementById('ep-net-stat-dga');
        const elFw = document.getElementById('ep-net-stat-fw');

        if (elConns) elConns.textContent = (data.total_connections_observed || 0).toLocaleString();
        if (elSusp) elSusp.textContent = (data.suspicious_outbound_conns || 0).toLocaleString();
        if (elC2) elC2.textContent = (data.c2_beacons_detected || 0).toLocaleString();
        if (elDga) elDga.textContent = (data.dga_domains_blocked || 0).toLocaleString();
        if (elFw) elFw.textContent = (data.active_firewall_blocks || 0).toLocaleString();
    } catch (e) {
        console.error('loadEndpointNetworkStats error:', e);
    }
}

async function loadEndpointNetworkConnections() {
    const tbody = document.getElementById('ep-net-conns-tbody');
    const countEl = document.getElementById('ep-net-conns-total-count');
    if (!tbody) return;
    const t = (k, fb) => (window.i18n ? window.i18n.t(k, fb) : (fb || k));

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const search = document.getElementById('ep-net-conn-search') ? document.getElementById('ep-net-conn-search').value.trim() : '';
        const severity = document.getElementById('ep-net-filter-severity') ? document.getElementById('ep-net-filter-severity').value : 'all';

        let url = `/api/v1/endpoint/network/connections?tenant=${encodeURIComponent(tenant)}&limit=100`;
        if (search) url += `&search=${encodeURIComponent(search)}`;
        if (severity && severity !== 'all') url += `&severity=${encodeURIComponent(severity)}`;

        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const conns = data.connections || [];
        if (countEl) countEl.textContent = `${data.total || conns.length} ${t('net_unit_conns') || 'Bağlantı'}`;

        if (conns.length === 0) {
            tbody.innerHTML = `<tr><td colspan="9" class="text-center" style="color: var(--text-muted); padding: 28px;">${t('net_no_conns') || 'Henüz kaydedilmiş ağ soketi veya telemetri bulunmuyor.'}</td></tr>`;
            return;
        }

        tbody.innerHTML = conns.map(c => {
            const timeStr = formatDateTime(c.created_at || c.timestamp);
            const sev = (c.threat_severity || 'info').toLowerCase();
            let sevBadge = `<span class="badge badge-secondary">INFO</span>`;
            if (sev === 'critical') sevBadge = `<span class="badge badge-danger">CRITICAL</span>`;
            else if (sev === 'high') sevBadge = `<span class="badge badge-warning" style="background: rgba(245, 158, 11, 0.2); color: #f59e0b;">HIGH</span>`;

            let stateBadge = `<span style="font-size: 11px; padding: 2px 6px; border-radius: 4px; background: rgba(59, 130, 246, 0.1); color: var(--accent); font-family: monospace;">${escapeHtml(c.state || 'ESTABLISHED')}</span>`;
            if (c.direction === 'listening') {
                stateBadge = `<span style="font-size: 11px; padding: 2px 6px; border-radius: 4px; background: rgba(148, 163, 184, 0.15); color: var(--text-muted); font-family: monospace;">LISTEN</span>`;
            }

            const localAddr = `${escapeHtml(c.local_ip || '0.0.0.0')}:${c.local_port || 0}`;
            const remoteAddr = c.remote_ip ? `${escapeHtml(c.remote_ip)}:${c.remote_port}` : '<span style="color: var(--text-muted);">-</span>';
            const reasonHtml = c.threat_reason ? `<div style="font-size: 11px; color: var(--danger); margin-top: 3px;">⚠️ ${escapeHtml(c.threat_reason)}</div>` : '';

            let actionBtn = '';
            if (c.remote_ip && c.direction === 'outbound' && !isPrivateIPString(c.remote_ip)) {
                if (c.action_taken === 'blocked') {
                    actionBtn = `<span class="badge badge-danger" style="font-size: 11px;">Engellendi</span>`;
                } else {
                    actionBtn = `<button class="btn btn-outline btn-sm" style="font-size: 11px; padding: 3px 8px; color: var(--danger); border-color: rgba(239, 68, 68, 0.4);" onclick="blockEndpointNetworkIP('${escapeHtml(c.remote_ip)}', '${escapeHtml(c.agent_hostname)}', '${escapeHtml(c.threat_reason || 'Şüpheli soket aktivitesi')}')" title="Hedef IP'yi host seviyesinde engelle"><i class="fas fa-ban"></i> Blokla</button>`;
                }
            } else {
                actionBtn = `<span style="color: var(--text-muted); font-size: 11px;">-</span>`;
            }

            return `<tr>
                <td style="font-size: 12px; white-space: nowrap; color: var(--text-muted);">${timeStr}</td>
                <td>
                    <div style="font-weight: 600; font-size: 13px;">${escapeHtml(c.agent_hostname || 'Bilinmeyen')}</div>
                    <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(c.agent_ip || '')}</div>
                </td>
                <td>
                    <div style="font-weight: 600; font-size: 12.5px; font-family: monospace;">${escapeHtml(c.process_name || 'system')}</div>
                    <div style="font-size: 11px; color: var(--text-muted);">PID: ${c.pid || 0}</div>
                </td>
                <td><span style="font-weight: 600; text-transform: uppercase; font-size: 11px;">${escapeHtml(c.protocol || 'tcp')}</span></td>
                <td style="font-family: monospace; font-size: 11.5px; color: var(--text-muted);">${localAddr}</td>
                <td style="font-family: monospace; font-size: 12px; font-weight: 600;">${remoteAddr}</td>
                <td>${stateBadge}</td>
                <td>
                    ${sevBadge}
                    ${reasonHtml}
                </td>
                <td style="text-align: right;">${actionBtn}</td>
            </tr>`;
        }).join('');
    } catch (e) {
        console.error('loadEndpointNetworkConnections error:', e);
        tbody.innerHTML = `<tr><td colspan="9" class="text-center" style="color: var(--danger); padding: 24px;">Hata: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function isPrivateIPString(ip) {
    if (!ip) return true;
    if (ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0') return true;
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.') || ip.startsWith('172.17.') || ip.startsWith('172.18.') || ip.startsWith('172.19.') || ip.startsWith('172.2') || ip.startsWith('172.30.') || ip.startsWith('172.31.')) return true;
    return false;
}

async function loadEndpointNetworkDNS() {
    const tbody = document.getElementById('ep-net-dns-tbody');
    const countEl = document.getElementById('ep-net-dns-total-count');
    if (!tbody) return;
    const t = (k, fb) => (window.i18n ? window.i18n.t(k, fb) : (fb || k));

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const search = document.getElementById('ep-net-dns-search') ? document.getElementById('ep-net-dns-search').value.trim() : '';
        const dgaOnly = document.getElementById('ep-net-dns-dga-only') && document.getElementById('ep-net-dns-dga-only').checked;

        let url = `/api/v1/endpoint/network/dns?tenant=${encodeURIComponent(tenant)}&limit=100`;
        if (search) url += `&search=${encodeURIComponent(search)}`;
        if (dgaOnly) url += `&dga_only=true`;

        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const queries = data.queries || [];
        if (countEl) countEl.textContent = `${data.total || queries.length} ${t('net_unit_queries') || 'Sorgu'}`;

        if (queries.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--text-muted); padding: 28px;">${t('net_no_dns') || 'Henüz kaydedilmiş DNS sorgusu bulunmuyor.'}</td></tr>`;
            return;
        }

        tbody.innerHTML = queries.map(q => {
            const timeStr = formatDateTime(q.created_at || q.timestamp);
            let dgaBadge = `<span class="badge badge-secondary" style="font-size: 10.5px;">Normal</span>`;
            if (q.is_dga || q.is_malicious) {
                dgaBadge = `<span class="badge badge-danger" style="font-size: 11px;">⚠️ DGA / Riskli</span>`;
            }

            let entropyColor = 'var(--text-muted)';
            if (q.entropy_score >= 3.75) entropyColor = '#ec4899';
            else if (q.entropy_score >= 3.3) entropyColor = 'var(--warning)';

            let actionBadge = `<span class="badge badge-info" style="font-size: 10.5px;">${escapeHtml(q.action_taken || 'resolved')}</span>`;
            if (q.action_taken === 'blocked') {
                actionBadge = `<span class="badge badge-danger" style="font-size: 10.5px;">BLOCKED</span>`;
            }

            const threatDesc = q.threat_reason ? `<div style="font-size: 11px; color: var(--danger); margin-top: 2px;">${escapeHtml(q.threat_reason)}</div>` : '';

            return `<tr>
                <td style="font-size: 12px; white-space: nowrap; color: var(--text-muted);">${timeStr}</td>
                <td>
                    <div style="font-weight: 600; font-size: 13px;">${escapeHtml(q.agent_hostname || 'Bilinmeyen')}</div>
                    <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(q.agent_ip || '')}</div>
                </td>
                <td style="font-family: monospace; font-size: 12px;">${escapeHtml(q.process_name || 'resolver')}</td>
                <td>
                    <div style="font-family: monospace; font-size: 12.5px; font-weight: 600; color: var(--text-primary);">${escapeHtml(q.query_domain)}</div>
                    ${threatDesc}
                </td>
                <td style="font-size: 11.5px;">
                    <span style="font-weight: 600;">${escapeHtml(q.query_type || 'A')}</span> &bull; 
                    <span style="color: var(--text-muted);">${escapeHtml(q.response_code || 'NOERROR')}</span>
                </td>
                <td>
                    <span style="font-family: monospace; font-weight: 700; color: ${entropyColor};">${Number(q.entropy_score || 0).toFixed(2)}</span>
                    <span style="font-size: 10px; color: var(--text-muted);"> bits</span>
                </td>
                <td>${dgaBadge}</td>
                <td style="text-align: right;">${actionBadge}</td>
            </tr>`;
        }).join('');
    } catch (e) {
        console.error('loadEndpointNetworkDNS error:', e);
        tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: var(--danger); padding: 24px;">Hata: ${escapeHtml(e.message)}</td></tr>`;
    }
}

async function blockEndpointNetworkIP(ip, hostname, reason) {
    const isTr = !window.i18n || window.i18n.currentLang === 'tr';
    const confirmMsg = isTr
        ? `'${ip}' IP adresini host seviyesinde engellemek ve mikro-izolasyon kuralı oluşturmak istediğinizden emin misiniz?`
        : `Are you sure you want to block IP '${ip}' at host level and create a micro-isolation rule?`;

    if (!confirm(confirmMsg)) return;

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch('/api/v1/endpoint/network/firewall/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                remote_ip: ip,
                reason: reason || 'Host containment via Network EDR'
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${res.status}`);
        }

        showToast(isTr ? `✓ ${ip} IP adresi için güvenlik duvarı engelleme kuralı eklendi` : `✓ Firewall isolation rule added for IP ${ip}`, 'success');
        loadEndpointNetwork();
    } catch (e) {
        showToast(`Hata: ${e.message}`, 'error');
    }
}

function openNetworkSimulateModal() {
    const modal = document.getElementById('modal-network-simulate');
    if (modal) {
        modal.classList.add('active');
        modal.style.display = 'flex';
    }
}

function closeNetworkSimulateModal() {
    const modal = document.getElementById('modal-network-simulate');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
}

async function executeNetworkSimulation() {
    const scenarioType = document.getElementById('net-sim-scenario') ? document.getElementById('net-sim-scenario').value : 'c2_beacon';
    const hostname = document.getElementById('net-sim-hostname') ? document.getElementById('net-sim-hostname').value.trim() : '';

    closeNetworkSimulateModal();
    const isTr = !window.i18n || window.i18n.currentLang === 'tr';
    showToast(isTr ? '🌐 Ağ ve DNS saldırı senaryosu simüle ediliyor...' : '🌐 Simulating network & DNS attack scenario...', 'info');

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch('/api/v1/endpoint/network/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                type: scenarioType,
                hostname: hostname
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${res.status}`);
        }

        showToast(isTr ? '✓ Tehdit simülasyonu başarıyla oluşturuldu ve SIEM alarmı tetiklendi!' : '✓ Threat simulation generated and SIEM alert dispatched!', 'success');
        loadEndpointNetwork();
    } catch (e) {
        showToast(`Simülasyon hatası: ${e.message}`, 'error');
    }
}

async function openNetworkFirewallRulesModal() {
    const modal = document.getElementById('modal-network-firewall-rules');
    if (modal) {
        modal.classList.add('active');
        modal.style.display = 'flex';
    }
    loadNetworkFirewallRules();
}

function closeNetworkFirewallRulesModal() {
    const modal = document.getElementById('modal-network-firewall-rules');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
}

async function loadNetworkFirewallRules() {
    const tbody = document.getElementById('ep-net-fw-tbody');
    if (!tbody) return;
    const t = (k, fb) => (window.i18n ? window.i18n.t(k, fb) : (fb || k));

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/network/firewall/rules?tenant=${encodeURIComponent(tenant)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const rules = data.rules || [];

        if (rules.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="padding: 24px; color: var(--text-muted);">${t('net_no_fw_rules') || 'Henüz tanımlanmış güvenlik duvarı engelleme kuralı bulunmuyor.'}</td></tr>`;
            return;
        }

        tbody.innerHTML = rules.map(r => `
            <tr>
                <td style="font-weight: 600;">${escapeHtml(r.rule_name)}</td>
                <td><span class="badge badge-secondary" style="font-size: 11px;">${escapeHtml(r.direction)}</span></td>
                <td><span class="badge badge-danger" style="font-size: 11px;">${escapeHtml(r.action)}</span></td>
                <td style="font-family: monospace; font-weight: 600;">${escapeHtml(r.remote_ip)}</td>
                <td style="font-size: 12px; color: var(--text-muted);">${escapeHtml(r.reason || '-')}</td>
                <td style="font-size: 12px;">${escapeHtml(r.created_by || 'system')}</td>
                <td style="text-align: right;">
                    <button class="btn btn-danger btn-sm" style="padding: 2px 7px; font-size: 11px;" onclick="deleteNetworkFirewallRule('${r.id}')"><i class="fas fa-trash"></i></button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="color: var(--danger); padding: 20px;">Hata: ${escapeHtml(e.message)}</td></tr>`;
    }
}

async function deleteNetworkFirewallRule(ruleId) {
    const isTr = !window.i18n || window.i18n.currentLang === 'tr';
    if (!confirm(isTr ? 'Bu güvenlik duvarı kuralını silmek istediğinizden emin misiniz?' : 'Are you sure you want to delete this firewall rule?')) return;

    try {
        const res = await fetch(`/api/v1/endpoint/network/firewall/rules/${ruleId}`, { method: 'DELETE' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        showToast(isTr ? '✓ Güvenlik duvarı kuralı silindi' : '✓ Firewall rule deleted', 'success');
        loadNetworkFirewallRules();
        loadEndpointNetworkStats();
    } catch (e) {
        showToast(`Hata: ${e.message}`, 'error');
    }
}

window.loadEndpointNetwork = loadEndpointNetwork;
window.loadEndpointNetworkStats = loadEndpointNetworkStats;
window.loadEndpointNetworkConnections = loadEndpointNetworkConnections;
window.loadEndpointNetworkDNS = loadEndpointNetworkDNS;
window.switchNetworkSubtab = switchNetworkSubtab;
window.blockEndpointNetworkIP = blockEndpointNetworkIP;
window.openNetworkSimulateModal = openNetworkSimulateModal;
window.closeNetworkSimulateModal = closeNetworkSimulateModal;
window.executeNetworkSimulation = executeNetworkSimulation;
window.openNetworkFirewallRulesModal = openNetworkFirewallRulesModal;
window.closeNetworkFirewallRulesModal = closeNetworkFirewallRulesModal;
window.deleteNetworkFirewallRule = deleteNetworkFirewallRule;

// ============================================================================
// PHASE P: ENDPOINT ANTI-RANSOMWARE SHIELD & DECOY CANARY DEFENSE
// ============================================================================

async function loadEndpointRansomware() {
    loadRansomwareStats();
    loadRansomwareCanaries();
    loadRansomwareIncidents();
}

async function loadRansomwareStats() {
    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/ransomware/stats?tenant=${encodeURIComponent(tenant)}`);
        if (!res.ok) return;
        const data = await res.json();

        const elIncidents = document.getElementById('ep-ransomware-stat-incidents');
        const elArmed = document.getElementById('ep-ransomware-stat-canaries-armed');
        const elTampered = document.getElementById('ep-ransomware-stat-canaries-tampered');
        const elTerminated = document.getElementById('ep-ransomware-stat-terminated');

        if (elIncidents) elIncidents.textContent = (data.total_incidents || 0).toLocaleString();
        if (elArmed) elArmed.textContent = (data.canaries_armed || 0).toLocaleString();
        if (elTampered) elTampered.textContent = (data.canaries_tampered || 0).toLocaleString();
        if (elTerminated) elTerminated.textContent = (data.processes_terminated || 0).toLocaleString();
    } catch (e) {
        console.error('loadRansomwareStats error:', e);
    }
}

async function loadRansomwareCanaries() {
    const tbody = document.getElementById('ep-ransomware-canaries-tbody');
    const countEl = document.getElementById('ep-ransomware-canaries-count');
    if (!tbody) return;
    const t = (k, fb) => (window.i18n ? window.i18n.t(k, fb) : (fb || k));

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/ransomware/canaries?tenant=${encodeURIComponent(tenant)}&limit=100`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const canaries = data.canaries || [];
        if (countEl) countEl.textContent = `${data.total || canaries.length} ${t('ransomware_unit_canaries') || 'Yem'}`;

        if (canaries.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="color: var(--text-muted); padding: 24px;">${t('ransomware_no_canaries') || 'Henüz dağıtılmış tuzak yem dosya bulunmuyor. Ajan bağlandığında otomatik konuşlandırılır.'}</td></tr>`;
            return;
        }

        tbody.innerHTML = canaries.map(c => {
            const timeStr = formatDateTime(c.last_checked_at || c.created_at);
            const statusBadge = c.status === 'TRIGGERED' 
                ? `<span class="badge badge-danger" style="animation: pulse 1.5s infinite;"><i class="fas fa-exclamation-triangle"></i> TRIGGERED</span>`
                : `<span class="badge badge-success"><i class="fas fa-check-circle"></i> ARMED</span>`;
            
            const hashShort = c.expected_hash ? (c.expected_hash.substring(0, 14) + '...') : '-';

            return `<tr>
                <td><strong>${escapeHtml(c.hostname || '-')}</strong></td>
                <td><code style="font-size: 11px;">${escapeHtml(c.file_path || '-')}</code></td>
                <td><span class="badge badge-secondary">${escapeHtml(c.file_type ? c.file_type.toUpperCase() : '-')}</span></td>
                <td><code title="${escapeHtml(c.expected_hash || '')}">${escapeHtml(hashShort)}</code></td>
                <td>${statusBadge}</td>
                <td style="color: var(--text-muted); font-size: 11.5px;">${timeStr}</td>
            </tr>`;
        }).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="color: var(--danger); padding: 24px;">Hata: ${escapeHtml(e.message)}</td></tr>`;
    }
}

async function loadRansomwareIncidents() {
    const tbody = document.getElementById('ep-ransomware-incidents-tbody');
    const countEl = document.getElementById('ep-ransomware-incidents-count');
    if (!tbody) return;
    const t = (k, fb) => (window.i18n ? window.i18n.t(k, fb) : (fb || k));

    try {
        const tenant = currentTenantContext || localStorage.getItem('active_tenant_slug') || 'default';
        const res = await fetch(`/api/v1/endpoint/ransomware/incidents?tenant=${encodeURIComponent(tenant)}&limit=100`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const incidents = data.incidents || [];
        if (countEl) countEl.textContent = `${data.total || incidents.length} ${t('ransomware_unit_incidents') || 'Olay'}`;

        if (incidents.length === 0) {
            tbody.innerHTML = `<tr><td colspan="9" class="text-center" style="color: var(--text-muted); padding: 24px;">${t('ransomware_no_incidents') || 'Harika! Uç noktalarda henüz hiçbir fidye yazılımı veya tuzak müdahalesi kaydedilmedi.'}</td></tr>`;
            return;
        }

        tbody.innerHTML = incidents.map(inc => {
            const timeStr = formatDateTime(inc.detected_at || inc.created_at);
            const actionBadge = inc.action_taken === 'TERMINATED'
                ? `<span class="badge badge-danger"><i class="fas fa-skull"></i> TERMINATED</span>`
                : inc.action_taken === 'QUARANTINED'
                ? `<span class="badge badge-warning"><i class="fas fa-box"></i> QUARANTINED</span>`
                : `<span class="badge badge-secondary">${escapeHtml(inc.action_taken || 'ALERTED')}</span>`;

            const triggerBadge = inc.trigger_type === 'CANARY_MODIFIED'
                ? `<span class="badge badge-warning" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b;"><i class="fas fa-bomb"></i> CANARY_MODIFIED</span>`
                : `<span class="badge badge-danger" style="background: rgba(239, 68, 68, 0.15); color: #ef4444;"><i class="fas fa-bolt"></i> ${escapeHtml(inc.trigger_type || 'ENTROPY')}</span>`;

            const entropyDisplay = inc.entropy > 0 ? inc.entropy.toFixed(3) : '-';

            return `<tr>
                <td style="color: var(--text-muted); font-size: 11.5px; white-space: nowrap;">${timeStr}</td>
                <td><strong>${escapeHtml(inc.hostname || '-')}</strong></td>
                <td><code style="color: var(--accent);">${escapeHtml(inc.process_name || '-')}</code></td>
                <td><code>${inc.process_pid || '-'}</code></td>
                <td>${triggerBadge}</td>
                <td><code style="font-size: 11px;">${escapeHtml(inc.target_file || '-')}</code></td>
                <td><span class="badge badge-outline">${escapeHtml(entropyDisplay)}</span></td>
                <td>${actionBadge}</td>
                <td><span class="badge badge-danger">${escapeHtml(inc.severity || 'CRITICAL')}</span></td>
            </tr>`;
        }).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center" style="color: var(--danger); padding: 24px;">Hata: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function openRansomwareSimulateModal() {
    const m = document.getElementById('modal-ransomware-simulate');
    if (m) m.style.display = 'flex';
}

function closeRansomwareSimulateModal() {
    const m = document.getElementById('modal-ransomware-simulate');
    if (m) m.style.display = 'none';
}

async function executeRansomwareSimulation() {
    const isTr = !window.i18n || window.i18n.currentLang === 'tr';
    const attackType = document.getElementById('ransomware-sim-scenario') ? document.getElementById('ransomware-sim-scenario').value : 'CANARY_TAMPER';
    const hostname = document.getElementById('ransomware-sim-hostname') ? document.getElementById('ransomware-sim-hostname').value.trim() : '';

    try {
        const res = await fetch('/api/v1/endpoint/ransomware/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                attack_type: attackType,
                hostname: hostname
            })
        });

        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        closeRansomwareSimulateModal();
        showToast(isTr ? `✓ ${data.message || 'Simülasyon başarıyla tamamlandı!'}` : `✓ ${data.message || 'Simulation completed successfully!'}`, 'success');

        loadEndpointRansomware();
    } catch (e) {
        showToast(`Hata: ${e.message}`, 'error');
    }
}

function openHoneypotConfigModal() {
    const m = document.getElementById('modal-honeypot-config');
    if (m) m.style.display = 'flex';

    // Fetch existing settings
    fetch('/api/v1/endpoint/ransomware/config')
        .then(res => res.json())
        .then(cfg => {
            if (!cfg) return;
            if (document.getElementById('hp-cfg-enabled')) document.getElementById('hp-cfg-enabled').checked = cfg.enabled !== false;
            if (document.getElementById('hp-cfg-canaries-enabled')) document.getElementById('hp-cfg-canaries-enabled').checked = cfg.canaries_enabled !== false;
            if (document.getElementById('hp-cfg-autonomous-kill')) document.getElementById('hp-cfg-autonomous-kill').checked = cfg.autonomous_kill !== false;
            if (document.getElementById('hp-cfg-action-mode')) document.getElementById('hp-cfg-action-mode').value = cfg.action_mode || 'TERMINATE';
            if (document.getElementById('hp-cfg-entropy')) {
                const ent = cfg.entropy_threshold || 7.5;
                document.getElementById('hp-cfg-entropy').value = ent;
                if (document.getElementById('hp-cfg-entropy-val')) {
                    document.getElementById('hp-cfg-entropy-val').textContent = parseFloat(ent).toFixed(2);
                }
            }
            if (document.getElementById('hp-cfg-custom-path')) document.getElementById('hp-cfg-custom-path').value = cfg.custom_path || '';
            if (document.getElementById('hp-cfg-interval')) document.getElementById('hp-cfg-interval').value = String(cfg.rearm_interval_sec || 60);

            // Decoy types checkboxes
            const types = (cfg.decoy_types || 'docx,xlsx,pdf').split(',').map(s => s.trim().toLowerCase());
            document.querySelectorAll('.hp-decoy-cb').forEach(cb => {
                cb.checked = types.includes(cb.value.toLowerCase());
            });
        })
        .catch(err => {
            console.warn('[Honeypot] Could not fetch config:', err);
        });
}

function closeHoneypotConfigModal() {
    const m = document.getElementById('modal-honeypot-config');
    if (m) m.style.display = 'none';
}

async function saveHoneypotConfig() {
    const isTr = !window.i18n || window.i18n.currentLang === 'tr';
    const btn = document.getElementById('btn-save-hp-cfg');
    if (btn) btn.disabled = true;

    const decoyList = [];
    document.querySelectorAll('.hp-decoy-cb:checked').forEach(cb => {
        decoyList.push(cb.value);
    });

    const payload = {
        enabled: document.getElementById('hp-cfg-enabled') ? document.getElementById('hp-cfg-enabled').checked : true,
        canaries_enabled: document.getElementById('hp-cfg-canaries-enabled') ? document.getElementById('hp-cfg-canaries-enabled').checked : true,
        autonomous_kill: document.getElementById('hp-cfg-autonomous-kill') ? document.getElementById('hp-cfg-autonomous-kill').checked : true,
        action_mode: document.getElementById('hp-cfg-action-mode') ? document.getElementById('hp-cfg-action-mode').value : 'TERMINATE',
        entropy_threshold: document.getElementById('hp-cfg-entropy') ? parseFloat(document.getElementById('hp-cfg-entropy').value) : 7.5,
        decoy_types: decoyList.length > 0 ? decoyList.join(',') : 'docx,xlsx,pdf',
        custom_path: document.getElementById('hp-cfg-custom-path') ? document.getElementById('hp-cfg-custom-path').value.trim() : '',
        rearm_interval_sec: document.getElementById('hp-cfg-interval') ? parseInt(document.getElementById('hp-cfg-interval').value, 10) : 60
    };

    try {
        const res = await fetch('/api/v1/endpoint/ransomware/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        closeHoneypotConfigModal();
        showToast(isTr ? `✓ ${data.message || 'Honeypot yapılandırması başarıyla kaydedildi!'}` : `✓ ${data.message || 'Honeypot configuration saved successfully!'}`, 'success');
        loadEndpointRansomware();
    } catch (e) {
        showToast(`Hata: ${e.message}`, 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function armFleetCanaries() {
    const isTr = !window.i18n || window.i18n.currentLang === 'tr';
    const btn = document.getElementById('btn-arm-fleet');
    if (btn) btn.disabled = true;

    try {
        const res = await fetch('/api/v1/endpoint/ransomware/arm', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        showToast(isTr ? `✓ ${data.message || 'Tüm filoya tuzak yemler dağıtıldı ve silahlandırıldı!'}` : `✓ ${data.message || 'Canary decoys deployed and armed fleet-wide!'}`, 'success');
        loadEndpointRansomware();
    } catch (e) {
        showToast(`Hata: ${e.message}`, 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

window.loadEndpointRansomware = loadEndpointRansomware;
window.loadRansomwareStats = loadRansomwareStats;
window.loadRansomwareCanaries = loadRansomwareCanaries;
window.loadRansomwareIncidents = loadRansomwareIncidents;
window.openRansomwareSimulateModal = openRansomwareSimulateModal;
window.closeRansomwareSimulateModal = closeRansomwareSimulateModal;
window.executeRansomwareSimulation = executeRansomwareSimulation;
window.openHoneypotConfigModal = openHoneypotConfigModal;
window.closeHoneypotConfigModal = closeHoneypotConfigModal;
window.saveHoneypotConfig = saveHoneypotConfig;
window.armFleetCanaries = armFleetCanaries;
window.toggleSidebarSection = toggleSidebarSection;
window.initSidebarFoldableSections = initSidebarFoldableSections;
window.ensureActiveNavSectionExpanded = ensureActiveNavSectionExpanded;
window.setAppTheme = setAppTheme;
window.getAppTheme = getAppTheme;
window.initTheme = initTheme;















