// Syslog Platform Operations & Security Dashboard Controller
let liveSocket = null;
let isLivePaused = false;
let liveLogCount = 0;
const MAX_LIVE_ROWS = 500;
let lastPacketCount = 0;
let lastSampleTime = Date.now();

document.addEventListener('DOMContentLoaded', () => {
    initAuthSession();
    initNavigation();
    initLiveStream();
    startPollingTelemetry();
    initSearch();
    initDeviceModal();
    initUserModal();
    initArchiveTrigger();
});

// Authentication & Session Guard
async function initAuthSession() {
    try {
        const res = await fetch('/api/v1/auth/me');
        if (!res.ok) {
            window.location.href = '/login';
            return;
        }
        const data = await res.json();
        if (data.username) {
            const nameEl = document.getElementById('current-user-name');
            const roleEl = document.getElementById('current-user-role');
            if (nameEl) nameEl.textContent = data.username;
            if (roleEl) roleEl.textContent = data.role || 'Administrator';
        }
    } catch (e) {
        window.location.href = '/login';
    }

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

// Navigation Tab Switcher
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const tab = item.getAttribute('data-tab');
            navItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');

            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            const targetPane = document.getElementById(`pane-${tab}`);
            if (targetPane) targetPane.classList.add('active');

            // Refresh tab-specific views
            if (tab === 'devices') loadDevices();
            if (tab === 'unregistered') loadUnregisteredSources();
            if (tab === 'archives') loadArchives();
            if (tab === 'health') loadHealthTelemetry();
            if (tab === 'settings') loadSettings();
            if (tab === 'users') loadUsers();
        });
    });
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

            // Calculate current EPS rate
            const now = Date.now();
            const timeDiffSec = (now - lastSampleTime) / 1000;
            if (timeDiffSec > 0 && lastPacketCount > 0) {
                const rxDiff = (data.packets_rx || 0) - lastPacketCount;
                const eps = Math.max(0, Math.round(rxDiff / timeDiffSec));
                document.getElementById('current-eps').textContent = `${eps.toLocaleString()} EPS`;
            }
            lastPacketCount = data.packets_rx || 0;
            lastSampleTime = now;

            // Header DB health
            document.getElementById('sb-ch-status').textContent = data.clickhouse_healthy ? 'Online' : 'Degraded';
        } catch (e) {
            console.error('Telemetry error:', e);
        }
    };
    poll();
    setInterval(poll, 2000);
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

    const connect = () => {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        liveSocket = new WebSocket(`${protocol}//${window.location.host}/api/v1/logs/live`);

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
                const vendorBadge = log.vendor === 'WatchGuard' ? '<span class="badge badge-primary">WatchGuard</span> ' : log.vendor ? `[${log.vendor}] ` : '';
                row.innerHTML = `
                    <span class="log-time">${timeStr}</span>
                    <span class="log-src">${log.source_ip}:${log.source_port}</span>
                    <span class="log-dev">${vendorBadge}${escapeHtml(log.device_name || 'UNKNOWN')}</span>
                    <span class="log-sev sev-${log.severity}">${log.severity}</span>
                    <span class="log-msg">${escapeHtml(log.message)}</span>
                `;

                container.appendChild(row);
                liveLogCount++;

                // Enforce Bounded Buffer (prevent memory leakage in browser)
                if (liveLogCount > MAX_LIVE_ROWS) {
                    container.removeChild(container.firstChild);
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
                            <span class="badge ${l.vendor === 'WatchGuard' ? 'badge-primary' : 'badge-secondary'}">${escapeHtml(l.vendor || 'Generic')}</span>
                            <strong>${escapeHtml(l.device_name || 'UNKNOWN')}</strong>
                        </td>
                        <td><span class="badge sev-${l.severity}">${l.severity}</span></td>
                        <td>${l.facility}</td>
                        <td>${escapeHtml(l.application || '-')}</td>
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
    tbody.innerHTML = '<tr><td colspan="7" class="text-center">Loading registered devices...</td></tr>';
    try {
        const res = await fetch('/api/v1/devices');
        const devices = await res.json();
        if (!devices || devices.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">No registered devices yet. Add one or convert from unknown sources.</td></tr>';
            return;
        }

        tbody.innerHTML = devices.map(d => `
            <tr>
                <td><strong>${escapeHtml(d.name)}</strong></td>
                <td class="mono-code">${d.ip_address}</td>
                <td>${d.vendor}</td>
                <td>${d.device_type}</td>
                <td>
                    <span class="badge ${d.syslog_status === 'HEALTHY' ? 'badge-success' : d.syslog_status === 'WARNING' ? 'badge-warning' : 'badge-secondary'}">
                        ${d.syslog_status}
                    </span>
                </td>
                <td>${d.last_seen_at ? new Date(d.last_seen_at).toLocaleString() : 'Never'}</td>
                <td><span class="badge badge-primary">${d.timestamp_policy}</span></td>
                <td>
                    <button class="btn btn-outline text-red" style="padding: 4px 8px;" onclick="deleteDevice('${d.id}')">Delete</button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-red">Failed to load devices: ${e.message}</td></tr>`;
    }
}

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

// Unknown Sources
async function loadUnregisteredSources() {
    const tbody = document.getElementById('unreg-body');
    tbody.innerHTML = '<tr><td colspan="7" class="text-center">Loading detected sources...</td></tr>';
    try {
        const res = await fetch('/api/v1/unregistered');
        const sources = await res.json();
        if (!sources || sources.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">No unregistered syslog traffic detected.</td></tr>';
            return;
        }

        tbody.innerHTML = sources.map(s => {
            const rawSample = (s.last_raw_sample || '').replace(/'/g, "\\'");
            return `
            <tr>
                <td class="mono-code text-yellow">${s.ip_address}</td>
                <td>${Number(s.packet_count).toLocaleString()}</td>
                <td>${s.detected_facility}</td>
                <td>${s.detected_severity}</td>
                <td>${new Date(s.first_seen_at).toLocaleString()}</td>
                <td>${new Date(s.last_seen_at).toLocaleString()}</td>
                <td>
                    <button class="btn btn-outline" onclick="onboardDevice('${s.ip_address}', '${rawSample}')">+ Register</button>
                </td>
            </tr>
            `;
        }).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-red">Failed: ${e.message}</td></tr>`;
    }
}

window.onboardDevice = (ip, sample = '') => {
    document.getElementById('dev-ip').value = ip;
    document.getElementById('dev-name').value = `Device-${ip.replace(/\./g, '-')}`;
    if (sample && (sample.toLowerCase().includes('watchguard') || sample.toLowerCase().includes('firebox') || sample.includes('msg_id='))) {
        document.getElementById('dev-vendor').value = 'WatchGuard';
        document.getElementById('dev-type').value = 'Firewall';
        document.getElementById('dev-name').value = `WatchGuard-FW-${ip.replace(/\./g, '-')}`;
    }
    document.getElementById('device-modal').style.display = 'flex';
};

// Archives & KamuSM Zaman Damgası
async function loadArchives() {
    const tbody = document.getElementById('archives-body');
    tbody.innerHTML = '<tr><td colspan="8" class="text-center">Loading archives...</td></tr>';
    try {
        const res = await fetch('/api/v1/archives');
        const list = await res.json();
        if (!list || list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center">No archives generated yet. Click "Create Archive Now" above.</td></tr>';
            return;
        }

        tbody.innerHTML = list.map(a => `
            <tr>
                <td><strong>${escapeHtml(a.archive_name)}</strong></td>
                <td>${new Date(a.start_timestamp).toISOString().substring(0, 16)}</td>
                <td>${new Date(a.end_timestamp).toISOString().substring(0, 16)}</td>
                <td>${Number(a.record_count).toLocaleString()}</td>
                <td>${(a.archive_size / 1024).toFixed(1)} KB</td>
                <td class="mono-code" title="${a.hash_value}">${a.hash_value.substring(0, 16)}...</td>
                <td>
                    <span class="badge ${a.timestamp_status === 'STAMPED' ? 'badge-success' : a.timestamp_status === 'FAILED' ? 'badge-danger' : 'badge-warning'}">
                        ${a.timestamp_status}
                    </span>
                </td>
                <td class="mono-code">${a.timestamp_evidence_path ? a.timestamp_evidence_path.split('/').pop() : 'Pending'}</td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-red">Failed: ${e.message}</td></tr>`;
    }
}

function initArchiveTrigger() {
    const btn = document.getElementById('btn-manual-archive');
    btn.addEventListener('click', async () => {
        btn.disabled = true;
        btn.textContent = 'Generating & Stamping...';
        try {
            const res = await fetch('/api/v1/archives/create', { method: 'POST' });
            if (!res.ok) {
                const err = await res.text();
                alert('Archive error: ' + err);
            } else {
                alert('Archive created and submitted to KamuSM Zaman Damgası engine!');
                loadArchives();
            }
        } catch (e) {
            alert('Request failed: ' + e.message);
        } finally {
            btn.disabled = false;
            btn.textContent = 'Create Archive Now';
        }
    });
}

function initDeviceModal() {
    const modal = document.getElementById('device-modal');
    document.getElementById('btn-add-device-modal').addEventListener('click', () => {
        modal.style.display = 'flex';
    });
    document.getElementById('btn-close-modal').addEventListener('click', () => {
        modal.style.display = 'none';
    });
    document.getElementById('btn-cancel-modal').addEventListener('click', () => {
        modal.style.display = 'none';
    });

    document.getElementById('btn-save-device').addEventListener('click', async () => {
        const payload = {
            name: document.getElementById('dev-name').value,
            ip_address: document.getElementById('dev-ip').value,
            vendor: document.getElementById('dev-vendor').value,
            device_type: document.getElementById('dev-type').value,
        };
        try {
            const res = await fetch('/api/v1/devices', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            if (!res.ok) throw new Error(await res.text());
            modal.style.display = 'none';
            loadDevices();
        } catch (e) {
            alert('Failed saving asset: ' + e.message);
        }
    });
}

async function loadHealthTelemetry() {
    const body = document.getElementById('health-telemetry-body');
    body.innerHTML = 'Loading health telemetry...';
    try {
        const res = await fetch('/api/v1/system/health');
        const h = await res.json();
        body.innerHTML = `
            <div class="status-row"><span>Node Name</span><strong>${h.node}</strong></div>
            <div class="status-row"><span>ClickHouse Storage</span><span class="badge badge-success">${h.clickhouse}</span></div>
            <div class="status-row"><span>PostgreSQL Metadata</span><span class="badge badge-success">${h.postgres}</span></div>
            <div class="status-row"><span>Ingestion Channel Queue Depth</span><span>${h.queue_depth}</span></div>
            <div class="status-row"><span>Packets Received</span><span>${Number(h.packets_rx).toLocaleString()}</span></div>
            <div class="status-row"><span>Events Parsed</span><span>${Number(h.events_parsed).toLocaleString()}</span></div>
            <div class="status-row"><span>Events Inserted (ClickHouse)</span><span class="text-green">${Number(h.events_inserted).toLocaleString()}</span></div>
            <div class="status-row"><span>Insert Errors</span><span>${h.insert_errors}</span></div>
        `;
    } catch (e) {
        body.innerHTML = `<span class="text-red">Health probe error: ${e.message}</span>`;
    }
}

// TÜBİTAK KamuSM Settings
async function loadSettings() {
    try {
        const res = await fetch('/api/v1/settings');
        if (!res.ok) return;
        const s = await res.json();

        if (s.kamusm_provider) document.getElementById('setting-provider').value = s.kamusm_provider;
        if (s.kamusm_server_url) document.getElementById('setting-server-url').value = s.kamusm_server_url;
        if (s.kamusm_server_port) document.getElementById('setting-server-port').value = s.kamusm_server_port;
        if (s.kamusm_customer_no) document.getElementById('setting-customer-no').value = s.kamusm_customer_no;
        if (s.kamusm_customer_password && s.kamusm_customer_password !== '********') {
            document.getElementById('setting-customer-pass').value = s.kamusm_customer_password;
        }
        if (s.kamusm_digest_type) document.getElementById('setting-digest').value = s.kamusm_digest_type;
        if (s.archive_interval) document.getElementById('setting-archive-interval').value = s.archive_interval;
        if (s.retention_days) document.getElementById('setting-retention-days').value = s.retention_days;
    } catch (e) {
        console.error('Failed loading settings:', e);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const btnSave = document.getElementById('btn-save-settings');
    if (btnSave) {
        btnSave.addEventListener('click', async () => {
            btnSave.disabled = true;
            btnSave.textContent = 'Saving Settings...';

            const payload = {
                kamusm_provider: document.getElementById('setting-provider').value,
                kamusm_server_url: document.getElementById('setting-server-url').value,
                kamusm_server_port: document.getElementById('setting-server-port').value,
                kamusm_customer_no: document.getElementById('setting-customer-no').value.trim(),
                kamusm_digest_type: document.getElementById('setting-digest').value,
                archive_interval: document.getElementById('setting-archive-interval').value,
                retention_days: document.getElementById('setting-retention-days').value,
            };

            const passVal = document.getElementById('setting-customer-pass').value.trim();
            if (passVal && passVal !== '********') {
                payload.kamusm_customer_password = passVal;
            }

            try {
                const res = await fetch('/api/v1/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                if (!res.ok) throw new Error(await res.text());
                alert('TÜBİTAK KamuSM & System Settings saved successfully!');
            } catch (e) {
                alert('Failed saving settings: ' + e.message);
            } finally {
                btnSave.disabled = false;
                btnSave.textContent = 'Save KamuSM Settings';
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
    tbody.innerHTML = '<tr><td colspan="8" class="text-center">Loading operators and security profiles...</td></tr>';

    try {
        const res = await fetch('/api/v1/users');
        if (res.status === 401) {
            window.location.href = '/login';
            return;
        }
        const users = await res.json();
        if (!users || users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center">No operator accounts found.</td></tr>';
            return;
        }

        const roleBadges = {
            'Super Administrator': 'badge-primary',
            'Security Analyst': 'badge-info',
            'Auditor': 'badge-success',
            'Operator': 'badge-warning',
            'Read Only': 'badge-secondary'
        };

        tbody.innerHTML = users.map(u => `
            <tr>
                <td><strong>${escapeHtml(u.username)}</strong></td>
                <td>${escapeHtml(u.full_name || '-')}</td>
                <td class="mono-code">${escapeHtml(u.email || '-')}</td>
                <td>
                    <span class="badge ${roleBadges[u.role] || 'badge-secondary'}">
                        ${escapeHtml(u.role)}
                    </span>
                </td>
                <td>
                    <span class="badge ${u.is_enabled ? 'badge-success' : 'badge-danger'}">
                        ${u.is_enabled ? 'Active' : 'Disabled'}
                    </span>
                </td>
                <td>${u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'Never'}</td>
                <td>${u.created_at ? new Date(u.created_at).toLocaleDateString() : '-'}</td>
                <td>
                    <div style="display: flex; gap: 6px;">
                        <button class="btn btn-outline" style="padding: 3px 8px; font-size: 11px;" onclick="toggleUserStatus('${u.id}')">
                            ${u.is_enabled ? 'Deactivate' : 'Activate'}
                        </button>
                        <button class="btn btn-outline text-red" style="padding: 3px 8px; font-size: 11px;" onclick="deleteUser('${u.id}', '${escapeHtml(u.username)}')">
                            Delete
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-red">Failed loading users: ${e.message}</td></tr>`;
    }
}

window.toggleUserStatus = async (id) => {
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

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

