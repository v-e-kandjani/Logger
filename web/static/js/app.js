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
    initTelemetryCharts();
    initSearch();
    initDeviceModal();
    initUserModal();
    initResetPasswordModal();
    initArchiveTrigger();
    initCustomExportModal();
    initStorageManagement();
    initUpdatesManagement();
    loadUpdateStatus();
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
        }

        // Only Super Administrators can see or manage users & system upgrades
        const usersTab = document.getElementById('nav-tab-users');
        if (usersTab) {
            usersTab.style.display = data.role === 'Super Administrator' ? '' : 'none';
        }
        const updatesTab = document.getElementById('nav-tab-updates');
        if (updatesTab) {
            updatesTab.style.display = data.role === 'Super Administrator' ? '' : 'none';
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

            // Gate access to users and updates tab for non-admins
            if ((tab === 'users' || tab === 'updates') && window.currentUser && window.currentUser.role !== 'Super Administrator') {
                showToast('Erişim Reddedildi: Yalnızca Süper Yöneticiler bu bölüme erişebilir.', 'error');
                return;
            }

            navItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');

            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            const targetPane = document.getElementById(`pane-${tab}`);
            if (targetPane) targetPane.classList.add('active');

            updateViewHeader(tab);

            // Refresh tab-specific views
            if (tab === 'dashboard') fetchAndRenderTelemetryCharts();
            if (tab === 'search') document.getElementById('btn-search-exec').click();
            if (tab === 'devices') loadDevices();
            if (tab === 'unregistered') loadUnregisteredSources();
            if (tab === 'archives') loadArchives();
            if (tab === 'health') loadHealthTelemetry();
            if (tab === 'settings') loadSettings();
            if (tab === 'users') loadUsers();
            if (tab === 'updates') loadUpdateStatus();
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

            // Storage telemetry
            if (data.storage) {
                updateStorageUI(data.storage);
            }
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

    // Pre-populate with recent logs from ClickHouse so stream is not blank on page load
    const preloadRecentLogs = async () => {
        try {
            const res = await fetch('/api/v1/logs?limit=50&range=all');
            if (!res.ok) return;
            const data = await res.json();
            if (data.logs && data.logs.length > 0 && liveLogCount === 0) {
                const recent = [...data.logs].reverse();
                recent.forEach(log => {
                    const row = document.createElement('div');
                    row.className = 'log-row';
                    const timeStr = log.timestamp ? log.timestamp.substring(11, 23) : '';
                    const vendorBadge = log.vendor === 'WatchGuard' ? '<span class="badge badge-primary">WatchGuard</span> ' : log.vendor ? `[${log.vendor}] ` : '';
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

        window._unregisteredSources = sources;
        tbody.innerHTML = sources.map((s, idx) => `
            <tr>
                <td class="mono-code text-yellow">${escapeHtml(s.ip_address)}</td>
                <td>${Number(s.packet_count).toLocaleString()}</td>
                <td>${escapeHtml(s.detected_facility || '-')}</td>
                <td>${escapeHtml(s.detected_severity || '-')}</td>
                <td>${new Date(s.first_seen_at).toLocaleString()}</td>
                <td>${new Date(s.last_seen_at).toLocaleString()}</td>
                <td>
                    <button class="btn btn-outline btn-register-unreg" data-idx="${idx}">+ Register</button>
                </td>
            </tr>
        `).join('');

        tbody.querySelectorAll('.btn-register-unreg').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const idx = parseInt(btn.getAttribute('data-idx'), 10);
                const s = window._unregisteredSources[idx];
                if (s) {
                    onboardDevice(s.ip_address, s.last_raw_sample || '');
                }
            });
        });
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-red">Failed: ${e.message}</td></tr>`;
    }
}

window.onboardDevice = (ip, sample = '') => {
    const ipInput = document.getElementById('dev-ip');
    const nameInput = document.getElementById('dev-name');
    if (ipInput) ipInput.value = ip;
    if (nameInput) nameInput.value = `Device-${ip.replace(/\./g, '-')}`;

    const vendorSelect = document.getElementById('dev-vendor');
    const typeSelect = document.getElementById('dev-type');
    const groupSelect = document.getElementById('dev-group');

    if (sample && (sample.toLowerCase().includes('watchguard') || sample.toLowerCase().includes('firebox') || sample.includes('msg_id='))) {
        if (vendorSelect) vendorSelect.value = 'WatchGuard';
        if (typeSelect) typeSelect.value = 'Firewall';
        if (nameInput) nameInput.value = `WatchGuard-FW-${ip.replace(/\./g, '-')}`;
        if (groupSelect) groupSelect.value = 'Perimeter Firewalls';
    } else if (sample && (sample.toLowerCase().includes('cisco') || sample.includes('%SYS-') || sample.includes('%LINK-'))) {
        if (vendorSelect) vendorSelect.value = 'Cisco';
        if (typeSelect) typeSelect.value = 'Switch';
        if (nameInput) nameInput.value = `Cisco-SW-${ip.replace(/\./g, '-')}`;
        if (groupSelect) groupSelect.value = 'Core Switches & Routers';
    } else {
        if (groupSelect) groupSelect.value = 'Default';
    }

    const modal = document.getElementById('device-modal');
    if (modal) {
        modal.style.display = 'flex';
    }
};

// Archives & KamuSM Zaman Damgası
async function loadArchives() {
    const tbody = document.getElementById('archives-body');
    tbody.innerHTML = '<tr><td colspan="9" class="text-center">Loading archives...</td></tr>';
    try {
        const res = await fetch('/api/v1/archives');
        const list = await res.json();
        if (!list || list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="text-center">No archives generated yet. Click "Create Archive Now" above.</td></tr>';
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
                <td>
                    <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                        <a href="/api/v1/archives/download?id=${a.id}&type=bundle" class="btn btn-primary" style="padding: 3px 8px; font-size: 11px; text-decoration: none;" title="Download complete compliance package (.zip containing logs, .zd evidence, and .sha256 hash)" download>
                            📦 Bundle (.zip)
                        </a>
                        <a href="/api/v1/archives/download?id=${a.id}&type=archive" class="btn btn-outline" style="padding: 3px 8px; font-size: 11px; text-decoration: none;" title="Download raw compressed logs (.jsonl.gz)" download>
                            📄 Logs (.gz)
                        </a>
                        ${a.timestamp_status === 'STAMPED' && a.timestamp_evidence_path ? `
                        <a href="/api/v1/archives/download?id=${a.id}&type=evidence" class="btn btn-outline" style="padding: 3px 8px; font-size: 11px; text-decoration: none;" title="Download legal proof / KamuSM timestamp (.zd)" download>
                            🛡️ Evidence (.zd)
                        </a>` : ''}
                    </div>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-red">Failed: ${e.message}</td></tr>`;
    }
}

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
            name: document.getElementById('dev-name').value.trim(),
            ip_address: document.getElementById('dev-ip').value.trim(),
            vendor: document.getElementById('dev-vendor').value,
            device_type: document.getElementById('dev-type').value,
            group_name: document.getElementById('dev-group') ? document.getElementById('dev-group').value : 'Default',
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
            loadUnregisteredSources();
        } catch (e) {
            alert('Failed saving asset: ' + e.message);
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
    tbody.innerHTML = '<tr><td colspan="8" class="text-center">Loading operators and security profiles...</td></tr>';

    try {
        const res = await fetch('/api/v1/users');
        if (res.status === 401) {
            window.location.href = '/login';
            return;
        }
        if (res.status === 403) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-red">Erişim Reddedildi: Yalnızca Süper Yöneticiler operatör hesaplarını görüntüleyebilir ve yönetebilir.</td></tr>';
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

        tbody.innerHTML = users.map(u => {
            const isSelf = window.currentUser && (u.username === window.currentUser.username || u.id === window.currentUser.user_id);
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
                    <span class="badge ${u.is_enabled ? 'badge-success' : 'badge-danger'}">
                        ${u.is_enabled ? 'Active' : 'Disabled'}
                    </span>
                </td>
                <td>${u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'Never'}</td>
                <td>${u.created_at ? new Date(u.created_at).toLocaleDateString() : '-'}</td>
                <td>
                    <div style="display: flex; gap: 6px; flex-wrap: wrap; align-items: center;">
                        <button class="btn btn-outline" style="padding: 3px 8px; font-size: 11px;" onclick="openResetPasswordModal('${u.id}', '${escapeHtml(u.username)}')">
                            Reset Password
                        </button>
                        ${isSelf ? `
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
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-red">Failed loading users: ${e.message}</td></tr>`;
    }
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
                btnSave.disabled = false;
                btnSave.textContent = 'Update Password';
            }
        });
    }
}

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
    const statusAlert = document.getElementById('export-status-alert');
    const statusText = document.getElementById('export-status-text');

    const openModal = () => {
        const now = new Date();
        const start = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        const formatForInput = (d) => {
            const pad = (n) => String(n).padStart(2, '0');
            return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
        };

        const startInput = document.getElementById('export-start-time');
        const endInput = document.getElementById('export-end-time');
        if (startInput) startInput.value = formatForInput(start);
        if (endInput) endInput.value = formatForInput(now);

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

            btnExecute.disabled = true;
            if (statusAlert && statusText) {
                statusText.textContent = window.i18n ? window.i18n.t('export_loading') : 'Loglar hazırlanıyor ve mühürleniyor...';
                statusAlert.style.display = 'block';
            }

            try {
                const res = await fetch('/api/v1/archives/export-custom', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        start: startVal,
                        end: endVal,
                        time_field: timeField,
                        format: format,
                        seal: seal,
                        register: register
                    })
                });

                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Dışa aktarma oluşturulamadı');

                // Trigger direct file download
                if (data.download_url) {
                    const downloadAnchor = document.createElement('a');
                    downloadAnchor.href = data.download_url;
                    downloadAnchor.setAttribute('download', '');
                    document.body.appendChild(downloadAnchor);
                    downloadAnchor.click();
                    document.body.removeChild(downloadAnchor);
                }

                alert(`Dışa aktarma ve mühürleme tamamlandı!\nKayıt: ${data.result.record_count} adet\nDurum: ${data.result.timestamp_status}`);
                closeModal();
                loadArchives();
            } catch (err) {
                alert('Hata: ' + err.message);
            } finally {
                btnExecute.disabled = false;
                if (statusAlert) statusAlert.style.display = 'none';
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

        const curVersion = data.current_version || 'v1.2.2';
        if (verEl) verEl.textContent = curVersion;
        const brandVer = document.getElementById('brand-version');
        if (brandVer) brandVer.textContent = curVersion;

        if (commitEl) commitEl.textContent = data.current_commit || '684fa6f';
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

    if (btnApply) {
        btnApply.addEventListener('click', async () => {
            if (!confirm('Apply available updates from GitHub to this server? Web assets and templates will be updated immediately.')) {
                return;
            }

            btnApply.disabled = true;
            btnApply.textContent = 'Downloading from GitHub...';

            try {
                const res = await fetch('/api/v1/system/update/apply', { method: 'POST' });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Failed applying updates');

                showToast(`✓ ${data.message}`, 'success');

                // Update local commit display
                if (data.new_commit) {
                    const commitEl = document.getElementById('upd-current-commit');
                    if (commitEl) commitEl.textContent = data.new_commit;
                }

                if (badge) {
                    badge.className = 'badge badge-success';
                    badge.textContent = 'Updated to ' + (data.new_commit || 'latest');
                }

                if (data.binary_changed) {
                    showToast('Web assets hot-patched! Backend Go changes require container restart.', 'info');
                }

                // Refresh status
                setTimeout(loadUpdateStatus, 1500);
            } catch (err) {
                showToast('Failed applying upgrade: ' + err.message, 'error');
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

function initTelemetryCharts() {
    const canvasCPU = document.getElementById('chart-canvas-cpu');
    const canvasRAM = document.getElementById('chart-canvas-ram');
    const canvasLogs = document.getElementById('chart-canvas-logs');
    const canvasNet = document.getElementById('chart-canvas-net');

    if (!canvasCPU || !canvasRAM || !canvasLogs || !canvasNet) return;

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
            if (elCores) elCores.textContent = `${cur.cpu_cores || 1} Cores (${cur.os || 'Linux'})`;

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
        }

        renderAllTelemetryCharts(data);
    } catch (e) {
        console.error('Error fetching telemetry metrics:', e);
    }
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

