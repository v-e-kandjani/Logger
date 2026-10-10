// Syslog Platform Operations & Security Dashboard Controller
let liveSocket = null;
let isLivePaused = false;
let liveLogCount = 0;
const MAX_LIVE_ROWS = 15;
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
    initSIEMManagement();
    initADAndMFAManagement();
    initHTTPSAndFQDNManagement();
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
            if (tab === 'siem') loadSIEMData();
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
    setInterval(poll, 5000);
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
    tbody.innerHTML = '<tr><td colspan="8" class="text-center">Loading registered devices...</td></tr>';
    try {
        const res = await fetch('/api/v1/devices');
        const devices = await res.json();
        if (!devices || devices.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center">No registered devices yet. Add one or convert from unknown sources.</td></tr>';
            return;
        }

        tbody.innerHTML = devices.map(d => `
            <tr>
                <td><strong>${escapeHtml(d.name)}</strong></td>
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
                    <button class="btn btn-outline" style="padding: 4px 8px; margin-right: 4px;" onclick="autoDetectDevice('${d.id}', '${d.ip_address}')" title="Auto-Detect Vendor & Type from Log Stream">🔍 Detect</button>
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
    tbody.innerHTML = '<tr><td colspan="8" class="text-center">Loading detected sources...</td></tr>';
    try {
        const res = await fetch('/api/v1/unregistered');
        const sources = await res.json();
        if (!sources || sources.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center">No unregistered syslog traffic detected.</td></tr>';
            return;
        }

        window._unregisteredSources = sources;
        tbody.innerHTML = sources.map((s, idx) => `
            <tr>
                <td class="mono-code text-yellow">${escapeHtml(s.ip_address)}</td>
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
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-red">Failed: ${e.message}</td></tr>`;
    }
}

window.onboardDevice = (ip, sample = '', sourceObj = null) => {
    const ipInput = document.getElementById('dev-ip');
    const nameInput = document.getElementById('dev-name');
    const vendorSelect = document.getElementById('dev-vendor');
    const typeSelect = document.getElementById('dev-type');
    const groupSelect = document.getElementById('dev-group');
    const modalBadge = document.getElementById('modal-auto-discovery-badge');
    const badgeText = document.getElementById('auto-discovery-badge-text');
    const confBadge = document.getElementById('auto-discovery-confidence-badge');

    if (ipInput) ipInput.value = ip;

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
        else if (detectedType === 'Server') groupSelect.value = 'Identity & Auth Servers';
        else groupSelect.value = 'Default';
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
    const addBtn = document.getElementById('btn-add-device-modal');
    if (addBtn) {
        addBtn.addEventListener('click', () => {
            const badge = document.getElementById('modal-auto-discovery-badge');
            if (badge) badge.style.display = 'none';
            const nameInp = document.getElementById('dev-name');
            const ipInp = document.getElementById('dev-ip');
            if (nameInp) nameInp.value = '';
            if (ipInp) ipInp.value = '';
            modal.style.display = 'flex';
        });
    }
    const closeBtn = document.getElementById('btn-close-modal');
    if (closeBtn) closeBtn.addEventListener('click', () => { modal.style.display = 'none'; });
    const cancelBtn = document.getElementById('btn-cancel-modal');
    if (cancelBtn) cancelBtn.addEventListener('click', () => { modal.style.display = 'none'; });

    const btnOnboardAll = document.getElementById('btn-onboard-all-unreg');
    if (btnOnboardAll) {
        btnOnboardAll.addEventListener('click', async () => {
            if (!confirm('Automatically onboard and register all auto-discovered network assets?')) return;
            btnOnboardAll.disabled = true;
            btnOnboardAll.innerHTML = '<span>⏳</span> Onboarding Assets...';
            try {
                const res = await fetch('/api/v1/unregistered/onboard-all', { method: 'POST' });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Failed onboarding assets');
                showToast(`✓ Successfully auto-onboarded ${data.onboarded_count || 0} discovered device(s)!`, 'success');
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
            showToast('✓ Device asset registered successfully', 'success');
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

        const redEl = document.getElementById('setting-https-redirect');
        if (redEl) redEl.checked = !!s.redirect_http;

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

        const cert = s.certificate;
        const cnEl = document.getElementById('cert-cn-display');
        const issuerEl = document.getElementById('cert-issuer-display');
        const expiryEl = document.getElementById('cert-expiry-display');
        const daysBadge = document.getElementById('cert-days-badge');
        const keyEl = document.getElementById('cert-key-display');
        const sansEl = document.getElementById('cert-sans-display');
        const fpEl = document.getElementById('cert-fp-display');
        const btnDl = document.getElementById('btn-download-cert');

        if (cert) {
            if (cnEl) cnEl.textContent = cert.subject_cn || 'Configured TLS Certificate';
            if (issuerEl) issuerEl.textContent = cert.issuer || '-';
            if (expiryEl) expiryEl.textContent = cert.not_after ? cert.not_after.split('T')[0] : '-';
            if (daysBadge) {
                const days = cert.days_remaining != null ? cert.days_remaining : 0;
                daysBadge.textContent = `${days} days left`;
                daysBadge.className = days > 30 ? 'badge badge-success' : 'badge badge-warning';
            }
            if (keyEl) keyEl.textContent = cert.key_type || 'RSA 2048-bit';
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

        const totEl = document.getElementById('cache-total-ram');
        if (totEl) totEl.textContent = s.total_ram_mb > 0 ? `${(s.total_ram_mb / 1024).toFixed(2)} GB` : '-';

        const availEl = document.getElementById('cache-avail-ram');
        if (availEl) availEl.textContent = s.avail_ram_mb > 0 ? `${(s.avail_ram_mb / 1024).toFixed(2)} GB` : '-';

        const budgetEl = document.getElementById('cache-budget-ram');
        if (budgetEl) budgetEl.textContent = s.max_memory_mb > 0 ? `${(s.max_memory_mb / 1024).toFixed(2)} GB (60%)` : '-';

        const usageEl = document.getElementById('cache-usage-ram');
        if (usageEl) usageEl.textContent = `${(s.used_memory_mb || 0).toFixed(2)} MB`;

        const itemsEl = document.getElementById('cache-items-count');
        if (itemsEl) itemsEl.textContent = (s.cached_items || 0).toLocaleString();

        const hitRatioEl = document.getElementById('cache-hit-ratio');
        if (hitRatioEl) hitRatioEl.textContent = `${(s.hit_ratio_pct || 0).toFixed(1)}%`;

        const hitsEl = document.getElementById('cache-hits-count');
        if (hitsEl) hitsEl.textContent = (s.hits || 0).toLocaleString();

        const missesEl = document.getElementById('cache-misses-count');
        if (missesEl) missesEl.textContent = (s.misses || 0).toLocaleString();

        const badge = document.getElementById('cache-status-badge');
        if (badge) {
            if (s.enabled) {
                badge.className = 'badge badge-success';
                badge.textContent = 'Active (Up to 60% RAM)';
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
                    body: JSON.stringify({ enabled, port, redirect_http: redirectHttp })
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
            } catch (e) {
                alert('Failed generating certificate: ' + e.message);
            } finally {
                btnGenCert.disabled = false;
                btnGenCert.textContent = '⚡ Generate & Activate Certificate';
            }
        });
    }

    // 3. Custom Certificate Upload
    const btnUploadCert = document.getElementById('btn-upload-cert');
    if (btnUploadCert) {
        btnUploadCert.addEventListener('click', async () => {
            const certPem = document.getElementById('cert-upload-cert').value.trim();
            const keyPem = document.getElementById('cert-upload-key').value.trim();

            if (!certPem || !keyPem) {
                alert('Please paste both Certificate PEM and Private Key PEM.');
                return;
            }

            btnUploadCert.disabled = true;
            btnUploadCert.textContent = 'Installing & Hot-Swapping Certificate...';

            try {
                const res = await fetch('/api/v1/settings/https/certificate/upload', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ cert_pem: certPem, key_pem: keyPem })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Failed uploading certificate');

                alert('✓ Enterprise TLS certificate uploaded, validated, and hot-swapped successfully!');
                document.getElementById('cert-upload-cert').value = '';
                document.getElementById('cert-upload-key').value = '';
                await loadHTTPSSettings();
            } catch (e) {
                alert('Failed uploading certificate: ' + e.message);
            } finally {
                btnUploadCert.disabled = false;
                btnUploadCert.textContent = '📤 Install & Hot-Swap Certificate';
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
                        register: register
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

        // Auto reload countdown
        let remaining = 4;
        const countdownEl = document.getElementById('upd-reload-countdown');
        if (countdownEl) countdownEl.textContent = `${remaining}s`;

        if (upgradeReloadTimer) clearInterval(upgradeReloadTimer);
        upgradeReloadTimer = setInterval(() => {
            remaining--;
            if (countdownEl) countdownEl.textContent = `${remaining}s`;
            if (remaining <= 0) {
                clearInterval(upgradeReloadTimer);
                window.location.reload(true);
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
// SIEM & Security Operations Center (SOC) Controller
// ==========================================================================
let siemFilterStatus = 'ALL';
let siemFilterSeverity = 'ALL';
let siemSearchQuery = '';
let currentInvestigatingAlertID = null;
let siemLiveSocket = null;

function initSIEMManagement() {
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

    const btnOpenRules = document.getElementById('btn-open-siem-rules');
    if (btnOpenRules) {
        btnOpenRules.addEventListener('click', openSIEMRulesModal);
    }

    const btnOpenSimulate = document.getElementById('btn-open-siem-simulate');
    if (btnOpenSimulate) {
        btnOpenSimulate.addEventListener('click', () => {
            const modal = document.getElementById('siem-simulate-modal');
            if (modal) modal.style.display = 'flex';
        });
    }

    // 7. Modal close triggers
    const btnCloseInv = document.getElementById('btn-close-siem-inv');
    if (btnCloseInv) {
        btnCloseInv.addEventListener('click', () => {
            document.getElementById('siem-investigate-modal').style.display = 'none';
        });
    }

    const btnCloseRules = document.getElementById('btn-close-siem-rules');
    if (btnCloseRules) {
        btnCloseRules.addEventListener('click', () => {
            document.getElementById('siem-rules-modal').style.display = 'none';
        });
    }

    const btnCloseSim = document.getElementById('btn-close-siem-simulate');
    if (btnCloseSim) {
        btnCloseSim.addEventListener('click', () => {
            document.getElementById('siem-simulate-modal').style.display = 'none';
        });
    }

    const btnCloseMitre = document.getElementById('btn-close-siem-mitre');
    if (btnCloseMitre) {
        btnCloseMitre.addEventListener('click', () => {
            document.getElementById('siem-mitre-modal').style.display = 'none';
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

            return `
                <tr>
                    <td>${sevBadge}</td>
                    <td style="font-size: 12px; color: var(--text-muted);">${timeStr}</td>
                    <td>
                        <div style="font-weight: 600; color: var(--text-main);">${escapeHtml(alert.rule_name)}</div>
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
        badge.textContent = `${filtered.length} / ${allSIEMRules.length} Rules`;
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

        if (!res.ok) throw new Error('Simulation failed');

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
    const wsUrl = `${proto}//${window.location.host}/api/v1/siem/live`;

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
    // Show toast for critical or high alerts
    if (alert.severity === 'CRITICAL' || alert.severity === 'HIGH') {
        showToast(`🚨 [${alert.severity}] ${alert.rule_name} (${alert.source_ip || 'Ağ'})`, 'warning');
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

