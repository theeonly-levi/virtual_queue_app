
document.addEventListener("DOMContentLoaded", () => {
    const API_BASE = window.API_BASE || ""; // Optionally set via script tag before this file

    // Elements
    const loginForm = document.getElementById("loginForm");
    const loginSection = document.getElementById("login-section");
    const dashboardContent = document.getElementById("dashboard-content");
    const loginError = document.getElementById("login-error");
    const queueCount = document.getElementById("queue-count");
    const servingIndicator = document.getElementById("serving-indicator");
    const queueTBody = document.getElementById("queue-tbody");
    const advanceBtn = document.getElementById("advance-btn");
    const refreshStatus = document.getElementById("refresh-status");
    const adminUsernameEl = document.getElementById("admin-username");
    const logoutBtn = document.getElementById("logout-btn");

    let refreshTimer = null;

    function setToken(token, username, role) {
        localStorage.setItem('auth_token', token);
        localStorage.setItem('auth_username', username || '');
        localStorage.setItem('auth_role', role || '');
    }
    function getToken() { return localStorage.getItem('auth_token'); }
    function getUsername() { return localStorage.getItem('auth_username'); }
    function clearToken() {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('auth_username');
        localStorage.removeItem('auth_role');
    }

    function showError(msg) {
        loginError.textContent = msg;
        loginError.style.display = 'block';
    }

    async function api(path, options = {}) {
        const headers = options.headers || {};
        headers['Content-Type'] = 'application/json';
        const token = getToken();
        if (token) headers['Authorization'] = 'Bearer ' + token;
        const resp = await fetch(API_BASE + path, { ...options, headers });
        let data = null;
        try { data = await resp.json(); } catch (e) {}
        if (!resp.ok) {
            const errMsg = (data && (data.error || data.message)) || resp.status + ' Error';
            throw new Error(errMsg);
        }
        return data;
    }

    async function login(username, password) {
        const data = await api('/login', { method: 'POST', body: JSON.stringify({ username, password }) });
        setToken(data.token, data.username, data.role);
        return data;
    }

    async function fetchQueue() {
        return api('/queue/list');
    }

    async function advanceQueue() {
        return api('/queue/next', { method: 'POST' });
    }

    async function markDone(entryId) {
        return api(`/queue/done/${entryId}`, { method: 'POST' });
    }

    function renderQueue(entries) {
        // Count and metrics
        const waiting = entries.filter(e => e.status === 'waiting');
        const serving = entries.find(e => e.status === 'serving');
        queueCount.innerHTML = `<div class="queue-tile animate-tile">
            <span class="tile-label">Waiting</span>
            <span class="tile-number">${waiting.length}</span>
        </div>`;
        if (serving) {
            servingIndicator.style.display = 'block';
            servingIndicator.innerHTML = `<strong>Serving:</strong> ${serving.name} <em>(${serving.visit_type})</em>`;
        } else {
            servingIndicator.style.display = 'none';
        }

        queueTBody.innerHTML = '';
        let positionCounter = 0;
        entries.forEach(entry => {
            const tr = document.createElement('tr');
            let posDisplay = '';
            if (entry.status === 'waiting') {
                positionCounter += 1;
                posDisplay = positionCounter;
            } else if (entry.status === 'serving') {
                posDisplay = '→';
                tr.classList.add('row-serving');
            }
            tr.innerHTML = `
                <td>${posDisplay}</td>
                <td>${entry.name}</td>
                <td>${entry.visit_type}</td>
                <td class="status-${entry.status}">${entry.status}</td>
                <td>
                    ${entry.status === 'serving' ? `<button data-action="done" data-id="${entry.id}">Done</button>` : ''}
                </td>
            `;
            queueTBody.appendChild(tr);
        });
    }

    async function refreshQueue(loop = true) {
        try {
            refreshStatus.textContent = 'Refreshing...';
            const entries = await fetchQueue();
            renderQueue(entries);
            refreshStatus.textContent = `Updated at ${new Date().toLocaleTimeString()}`;
        } catch (e) {
            refreshStatus.textContent = 'Error: ' + e.message;
        } finally {
            if (loop) {
                clearTimeout(refreshTimer);
                refreshTimer = setTimeout(() => refreshQueue(true), 5000);
            }
        }
    }

    // Event: login form
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginError.style.display = 'none';
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();
        try {
            const data = await login(username, password);
            if (data.role !== 'admin') {
                showError('You are not an admin.');
                clearToken();
                return;
            }
            adminUsernameEl.textContent = data.username;
            loginSection.style.display = 'none';
            dashboardContent.style.display = 'block';
            refreshQueue(true);
        } catch (err) {
            showError(err.message || 'Login failed');
        }
    });

    // Event: advance queue
    advanceBtn.addEventListener('click', async () => {
        advanceBtn.disabled = true;
        try {
            await advanceQueue();
            refreshQueue(false); // immediate refresh
        } catch (e) {
            alert('Advance failed: ' + e.message);
        } finally {
            advanceBtn.disabled = false;
        }
    });

    // Event delegation for mark done
    queueTBody.addEventListener('click', async (e) => {
        const btn = e.target.closest('button[data-action="done"]');
        if (!btn) return;
        const id = btn.getAttribute('data-id');
        btn.disabled = true;
        try {
            await markDone(id);
            refreshQueue(false);
        } catch (err) {
            alert('Mark done failed: ' + err.message);
        } finally {
            btn.disabled = false;
        }
    });

    logoutBtn.addEventListener('click', () => {
        clearToken();
        clearTimeout(refreshTimer);
        dashboardContent.style.display = 'none';
        loginSection.style.display = 'block';
        adminUsernameEl.textContent = '';
    });

    // Auto-login if token present and user is admin (we can't verify role client-side safely, but attempt fetch)
    (async function bootstrap() {
        if (getToken()) {
            try {
                // Probe queue endpoint; if unauthorized it will throw and we clear token.
                await fetchQueue();
                adminUsernameEl.textContent = getUsername();
                loginSection.style.display = 'none';
                dashboardContent.style.display = 'block';
                refreshQueue(true);
            } catch (e) {
                clearToken();
            }
        }
    })();
});
