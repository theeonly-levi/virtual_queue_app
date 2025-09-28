
// Frontend auth + queue UI logic (placeholder / mock). Integrate with backend endpoints when available.

// Patient UI logic for auth + queue interaction with backend
// Assumptions: Backend served at same origin or adjust API_BASE
// Endpoints used: /register, /login, /queue/join, /queue/me

(function(){
    const API_BASE = '';
    let authToken = null;
    let pollTimer = null;

    // Elements
    const loginTabBtn = document.getElementById('tab-login');
    const registerTabBtn = document.getElementById('tab-register');
    const loginPanel = document.getElementById('panel-login');
    const registerPanel = document.getElementById('panel-register');
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const joinForm = document.getElementById('joinForm');
    const queueSection = document.getElementById('queueSection');
    const authCard = document.getElementById('authCard');
    const ticketBox = document.getElementById('ticketBox');
    const ticketStatusEl = document.getElementById('ticketStatus');
    const ticketPositionEl = document.getElementById('ticketPosition');
    const etaValueEl = document.getElementById('etaValue');
    const joinView = document.getElementById('joinView');
    const userView = document.getElementById('userView');
    const joinBtn = document.getElementById('joinBtn');
    const leaveBtn = document.getElementById('leaveBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    const whoamiEl = document.getElementById('whoami');
    const loginError = document.getElementById('loginError');
    const regError = document.getElementById('regError');

    function switchTab(which){
        if(which==='login'){
            loginTabBtn.classList.add('active');
            registerTabBtn.classList.remove('active');
            loginPanel.classList.remove('hidden');
            registerPanel.classList.add('hidden');
        } else {
            registerTabBtn.classList.add('active');
            loginTabBtn.classList.remove('active');
            registerPanel.classList.remove('hidden');
            loginPanel.classList.add('hidden');
        }
    }

    loginTabBtn?.addEventListener('click',()=>switchTab('login'));
    registerTabBtn?.addEventListener('click',()=>switchTab('register'));

    async function api(path, options={}){
        const headers = options.headers || {};
        headers['Content-Type'] = 'application/json';
        if(authToken) headers['Authorization'] = 'Bearer ' + authToken;
        const res = await fetch(API_BASE + path, { ...options, headers });
        let data = null;
        const ct = res.headers.get('content-type')||'';
        if(ct.includes('application/json')){
            data = await res.json();
        } else {
            data = await res.text();
        }
        if(!res.ok){
            const msg = data && data.error ? data.error : (data && data.message ? data.message : res.status+" " + res.statusText);
            throw new Error(msg);
        }
        return data;
    }

    function setAuth(token, username){
        authToken = token;
        whoamiEl.textContent = username;
        authCard.classList.add('hidden');
        queueSection.classList.remove('hidden');
        pollStatus();
    }

    function logout(){
        authToken = null;
        whoamiEl.textContent = '';
        clearInterval(pollTimer); pollTimer=null;
        resetTicket();
        queueSection.classList.add('hidden');
        authCard.classList.remove('hidden');
        switchTab('login');
    }

    logoutBtn?.addEventListener('click', logout);

    function resetTicket(){
        ticketStatusEl.textContent = '—';
        ticketPositionEl.textContent = '—';
        etaValueEl.textContent = '—';
        joinView.classList.remove('hidden');
        userView.classList.add('hidden');
    }

    function updateTicket(entry){
        if(!entry){
            resetTicket();
            return;
        }
        joinView.classList.add('hidden');
        userView.classList.remove('hidden');
        ticketStatusEl.textContent = entry.status;
        ticketPositionEl.textContent = (entry.status === 'waiting' && entry.position!=null) ? entry.position : (entry.status==='serving' ? 'Now' : '—');
        etaValueEl.textContent = estimateETA(entry);
    }

    function estimateETA(entry){
        if(!entry || entry.status!=='waiting' || entry.position==null) return '—';
        // naive estimate: 5 minutes per patient ahead
        const mins = (entry.position - 1) * 5;
        if(mins <= 0) return 'Soon';
        if(mins < 60) return mins + ' min';
        const h = Math.floor(mins/60); const m = mins % 60;
        return h + 'h ' + (m? m+'m':'' );
    }

    async function pollStatus(){
        if(!authToken) return;
        try {
            const data = await api('/queue/me');
            updateTicket(data.entry || null);
        } catch(err){
            console.warn('poll error', err.message);
        }
        if(!pollTimer){
            pollTimer = setInterval(pollStatus, 5000);
        }
    }

    // Login
    loginForm?.addEventListener('submit', async (e)=>{
        e.preventDefault();
        loginError.textContent='';
        const username = document.getElementById('login_username').value.trim();
        const password = document.getElementById('login_password').value;
        if(!username || !password){ loginError.textContent='Missing credentials'; return; }
        try {
            const data = await api('/login', { method:'POST', body: JSON.stringify({ username, password }) });
            setAuth(data.token, data.username || username);
        } catch(err){
            loginError.textContent = err.message;
        }
    });

    // Register
    registerForm?.addEventListener('submit', async (e)=>{
        e.preventDefault();
        regError.textContent='';
        const username = document.getElementById('reg_username').value.trim();
        const password = document.getElementById('reg_password').value;
        if(!username || !password){ regError.textContent='Fill all fields'; return; }
        try {
            await api('/register', { method:'POST', body: JSON.stringify({ username, password }) });
            // auto-login after register
            const data = await api('/login', { method:'POST', body: JSON.stringify({ username, password }) });
            setAuth(data.token, data.username || username);
        } catch(err){
            regError.textContent = err.message;
        }
    });

    // Join queue
    joinForm?.addEventListener('submit', async (e)=>{
        e.preventDefault();
        if(!authToken) return;
        joinBtn.disabled = true;
        try {
            const visit_type = document.getElementById('visit_type').value || 'general';
            await api('/queue/join', { method:'POST', body: JSON.stringify({ visit_type }) });
            await pollStatus();
        } catch(err){
            alert('Join failed: ' + err.message);
        } finally {
            joinBtn.disabled = false;
        }
    });

    // Leave queue - placeholder (needs backend endpoint if desired)
    leaveBtn?.addEventListener('click', ()=>{
        alert('Leave queue not implemented on server yet.');
    });

    // Attempt token restore (POC: none stored) - could add localStorage logic
    switchTab('login');
})();

let mockPosition = null; // placeholder for queue position

function swap(showRegister) {
    if (showRegister) {
        loginForm.classList.add('hidden');
        registerForm.classList.remove('hidden');
        registerForm.querySelector('input').focus();
    } else {
        registerForm.classList.add('hidden');
        loginForm.classList.remove('hidden');
        loginForm.querySelector('input').focus();
    }
    loginError.textContent = '';
    registerError.textContent = '';
}

if (showRegisterBtn) showRegisterBtn.addEventListener('click', () => swap(true));
if (showLoginBtn) showLoginBtn.addEventListener('click', () => swap(false));

// Simulated API helpers (replace with real fetch calls)
async function apiRegister(payload) {
    // Example real call: return fetch('/api/register', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)}).then(r=>r.json())
    return new Promise(resolve => setTimeout(() => resolve({ success: true }), 400));
}

async function apiLogin(payload) {
    return new Promise(resolve => setTimeout(() => resolve({ success: true, token: 'demo-token', position: Math.floor(Math.random()*6)+1 }), 400));
}

async function apiQueueStatus() {
    if (mockPosition === null) mockPosition = Math.floor(Math.random()*6)+1;
    // drift position downward randomly
    if (mockPosition > 1 && Math.random() < 0.4) mockPosition -= 1;
    return { position: mockPosition };
}

registerForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    registerError.textContent = '';
    const name = document.getElementById('reg_name').value.trim();
    const email = document.getElementById('reg_email').value.trim();
    const pwd = document.getElementById('reg_password').value.trim();
    const pwd2 = document.getElementById('reg_password_confirm').value.trim();
    const visitType = document.getElementById('reg_visit_type').value.trim();

    if (pwd !== pwd2) {
        registerError.textContent = 'Passwords do not match.';
        return;
    }
    if (pwd.length < 6) {
        registerError.textContent = 'Password must be at least 6 characters.';
        return;
    }
    try {
        const resp = await apiRegister({ name, email, password: pwd, visit_type: visitType });
        if (!resp.success) {
            registerError.textContent = resp.message || 'Registration failed.';
            return;
        }
        swap(false);
        loginError.textContent = 'Account created. Please log in.';
    } catch (err) {
        registerError.textContent = 'Network error. Try again.';
    }
});

loginForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginError.textContent = '';
    const email = document.getElementById('login_email').value.trim();
    const password = document.getElementById('login_password').value.trim();
    try {
        const resp = await apiLogin({ email, password });
        if (!resp.success) {
            loginError.textContent = resp.message || 'Login failed.';
            return;
        }
        mockPosition = resp.position;
        authCard.classList.add('hidden');
        queueSection.classList.remove('hidden');
        queueStatus.textContent = 'You are in the queue. Position: ' + mockPosition;
    } catch (err) {
        loginError.textContent = 'Network error. Try again.';
    }
});

refreshQueueBtn?.addEventListener('click', async () => {
    const status = await apiQueueStatus();
    queueStatus.textContent = 'Current position: ' + status.position;
});

logoutBtn?.addEventListener('click', () => {
    queueSection.classList.add('hidden');
    authCard.classList.remove('hidden');
    swap(false);
    mockPosition = null;
    queueStatus.textContent = 'Not checked in yet.';

document.addEventListener("DOMContentLoaded", function () {
    const loginForm = document.getElementById("loginForm");

    loginForm.addEventListener("submit", function (event) {
        event.preventDefault(); // Prevent default form submission

        const username = document.getElementById("username").value.trim();
        const password = document.getElementById("password").value.trim();

        // Simulated user credentials (in real apps, validate via server/API)
        const validCredentials = {
            username: "admin",
            password: "admin123"
        };

        // Check credentials
        if (username === validCredentials.username && password === validCredentials.password) {
            // Simulate successful login
            alert("Login successful!");

            // Redirect or update UI
            showQueueDashboard(); // You can replace this with window.location = 'dashboard.html' if needed
        } else {
            // Show error
            alert("Invalid username or password.");
        }
    });

});

function showQueueDashboard() {
    const form = document.getElementById("loginForm");
    const queueList = document.getElementById("queueList");

    // Hide login form
    form.style.display = "none";

    // Simulate a list of users in the virtual queue
    const usersInQueue = [
        { name: "Mashbeats", position: 1 },
        { name: "Levi", position: 2 },
        { name: "Tumi", position: 3 },
        { name: "Tumelo929", position: 4}
    ];

    // Build the queue list HTML
    let html = `<h2>Queue Dashboard</h2>`;
    html += `<ul>`;
    usersInQueue.forEach(user => {
        html += `<li>${user.position}. ${user.name}</li>`;
    });
    html += `</ul>`;

    // Display it
    queueList.innerHTML = html;
}
})
