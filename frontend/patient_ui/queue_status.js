// Frontend auth + queue UI logic (placeholder / mock). Integrate with backend endpoints when available.

const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const showRegisterBtn = document.getElementById('showRegisterBtn');
const showLoginBtn = document.getElementById('showLoginBtn');
const loginError = document.getElementById('loginError');
const registerError = document.getElementById('registerError');
const authCard = document.getElementById('authCard');
const queueSection = document.getElementById('queueSection');
const queueStatus = document.getElementById('queueStatus');
const refreshQueueBtn = document.getElementById('refreshQueueBtn');
const logoutBtn = document.getElementById('logoutBtn');

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
});
