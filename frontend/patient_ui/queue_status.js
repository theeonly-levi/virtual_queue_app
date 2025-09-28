
// Frontend auth + queue UI logic (placeholder / mock). Integrate with backend endpoints when available.

// Patient UI logic for auth + queue interaction with backend
// Assumptions: Backend served at same origin or adjust API_BASE
// Endpoints used: /register, /login, /queue/join, /queue/me

// Patient UI logic: auth, queue status, medication advice
// Back-end endpoints assumed: /register, /login, /queue/join, /queue/me, /ai/advice
// Set window.API_BASE for cross-origin deployment if needed.
(function(){
    const API_BASE = window.API_BASE || '';
    let authToken = null;
    let pollTimer = null;
    const TOKEN_KEY = 'patient_jwt_token';
    const ADVICE_HISTORY_LIMIT = 30;
    const adviceHistory = [];

    // Elements (selectors align with index.html markup)
    const loginTabBtn = document.getElementById('tab-login');
    const registerTabBtn = document.getElementById('tab-register');
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const joinForm = document.getElementById('joinForm');
    const queueSection = document.getElementById('queueSection');
    const authCard = document.getElementById('authCard');
    const ticketStatusEl = document.getElementById('ticketStatus');
    const ticketPositionEl = document.getElementById('ticketPosition');
    const etaValueEl = document.getElementById('etaValue');
    const logoutBtn = document.getElementById('logoutBtn');
    const loginError = document.getElementById('loginError');
    const registerError = document.getElementById('registerError') || document.getElementById('registerError');
    const refreshBtn = document.getElementById('refreshBtn');
    const joinVisitTypeInput = document.getElementById('join_visit_type');
    const leaveBtn = document.getElementById('leaveBtn');
    // AI advice elements
    const advicePanel = document.getElementById('advicePanel');
    const toggleAdviceBtn = document.getElementById('toggleAdviceBtn');
    const adviceForm = document.getElementById('adviceForm');
    const adviceInput = document.getElementById('adviceInput');
    const adviceResult = document.getElementById('adviceResult');

    // Basic tab switch (forms already in DOM)
    function switchTab(which){
        const loginPanel = document.getElementById('loginForm');
        const registerPanel = document.getElementById('registerForm');
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
    loginTabBtn?.addEventListener('click', ()=>switchTab('login'));
    registerTabBtn?.addEventListener('click', ()=>switchTab('register'));

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

    function setAuth(token){
        authToken = token;
        try { localStorage.setItem(TOKEN_KEY, token); } catch(_){}
        authCard.classList.add('hidden');
        queueSection.classList.remove('hidden');
        pollStatus();
    }

    function logout(){
        authToken = null;
        try { localStorage.removeItem(TOKEN_KEY); } catch(_){}
        clearInterval(pollTimer); pollTimer=null;
        resetTicket();
        queueSection.classList.add('hidden');
        authCard.classList.remove('hidden');
        advicePanel?.classList.add('hidden');
        switchTab('login');
    }

    logoutBtn?.addEventListener('click', logout);

    function resetTicket(){
        ticketStatusEl.textContent = '—';
        ticketPositionEl.textContent = '—';
        etaValueEl.textContent = '—';
    }

    function updateTicket(entry){
        if(!entry){ resetTicket(); return; }
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
            setAuth(data.token);
        } catch(err){
            loginError.textContent = err.message;
        }
    });

    // Register
    registerForm?.addEventListener('submit', async (e)=>{
        e.preventDefault();
        const regError = document.getElementById('registerError') || document.getElementById('registerError');
        if(regError) regError.textContent='';
        const username = document.getElementById('reg_username').value.trim();
        const password = document.getElementById('reg_password').value;
        const password2 = document.getElementById('reg_password2').value;
        const name = document.getElementById('reg_name').value.trim() || username;
        const visit_type = document.getElementById('reg_visit_type').value.trim() || 'General';
        const auto_join = document.getElementById('reg_auto_join').checked;
        if(!username || !password){ if(regError) regError.textContent='Fill all fields'; return; }
        if(password !== password2){ if(regError) regError.textContent='Passwords do not match'; return; }
        try {
            await api('/register', { method:'POST', body: JSON.stringify({ username, password, name, visit_type, auto_join }) });
            // auto-login after register
            const data = await api('/login', { method:'POST', body: JSON.stringify({ username, password }) });
            setAuth(data.token);
        } catch(err){
            if(regError) regError.textContent = err.message;
        }
    });

    // Join queue
    joinForm?.addEventListener('submit', async (e)=>{
        e.preventDefault();
        if(!authToken) return;
        try {
            const visit_type = joinVisitTypeInput.value || 'General';
            await api('/queue/join', { method:'POST', body: JSON.stringify({ visit_type }) });
            await pollStatus();
        } catch(err){
            alert('Join failed: ' + err.message);
        }
    });

    leaveBtn?.addEventListener('click', async ()=> {
        if(!authToken) return;
        leaveBtn.disabled = true;
        try {
            const resp = await api('/queue/leave', { method:'POST' });
            await pollStatus();
        } catch(err){
            alert('Leave failed: ' + err.message);
        } finally {
            leaveBtn.disabled = false;
        }
    });

    // Manual refresh
    refreshBtn?.addEventListener('click', ()=> pollStatus());

    // AI Advice toggle
    toggleAdviceBtn?.addEventListener('click', ()=>{
        advicePanel.classList.toggle('hidden');
        if(!advicePanel.classList.contains('hidden')) adviceInput.focus();
    });

    // AI Advice submission
    adviceForm?.addEventListener('submit', async (e)=>{
        e.preventDefault();
        if(!authToken) return;
        const q = adviceInput.value.trim();
        if(!q) return;
        adviceResult.textContent = 'Loading...';
        try {
            const data = await api('/ai/advice', { method:'POST', body: JSON.stringify({ question: q }) });
            adviceHistory.push({ q, a: data.answer });
            if(adviceHistory.length > ADVICE_HISTORY_LIMIT) adviceHistory.shift();
            adviceResult.textContent = adviceHistory.map(turn => `Q: ${turn.q}\nA: ${turn.a}\n`).join('\n');
        } catch(err){
            adviceResult.textContent = 'Error: ' + err.message;
        }
    });

    // Attempt token restore (POC: none stored) - could add localStorage logic
    // Attempt token restore
    try {
        const saved = localStorage.getItem(TOKEN_KEY);
        if(saved){
            authToken = saved;
            // Probe queue; if fails, drop token
            api('/queue/me').then(()=>{
                authCard.classList.add('hidden');
                queueSection.classList.remove('hidden');
                pollStatus();
            }).catch(()=>{ localStorage.removeItem(TOKEN_KEY); authToken=null;});
        }
    } catch(_){}
    switchTab('login');
})();
