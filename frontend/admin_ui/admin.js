
document.addEventListener("DOMContentLoaded", function () {
    const loginForm = document.getElementById("loginForm");
    const loginSection = document.getElementById("login-section");
    const dashboardContent = document.getElementById("dashboard-content");
    const loginError = document.getElementById("login-error");
    const queueCount = document.getElementById("queue-count");
    const queueList = document.getElementById("queue-list");

    loginForm.addEventListener("submit", function (event) {
        event.preventDefault();
        const username = document.getElementById("username").value.trim();
        const password = document.getElementById("password").value.trim();

        // Simulated credentials (replace with server-side validation in production)
        const validCredentials = {
            username: "admin",
            password: "admin123"
        };

        if (username === validCredentials.username && password === validCredentials.password) {
            loginSection.style.display = "none";
            dashboardContent.style.display = "block";
            loginError.style.display = "none";
            showQueueDashboard();
        } else {
            loginError.textContent = "Invalid username or password.";
            loginError.style.display = "block";
        }
    });

    function showQueueDashboard() {
        // Simulated queue data (replace with API call in production)
        const queue = [
            { name: "Mashbeats", visit_reason: "Consultation" },
            { name: "Levi", visit_reason: "Prescription renewal" },
            { name: "Tumi", visit_reason: "Follow-up" },
            { name: "Tumelo929", visit_reason: "Lab results" }
        ];

        // Animated tile for total number in queue
        queueCount.innerHTML = `<div class="queue-tile animate-tile">
            <span class="tile-label">Total in Queue</span>
            <span class="tile-number">${queue.length}</span>
        </div>`;

        // Banners for each individual
        queueList.innerHTML = "";
        queue.forEach((person, idx) => {
            const banner = document.createElement("div");
            banner.className = "queue-banner animate-banner";
            banner.innerHTML = `
                <div class="banner-index">#${idx + 1}</div>
                <div class="banner-info">
                    <span class="banner-name">${person.name}</span>
                    <span class="banner-reason">${person.visit_reason}</span>
                </div>
            `;
            queueList.appendChild(banner);
        });
    }
});
