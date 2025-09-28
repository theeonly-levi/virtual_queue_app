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
