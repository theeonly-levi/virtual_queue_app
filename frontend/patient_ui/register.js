document.addEventListener("DOMContentLoaded", function () {
    const registerForm = document.getElementById("registerForm");
    const errorDiv = document.getElementById("register-error");
    const successDiv = document.getElementById("register-success");

    registerForm.addEventListener("submit", function (event) {
        event.preventDefault();
        const username = document.getElementById("newUsername").value.trim();
        const password = document.getElementById("newPassword").value;
        const confirmPassword = document.getElementById("confirmPassword").value;

        errorDiv.style.display = "none";
        successDiv.style.display = "none";

        if (!username || !password || !confirmPassword) {
            errorDiv.textContent = "All fields are required.";
            errorDiv.style.display = "block";
            return;
        }
        if (password.length < 6) {
            errorDiv.textContent = "Password must be at least 6 characters.";
            errorDiv.style.display = "block";
            return;
        }
        if (password !== confirmPassword) {
            errorDiv.textContent = "Passwords do not match.";
            errorDiv.style.display = "block";
            return;
        }
        // Simulate registration success (replace with backend call)
        successDiv.textContent = "Account created successfully! You can now log in.";
        successDiv.style.display = "block";
        registerForm.reset();
    });
});
