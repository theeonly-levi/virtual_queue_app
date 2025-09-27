document.getElementById('registrationForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const name = document.getElementById('name').value;
    const visit_type = document.getElementById('visit_type').value;
    const response = await fetch('http://127.0.0.1:5000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, visit_type })
    });
    const data = await response.json();
    document.getElementById('queueStatus').innerText = 'Your Queue Number: ' + data.queue_number;
});
