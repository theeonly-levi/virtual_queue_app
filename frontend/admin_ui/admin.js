async function fetchQueue() {
    const response = await fetch('http://127.0.0.1:5000/queue');
    const queue = await response.json();
    const listDiv = document.getElementById('queueList');
    listDiv.innerHTML = '';
    queue.forEach(p => {
        const item = document.createElement('div');
        item.innerText = `ID: ${p.id}, Visit: ${p.visit_type}, Status: ${p.status}`;
        listDiv.appendChild(item);
    });
}
setInterval(fetchQueue, 2000);