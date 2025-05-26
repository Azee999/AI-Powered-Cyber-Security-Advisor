function updatePopupStats() {
    fetch('/get-stats')
        .then(res => res.json())
        .then(data => {
            document.getElementById('popup-scans').textContent = data.total_scans || 0;
            document.getElementById('popup-threats').textContent = 
                Object.values(data.threats_blocked || {}).reduce((a, b) => a + b, 0);
        });
}

function quickScan() {
    const input = document.getElementById('quick-scan-input').value.trim();
    if (!input) return;
    
    let endpoint, payloadKey;
    if (input.includes('@')) {
        endpoint = '/analyze-email';
        payloadKey = 'content';
    } else if (input.length > 20 && !input.includes(' ')) {
        endpoint = '/check-password';
        payloadKey = 'password';
    } else {
        endpoint = '/scan-url';
        payloadKey = 'url';
    }
    
    fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [payloadKey]: input })
    })
    .then(res => res.json())
    .then(data => {
        const alertList = document.getElementById('alert-list');
        const alertItem = document.createElement('div');
        alertItem.className = 'list-group-item alert-item';
        
        const isThreat = data.is_malicious || data.is_threat || data.is_breached;
        alertItem.classList.add(isThreat ? 'list-group-item-danger' : 'list-group-item-success');
        
        alertItem.innerHTML = `
            <div class="d-flex align-items-center">
                <i class="fas ${isThreat ? 'fa-exclamation-triangle' : 'fa-check-circle'} me-2"></i>
                <span>${input.substring(0, 20)}${input.length > 20 ? '...' : ''}</span>
            </div>
        `;
        
        alertList.prepend(alertItem);
        if (alertList.children.length > 5) {
            alertList.removeChild(alertList.lastChild);
        }
        updatePopupStats();
    });
}

// Initialize
updatePopupStats();