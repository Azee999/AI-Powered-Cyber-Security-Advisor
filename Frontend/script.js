// Tool navigation
function showTool(toolName) {
    document.querySelectorAll('.tool-section').forEach(section => {
        section.style.display = 'none';
    });
    document.getElementById(`${toolName}-tool`).style.display = 'block';
}

// Notification system
function showNotification(message, type='danger') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show`;
    notification.role = 'alert';
    notification.innerHTML = `
        <i class="fas ${type === 'danger' ? 'fa-exclamation-triangle' : 'fa-check-circle'} me-2"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    const container = document.getElementById('notification-area') || createNotificationContainer();
    container.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 150);
    }, 5000);
}

function createNotificationContainer() {
    const container = document.createElement('div');
    container.id = 'notification-area';
    container.className = 'position-fixed top-0 end-0 p-3';
    container.style.zIndex = '9999';
    document.body.appendChild(container);
    return container;
}

// Stats management
function updateStats() {
    fetch('/get-stats')
        .then(res => res.json())
        .then(data => {
            document.getElementById('total-scans').textContent = data.total_scans || 0;
            document.getElementById('threats-blocked').textContent = 
                Object.values(data.threats_blocked || {}).reduce((a, b) => a + b, 0);
            document.getElementById('last-scan').textContent = 
                data.last_scan ? new Date(data.last_scan * 1000).toLocaleString() : 'Never';
        });
}

// URL Scanning
async function scanUrl() {
    const url = document.getElementById('url-input').value.trim();
    const btn = document.getElementById('url-btn');
    const resultDiv = document.getElementById('url-result');
    
    if (!url) {
        showNotification('Please enter a URL', 'warning');
        return;
    }
    
    // Set loading state
    btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span> Scanning...';
    btn.disabled = true;
    
    try {
        const response = await fetch('/scan-url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        
        if (!response.ok) throw new Error('Network response was not ok');
        
        const data = await response.json();
        
        if (data.is_malicious) {
            resultDiv.innerHTML = `
                <div class="alert alert-danger">
                    <h5><i class="fas fa-exclamation-triangle me-2"></i>Malicious URL Detected</h5>
                    <p>${url} appears to be malicious.</p>
                    <p class="mb-0">Details: ${data.details || 'No additional details'}</p>
                </div>
            `;
            showNotification(`Blocked malicious URL: ${url}`, 'danger');
        } else {
            resultDiv.innerHTML = `
                <div class="alert alert-success">
                    <h5><i class="fas fa-check-circle me-2"></i>URL Appears Safe</h5>
                    <p>${url} doesn't appear to be malicious.</p>
                </div>
            `;
        }
        updateStats();
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="alert alert-danger">
                Error scanning URL: ${error.message}
            </div>
        `;
        console.error('URL scan error:', error);
    } finally {
        // Reset button
        btn.innerHTML = '<i class="fas fa-search me-1"></i> Scan URL';
        btn.disabled = false;
    }
}

// Email Analysis
async function analyzeEmail() {
    const content = document.getElementById('email-content').value.trim();
    const btn = document.getElementById('email-btn');
    const resultDiv = document.getElementById('email-result');
    
    if (!content) {
        showNotification('Please enter email content', 'warning');
        return;
    }
    
    // Set loading state
    btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span> Analyzing...';
    btn.disabled = true;
    
    try {
        const response = await fetch('/analyze-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });
        
        if (!response.ok) throw new Error('Network response was not ok');
        
        const data = await response.json();
        
        if (data.error) {
            resultDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
            return;
        }
        
        let riskLevel = 'success';
        if (data.risk_score > 70) riskLevel = 'danger';
        else if (data.risk_score > 30) riskLevel = 'warning';
        
        resultDiv.innerHTML = `
            <div class="alert alert-${riskLevel}">
                <h5><i class="fas fa-envelope me-2"></i>Analysis Result</h5>
                <p><strong>Risk Score:</strong> ${data.risk_score}/100</p>
                <p><strong>Phishing Likely:</strong> ${data.is_phishing ? 'Yes' : 'No'}</p>
                <p><strong>Reasons:</strong></p>
                <ul>
                    ${data.reasons.map(reason => `<li>${reason}</li>`).join('')}
                </ul>
            </div>
        `;
        updateStats();
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="alert alert-danger">
                Error analyzing email: ${error.message}
            </div>
        `;
        console.error('Email analysis error:', error);
    } finally {
        // Reset button
        btn.innerHTML = '<i class="fas fa-search me-1"></i> Analyze Email';
        btn.disabled = false;
    }
}

// Password Check
async function checkPassword() {
    const password = document.getElementById('password-input').value;
    const btn = document.getElementById('password-btn');
    const resultDiv = document.getElementById('password-result');
    
    if (!password) {
        showNotification('Please enter a password', 'warning');
        return;
    }
    
    // Set loading state
    btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span> Checking...';
    btn.disabled = true;
    
    try {
        const response = await fetch('/check-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        
        if (!response.ok) throw new Error('Network response was not ok');
        
        const data = await response.json();
        
        if (data.error) {
            resultDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
            return;
        }
        
        if (data.is_breached) {
            resultDiv.innerHTML = `
                <div class="alert alert-danger">
                    <h5><i class="fas fa-exclamation-triangle me-2"></i>Password Compromised!</h5>
                    <p>This password has appeared in ${data.breach_count || 'multiple'} data breaches.</p>
                    <p><strong>Recommendation:</strong> Change this password immediately.</p>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `
                <div class="alert alert-success">
                    <h5><i class="fas fa-check-circle me-2"></i>Password Secure</h5>
                    <p>This password hasn't been found in any known breaches.</p>
                </div>
            `;
        }
        updateStats();
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="alert alert-danger">
                Error checking password: ${error.message}
            </div>
        `;
        console.error('Password check error:', error);
    } finally {
        // Reset button
        btn.innerHTML = '<i class="fas fa-search me-1"></i> Check Password';
        btn.disabled = false;
    }
}

// Report Generation
function generateReport() {
    window.open('/generate-report', '_blank');
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    updateStats();
    setInterval(updateStats, 30000);
    createNotificationContainer();
    showTool('url'); // Default to URL scanner
});