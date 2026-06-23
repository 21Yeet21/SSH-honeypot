// script.js - Dashboard data fetching and chart rendering
// Updated to match the actual dashboard.py endpoints

// Global chart instances
let attacksChart = null;
let usernamesChart = null;
let passwordsChart = null;

// Update stats cards
async function updateStats() {
    try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        
        document.getElementById('total-attacks').textContent = data.total_attacks || 0;
        document.getElementById('unique-ips').textContent = data.unique_ips || 0;
        document.getElementById('top-username').textContent = data.top_username || 'N/A';
        document.getElementById('top-password').textContent = data.top_password || 'N/A';
    } catch (err) {
        console.error('Stats error:', err);
    }
}

// Update attacks per hour bar chart
async function updateAttacksChart() {
    try {
        const res = await fetch('/api/attacks-per-hour');
        const data = await res.json();
        
        // Handle both array format [{label, value}] and object format {label: value}
        let labels, values;
        if (Array.isArray(data)) {
            labels = data.map(item => item.label);
            values = data.map(item => item.value);
        } else {
            labels = Object.keys(data);
            values = Object.values(data);
        }
        
        const ctx = document.getElementById('attacks-per-hour-chart').getContext('2d');
        
        if (attacksChart) attacksChart.destroy();
        
        attacksChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Attacks',
                    data: values,
                    backgroundColor: 'rgba(0, 240, 255, 0.6)',
                    borderColor: 'rgba(0, 240, 255, 1)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { 
                        beginAtZero: true, 
                        grid: { color: 'rgba(255,255,255,0.1)' },
                        ticks: { color: '#fff' }
                    },
                    x: { 
                        grid: { display: false },
                        ticks: { color: '#fff' }
                    }
                }
            }
        });
    } catch (err) {
        console.error('Attacks chart error:', err);
    }
}

// Update top usernames doughnut chart
async function updateUsernamesChart() {
    try {
        const res = await fetch('/api/top-usernames');
        const data = await res.json();
        
        // Handle both array format [{label, value}] and object format {label: value}
        let labels, values;
        if (Array.isArray(data)) {
            labels = data.map(item => item.label);
            values = data.map(item => item.value);
        } else {
            labels = Object.keys(data);
            values = Object.values(data);
        }
        
        const ctx = document.getElementById('top-usernames-chart').getContext('2d');
        
        if (usernamesChart) usernamesChart.destroy();
        
        usernamesChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: [
                        'rgba(0, 240, 255, 0.8)',
                        'rgba(112, 0, 255, 0.8)',
                        'rgba(0, 255, 136, 0.8)',
                        'rgba(255, 0, 128, 0.8)',
                        'rgba(255, 200, 0, 0.8)',
                        'rgba(128, 0, 255, 0.8)',
                        'rgba(0, 200, 255, 0.8)',
                        'rgba(255, 100, 0, 0.8)',
                        'rgba(0, 255, 200, 0.8)',
                        'rgba(200, 0, 255, 0.8)'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { 
                    legend: { 
                        position: 'bottom', 
                        labels: { color: '#fff', padding: 15 }
                    }
                }
            }
        });
    } catch (err) {
        console.error('Usernames chart error:', err);
    }
}

// Update top passwords pie chart
async function updatePasswordsChart() {
    try {
        const res = await fetch('/api/top-passwords');
        const data = await res.json();
        
        // Handle both array format [{label, value}] and object format {label: value}
        let labels, values;
        if (Array.isArray(data)) {
            labels = data.map(item => item.label);
            values = data.map(item => item.value);
        } else {
            labels = Object.keys(data);
            values = Object.values(data);
        }
        
        const ctx = document.getElementById('top-accounts-chart').getContext('2d');
        
        if (passwordsChart) passwordsChart.destroy();
        
        passwordsChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: [
                        'rgba(255, 0, 128, 0.8)',
                        'rgba(255, 200, 0, 0.8)',
                        'rgba(0, 240, 255, 0.8)',
                        'rgba(112, 0, 255, 0.8)',
                        'rgba(0, 255, 136, 0.8)',
                        'rgba(255, 100, 100, 0.8)',
                        'rgba(100, 255, 100, 0.8)',
                        'rgba(100, 100, 255, 0.8)',
                        'rgba(255, 150, 0, 0.8)',
                        'rgba(0, 150, 255, 0.8)'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { 
                    legend: { 
                        position: 'bottom', 
                        labels: { color: '#fff', padding: 15 }
                    }
                }
            }
        });
    } catch (err) {
        console.error('Passwords chart error:', err);
    }
}

// Update recent attacks table - FIXED: Use /api/live-feed instead of /api/recent-attacks
async function updateTable() {
    try {
        const res = await fetch('/api/live-feed'); // CORRECTED ENDPOINT
        const data = await res.json();
        
        const tbody = document.getElementById('attacks-tbody');
        tbody.innerHTML = '';
        
        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:20px;">No attacks recorded yet</td></tr>';
            return;
        }
        
        data.forEach(attack => {
            const row = tbody.insertRow();
            row.innerHTML = `
                <td style="padding:12px">${attack.timestamp || 'N/A'}</td>
                <td style="padding:12px">${attack.source_ip || 'unknown'}</td>
                <td style="padding:12px;color:#00f0ff">${attack.username || 'N/A'}</td>
                <td style="padding:12px;color:#ff0080">${attack.password || 'N/A'}</td>
                <td style="padding:12px;color:#888">${attack.protocol_version || 'SSH'}</td>
            `;
        });
    } catch (err) {
        console.error('Table error:', err);
    }
}

// Initialize all
async function init() {
    console.log('Dashboard initializing...');
    await updateStats();
    await updateAttacksChart();
    await updateUsernamesChart();
    await updatePasswordsChart();
    await updateTable();
    console.log('Dashboard ready!');
}

// Auto-refresh stats and table every 5 seconds
setInterval(() => {
    updateStats();
    updateTable();
}, 5000);

// Start when page loads
document.addEventListener('DOMContentLoaded', init);