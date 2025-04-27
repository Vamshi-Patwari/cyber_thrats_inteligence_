document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard loaded!');

    // Load initial data
    loadIPThreats();
    loadTrafficAnalysis();
    loadLoginAttempts();

    // Initialize map
    initMap();

    // Initialize charts
    initCharts();

    // Set up tab switching
    setupTabs();
});

// Function to load IP threats
function loadIPThreats() {
    fetch('/api/threats')
        .then(response => response.json())
        .then(threats => {
            const tableBody = document.querySelector('#ip-threats-table tbody');
            tableBody.innerHTML = '';

            threats.forEach(threat => {
                const row = document.createElement('tr');

                // Format date
                const lastSeen = new Date(threat.lastSeen);
                const formattedDate = lastSeen.toLocaleDateString() + ' ' + lastSeen.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});

                row.innerHTML = `
                    <td>${threat.ipAddress}</td>
                    <td>${threat.type}</td>
                    <td><span class="severity-badge ${threat.severity.toLowerCase()}">${threat.severity}</span></td>
                    <td>${formattedDate}</td>
                    <td>${threat.count}</td>
                    <td><button class="button" data-threat-id="${threat.id}">Details</button></td>
                `;

                tableBody.appendChild(row);
            });

            // Add event listeners to detail buttons
            document.querySelectorAll('#ip-threats-table button').forEach(button => {
                button.addEventListener('click', function() {
                    const threatId = this.getAttribute('data-threat-id');
                    loadThreatDetails(threatId);
                });
            });

            // Select the first threat by default if available
            if (threats.length > 0) {
                loadThreatDetails(threats[0].id);
            }
        })
        .catch(error => {
            console.error('Error loading IP threats:', error);
        });
}

// Function to load traffic analysis data
function loadTrafficAnalysis() {
    fetch('/api/traffic')
        .then(response => response.json())
        .then(trafficData => {
            const tableBody = document.querySelector('#traffic-table tbody');
            tableBody.innerHTML = '';

            trafficData.forEach(traffic => {
                const row = document.createElement('tr');

                // Format date
                const timestamp = new Date(traffic.timestamp);
                const formattedTime = timestamp.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});

                row.innerHTML = `
                    <td>${formattedTime}</td>
                    <td>${traffic.sourceIP}</td>
                    <td>${traffic.destinationIP}</td>
                    <td>${traffic.protocol}</td>
                    <td>${traffic.port}</td>
                    <td>${traffic.bytesTransferred.toLocaleString()}</td>
                    <td>${traffic.packetsTransferred}</td>
                    <td><span class="status-badge ${traffic.status.toLowerCase()}">${traffic.status}</span></td>
                `;

                tableBody.appendChild(row);
            });
        })
        .catch(error => {
            console.error('Error loading traffic analysis:', error);
        });
}

// Function to load threat details
function loadThreatDetails(threatId) {
    fetch(`/api/threat/${threatId}`)
        .then(response => response.json())
        .then(threat => {
            const detailsContent = document.getElementById('threat-details-content');

            // Format date
            const lastSeen = new Date(threat.lastSeen);
            const formattedDate = lastSeen.toLocaleDateString() + ' ' + lastSeen.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});

            detailsContent.innerHTML = `
                <div class="detail-row">
                    <strong>IP Address:</strong> ${threat.ipAddress}
                </div>
                <div class="detail-row">
                    <strong>Type:</strong> ${threat.type}
                </div>
                <div class="detail-row">
                    <strong>Severity:</strong>
                    <span class="severity-badge ${threat.severity.toLowerCase()}">${threat.severity}</span>
                </div>
                <div class="detail-row">
                    <strong>Last Seen:</strong> ${formattedDate}
                </div>
                <div class="detail-row">
                    <strong>Count:</strong> ${threat.count}
                </div>
                <div class="detail-row">
                    <strong>Description:</strong> ${threat.description}
                </div>
                <div class="detail-row">
                    <strong>Source:</strong> ${threat.source}
                </div>
            `;
        })
        .catch(error => {
            console.error('Error loading threat details:', error);
        });
}

// Function to set up tab switching
function setupTabs() {
    const tabs = document.querySelectorAll('.tab');

    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            // Remove active class from all tabs
            tabs.forEach(t => t.classList.remove('active'));

            // Add active class to clicked tab
            this.classList.add('active');

            // Hide all tab content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });

            // Show the selected tab content
            const tabId = this.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');

            // Refresh map when switching to the map tab
            if (tabId === 'threat-map' && window.threatMap) {
                window.threatMap.invalidateSize();
            }

            // Refresh charts when switching to the threat distribution tab
            if (tabId === 'threat-distribution') {
                initCharts();
            }
        });
    });
}

// Global variable to store the map
let threatMap;

// Function to initialize the map
function initMap() {
    // Create map instance
    threatMap = L.map('map').setView([20, 0], 2);
    window.threatMap = threatMap;

    // Add dark theme map tile layer
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(threatMap);

    // Load threat markers
    loadThreatMarkers();
}

// Function to load threat markers on the map
function loadThreatMarkers() {
    fetch('/api/threats')
        .then(response => response.json())
        .then(threats => {
            threats.forEach(threat => {
                if (threat.location) {
                    // Determine marker color based on severity
                    let markerColor;
                    switch (threat.severity.toLowerCase()) {
                        case 'high':
                            markerColor = '#d32f2f';
                            break;
                        case 'medium':
                            markerColor = '#f9a825';
                            break;
                        case 'low':
                            markerColor = '#43a047';
                            break;
                        default:
                            markerColor = '#2196f3';
                    }

                    // Create custom marker
                    const marker = L.circleMarker([threat.location.lat, threat.location.lng], {
                        radius: 8,
                        fillColor: markerColor,
                        color: '#fff',
                        weight: 1,
                        opacity: 1,
                        fillOpacity: 0.8
                    }).addTo(threatMap);

                    // Add popup with threat information
                    const popupContent = `
                        <div class="marker-popup">
                            <h3>${threat.ipAddress}</h3>
                            <p><strong>Type:</strong> ${threat.type}</p>
                            <p><strong>Severity:</strong> ${threat.severity}</p>
                            <p><strong>Location:</strong> ${threat.location.city}, ${threat.location.country}</p>
                            <p><strong>Count:</strong> ${threat.count}</p>
                        </div>
                    `;

                    // Create and style the popup
                    const popup = L.popup({
                        className: 'dark-popup',
                        closeButton: true,
                        autoClose: true,
                        closeOnEscapeKey: true
                    }).setContent(popupContent);

                    marker.bindPopup(popup);
                }
            });
        })
        .catch(error => {
            console.error('Error loading threat markers:', error);
        });
}

// Function to load login attempts
function loadLoginAttempts() {
    fetch('/api/login-attempts')
        .then(response => response.json())
        .then(loginAttempts => {
            const tableBody = document.querySelector('#login-attempts-table tbody');
            tableBody.innerHTML = '';

            loginAttempts.forEach(login => {
                const row = document.createElement('tr');

                // Format date
                const timestamp = new Date(login.timestamp);
                const formattedDate = timestamp.toLocaleDateString() + ' ' + timestamp.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});

                // Determine anomaly score class
                let anomalyScoreClass = 'low';
                if (login.anomalyScore > 70) {
                    anomalyScoreClass = 'high';
                } else if (login.anomalyScore > 30) {
                    anomalyScoreClass = 'medium';
                }

                // Create anomaly score indicator
                const anomalyScoreHTML = `
                    <div class="anomaly-score">
                        <div class="anomaly-score-fill ${anomalyScoreClass}" style="width: ${login.anomalyScore}%;"></div>
                        <div class="anomaly-score-text">${Math.round(login.anomalyScore)}</div>
                    </div>
                `;

                row.innerHTML = `
                    <td>${formattedDate}</td>
                    <td>${login.username}</td>
                    <td>${login.ipAddress}</td>
                    <td>${login.behaviorType}</td>
                    <td><span class="status-badge ${login.status.toLowerCase()}">${login.status}</span></td>
                    <td>${anomalyScoreHTML}</td>
                    <td><button class="button" data-login-id="${login.id}">Details</button></td>
                `;

                tableBody.appendChild(row);
            });

            // Add event listeners to detail buttons
            document.querySelectorAll('#login-attempts-table button').forEach(button => {
                button.addEventListener('click', function() {
                    const loginId = this.getAttribute('data-login-id');
                    loadLoginDetails(loginId, loginAttempts);
                });
            });

            // Select the first login attempt by default if available
            if (loginAttempts.length > 0) {
                loadLoginDetails(loginAttempts[0].id, loginAttempts);
            }
        })
        .catch(error => {
            console.error('Error loading login attempts:', error);
        });
}

// Function to load login details
function loadLoginDetails(loginId, loginAttempts) {
    const login = loginAttempts.find(l => l.id === loginId);
    if (!login) return;

    const detailsContent = document.getElementById('login-details-content');

    // Format date
    const timestamp = new Date(login.timestamp);
    const formattedDate = timestamp.toLocaleDateString() + ' ' + timestamp.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'});

    detailsContent.innerHTML = `
        <div class="detail-row">
            <strong>Username:</strong> ${login.username}
        </div>
        <div class="detail-row">
            <strong>Time:</strong> ${formattedDate}
        </div>
        <div class="detail-row">
            <strong>IP Address:</strong> ${login.ipAddress}
        </div>
        <div class="detail-row">
            <strong>Device Info:</strong> ${login.deviceInfo}
        </div>
        <div class="detail-row">
            <strong>Location:</strong> ${login.location}
        </div>
        <div class="detail-row">
            <strong>Behavior Type:</strong> ${login.behaviorType}
        </div>
        <div class="detail-row">
            <strong>Status:</strong>
            <span class="status-badge ${login.status.toLowerCase()}">${login.status}</span>
        </div>
        <div class="detail-row">
            <strong>Anomaly Score:</strong> ${login.anomalyScore}
        </div>
        <div class="detail-row">
            <strong>Description:</strong> ${login.description}
        </div>
    `;
}

// Function to initialize all charts
function initCharts() {
    // Fetch data for charts
    Promise.all([
        fetch('/api/threats').then(response => response.json()),
        fetch('/api/traffic').then(response => response.json())
    ])
    .then(([threats, traffic]) => {
        createThreatTypesChart(threats);
        createSeverityChart(threats);
        createProtocolChart(traffic);
        createActionChart(traffic);
    })
    .catch(error => {
        console.error('Error loading chart data:', error);
    });
}

// Function to create Threat Types Distribution chart
function createThreatTypesChart(threats) {
    // Count threats by type
    const threatTypes = {};
    threats.forEach(threat => {
        if (!threatTypes[threat.type]) {
            threatTypes[threat.type] = 0;
        }
        threatTypes[threat.type]++;
    });

    // Prepare data for chart
    const labels = Object.keys(threatTypes);
    const data = Object.values(threatTypes);
    const backgroundColors = [
        'rgba(255, 99, 132, 0.7)',
        'rgba(54, 162, 235, 0.7)',
        'rgba(255, 206, 86, 0.7)',
        'rgba(75, 192, 192, 0.7)',
        'rgba(153, 102, 255, 0.7)',
        'rgba(255, 159, 64, 0.7)'
    ];

    // Create chart
    const ctx = document.getElementById('threatTypesChart').getContext('2d');
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColors,
                borderColor: '#1e1e1e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#e0e0e0',
                        font: {
                            size: 12
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Distribution of Threat Types',
                    color: '#ffffff',
                    font: {
                        size: 16
                    }
                },
                tooltip: {
                    backgroundColor: '#2a2a2a',
                    titleColor: '#ffffff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#333333',
                    borderWidth: 1
                }
            }
        }
    });
}

// Function to create Severity Distribution chart
function createSeverityChart(threats) {
    // Count threats by severity
    const severityCounts = {
        'High': 0,
        'Medium': 0,
        'Low': 0
    };

    threats.forEach(threat => {
        if (severityCounts.hasOwnProperty(threat.severity)) {
            severityCounts[threat.severity]++;
        }
    });

    // Prepare data for chart
    const labels = Object.keys(severityCounts);
    const data = Object.values(severityCounts);
    const backgroundColors = [
        'rgba(255, 82, 82, 0.7)',  // High - Red
        'rgba(255, 171, 64, 0.7)', // Medium - Orange
        'rgba(105, 240, 174, 0.7)' // Low - Green
    ];

    // Create chart
    const ctx = document.getElementById('severityChart').getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColors,
                borderColor: '#1e1e1e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#e0e0e0',
                        font: {
                            size: 12
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Distribution of Threat Severity',
                    color: '#ffffff',
                    font: {
                        size: 16
                    }
                },
                tooltip: {
                    backgroundColor: '#2a2a2a',
                    titleColor: '#ffffff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#333333',
                    borderWidth: 1
                }
            }
        }
    });
}

// Function to create Protocol Distribution chart
function createProtocolChart(traffic) {
    // Count traffic by protocol
    const protocolCounts = {};
    traffic.forEach(entry => {
        if (!protocolCounts[entry.protocol]) {
            protocolCounts[entry.protocol] = 0;
        }
        protocolCounts[entry.protocol]++;
    });

    // Prepare data for chart
    const labels = Object.keys(protocolCounts);
    const data = Object.values(protocolCounts);
    const backgroundColors = [
        'rgba(54, 162, 235, 0.7)',  // TCP - Blue
        'rgba(255, 206, 86, 0.7)',  // UDP - Yellow
        'rgba(153, 102, 255, 0.7)'  // ICMP - Purple
    ];

    // Create chart
    const ctx = document.getElementById('protocolChart').getContext('2d');
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Number of Connections',
                data: data,
                backgroundColor: backgroundColors,
                borderColor: '#1e1e1e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: '#333333'
                    },
                    ticks: {
                        color: '#e0e0e0'
                    }
                },
                x: {
                    grid: {
                        color: '#333333'
                    },
                    ticks: {
                        color: '#e0e0e0'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Distribution of Network Protocols',
                    color: '#ffffff',
                    font: {
                        size: 16
                    }
                },
                tooltip: {
                    backgroundColor: '#2a2a2a',
                    titleColor: '#ffffff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#333333',
                    borderWidth: 1
                }
            }
        }
    });
}

// Function to create Action Taken Distribution chart
function createActionChart(traffic) {
    // Count traffic by action taken (status)
    const actionCounts = {
        'Blocked': 0,
        'Allowed': 0,
        'Flagged': 0
    };

    traffic.forEach(entry => {
        if (actionCounts.hasOwnProperty(entry.status)) {
            actionCounts[entry.status]++;
        }
    });

    // Prepare data for chart
    const labels = Object.keys(actionCounts);
    const data = Object.values(actionCounts);
    const backgroundColors = [
        'rgba(255, 82, 82, 0.7)',   // Blocked - Red
        'rgba(105, 240, 174, 0.7)', // Allowed - Green
        'rgba(255, 171, 64, 0.7)'   // Flagged - Orange
    ];

    // Create chart
    const ctx = document.getElementById('actionChart').getContext('2d');
    new Chart(ctx, {
        type: 'polarArea',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColors,
                borderColor: '#1e1e1e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    grid: {
                        color: '#333333'
                    },
                    ticks: {
                        color: '#e0e0e0',
                        backdropColor: 'transparent'
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#e0e0e0',
                        font: {
                            size: 12
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Distribution of Actions Taken',
                    color: '#ffffff',
                    font: {
                        size: 16
                    }
                },
                tooltip: {
                    backgroundColor: '#2a2a2a',
                    titleColor: '#ffffff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#333333',
                    borderWidth: 1
                }
            }
        }
    });
}