document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard loaded!');

    // Load initial data
    loadIPThreats();
    loadTrafficAnalysis();

    // Initialize map
    initMap();

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
