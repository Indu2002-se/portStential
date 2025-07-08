// Global variables
    let scanActive = false;
    let scanId = null;
    let updateInterval = null;
    let resultCount = 0; // Track the number of found ports
    let currentLogIndex = 0;

    // DOM Elements
    const targetInput = document.getElementById('target');
    const portRangeInput = document.getElementById('port-range');
    const threadsInput = document.getElementById('threads');
    const timeoutInput = document.getElementById('timeout');
    const usePredefinedCheck = document.getElementById('use-predefined');
    const scanButton = document.getElementById('scan-button');
    const stopButton = document.getElementById('stop-button');
    const exportButton = document.getElementById('export-button');
    const progressBar = document.getElementById('progress-bar');
    const statusLabel = document.getElementById('status-label');
    const resultsBody = document.getElementById('results-body');
    const logContainer = document.getElementById('log-container');
    const exportModal = document.getElementById('export-modal');
    const threadWarning = document.getElementById('thread-warning');
    const currentTimeElem = document.getElementById('current-time');

    // Update current time
    function updateTime() {
        const now = new Date();
        currentTimeElem.textContent = now.toLocaleString();
    }
    
    // Play sound effect (optional - silent if audio not supported)
    function playTechSound(type) {
        // Function stub - sound effects disabled for now
        console.log(`Sound effect: ${type}`);
    }

    // Initialize
    document.addEventListener('DOMContentLoaded', function() {
        updateTime();
        setInterval(updateTime, 1000);

        // Event listeners
        usePredefinedCheck.addEventListener('change', togglePortInput);

        // Check thread count on input to show warnings
        threadsInput.addEventListener('input', function() {
            const threadCount = parseInt(this.value);
            // Estimate CPU cores for client-side warning (actual value comes from server later)
            const estimatedCores = 8;
            const recommendedMax = estimatedCores * 2;

            if (threadCount > recommendedMax) {
                threadWarning.style.display = 'block';
            } else {
                threadWarning.style.display = 'none';
            }
        });
    });

    // Tab navigation
    function showTab(tabId) {
        // Hide all tab content
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
        });

        // Remove active class from all tab buttons
        document.querySelectorAll('.tab-button').forEach(button => {
            button.classList.remove('active');
        });

        // Show selected tab
        document.getElementById(tabId).classList.add('active');

        // Set active class on clicked button
        event.currentTarget.classList.add('active');
    }

    // Toggle port input based on checkbox
    function togglePortInput() {
        if (usePredefinedCheck.checked) {
            portRangeInput.value = '21,22,23,25,80,443,3306,8080';
        } else {
            portRangeInput.value = '';
        }
    }

    // Get local IP address
    function useLocalIP() {
        fetch('/api/local-ip')
            .then(response => response.json())
            .then(data => {
                if (data.ip) {
                    targetInput.value = data.ip;
                    addLogEntry('Local IP detected: ' + data.ip, 'info');
                }
            })
            .catch(error => {
                addLogEntry('Error detecting local IP: ' + error, 'error');
            });
    }

    // Validate input before starting scan
    function validateInput() {
        const target = targetInput.value.trim();
        const portRange = portRangeInput.value.trim();
        const threads = parseInt(threadsInput.value);
        const timeout = parseFloat(timeoutInput.value);

        if (!target) {
            alert('Please enter a target host.');
            return false;
        }

        if (!portRange) {
            alert('Please enter port range.');
            return false;
        }

        if (isNaN(threads) || threads < 1) {
            alert('Thread count must be at least 1.');
            return false;
        }

        if (isNaN(timeout) || timeout <= 0) {
            alert('Timeout must be greater than 0.');
            return false;
        }

        return true;
    }

    // Start scan
    function startScan() {
        if (!validateInput()) return;

        const scanData = {
            target: targetInput.value.trim(),
            port_range: portRangeInput.value.trim(),
            threads: parseInt(threadsInput.value),
            timeout: parseFloat(timeoutInput.value)
        };

        // Update UI
        scanButton.disabled = true;
        stopButton.disabled = false;
        exportButton.disabled = true;
        statusLabel.textContent = 'Scanning...';
        progressBar.style.width = '0%';

        // Clear previous results
        clearResults(false);

        // Log scan start
        addLogEntry(`Starting scan on ${scanData.target} with ${scanData.threads} threads`, 'info');
        addLogEntry(`Timeout set to ${scanData.timeout} seconds`, 'info');

        // Check and warn about excessive thread count
        const estimatedCores = 8; // Estimate for client-side warning
        const recommendedMax = estimatedCores * 2;
        if (scanData.threads > recommendedMax) {
            addLogEntry(`Warning: ${scanData.threads} threads may be too high for optimal performance. The server will limit this as needed.`, 'warning');
        }

        // Start scan
        fetch('/api/scan/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(scanData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                addLogEntry('Error: ' + data.error, 'error');
                resetScanUI();
                return;
            }

            scanId = data.scan_id;
            scanActive = true;

            // Start polling for updates
            updateInterval = setInterval(updateScanProgress, 500);
        })
        .catch(error => {
            addLogEntry('Error starting scan: ' + error, 'error');
            resetScanUI();
        });
    }

    // Stop scan
    function stopScan() {
        if (!scanActive || !scanId) return;

        fetch(`/api/scan/${scanId}/stop`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            addLogEntry('Scan stopped by user', 'warning');
            resetScanUI();
        })
        .catch(error => {
            addLogEntry('Error stopping scan: ' + error, 'error');
        });

        clearInterval(updateInterval);
        scanActive = false;
    }

    // Update scan progress
    function updateScanProgress() {
        if (!scanActive || !scanId) return;

        fetch(`/api/scan/${scanId}/status`)
            .then(response => response.json())
            .then(data => {
                // Show CPU cores information and thread limit if available
                if (data.cpu_cores && !window.threadInfoShown) {
                    const maxRecommended = data.max_recommended_threads || (data.cpu_cores * 2);
                    addLogEntry(`System has ${data.cpu_cores} CPU cores. Maximum recommended threads: ${maxRecommended}`, 'info');

                    // If user specified more threads than recommended, show a warning
                    const userThreads = parseInt(threadsInput.value);
                    if (userThreads > maxRecommended) {
                        addLogEntry(`Your specified ${userThreads} threads exceeds the recommended maximum of ${maxRecommended}. The scan will use a limited thread count for optimal performance.`, 'warning');
                    }

                    window.threadInfoShown = true;
                }

                // Update progress bar
                progressBar.style.width = `${data.progress}%`;

                // Add new log entries
                if (data.logs && data.logs.length > 0) {
                    data.logs.forEach(log => {
                        addLogEntry(log.message, log.level);
                    });
                }

                // Update results table
                if (data.results) {
                    updateResultsTable(data.results);
                }
                
                // Update dashboard statistics if we're on the same page
                if (data.real_time_stats) {
                    updateDashboardStats(data.real_time_stats);
                }

                // Check if scan is complete
                if (data.status === 'completed' || data.status === 'failed' || data.status === 'stopped') {
                    clearInterval(updateInterval);
                    scanActive = false;

                    if (data.status === 'completed') {
                        statusLabel.textContent = `Completed in ${data.duration.toFixed(2)}s`;
                        progressBar.style.width = '100%';

                        // Enable export button if we have results
                        if (data.results && Object.keys(data.results).length > 0) {
                            exportButton.disabled = false;
                        }
                    } else if (data.status === 'failed') {
                        statusLabel.textContent = 'Scan Failed';
                    } else {
                        statusLabel.textContent = 'Stopped';
                    }

                    scanButton.disabled = false;
                    stopButton.disabled = true;
                }
            })
            .catch(error => {
                addLogEntry('Error updating scan status: ' + error, 'error');
                clearInterval(updateInterval);
                resetScanUI();
            });
    }

    // Update dashboard statistics if we're on the dashboard page
    function updateDashboardStats(stats) {
        // Check if dashboard elements exist (we might be on the scanner page)
        const openPortsElement = document.getElementById('open-ports');
        const vulnerabilitiesElement = document.getElementById('vulnerabilities');
        
        if (openPortsElement && stats.open_ports !== undefined) {
            openPortsElement.textContent = stats.open_ports;
        }
        
        if (vulnerabilitiesElement && stats.vulnerabilities !== undefined) {
            vulnerabilitiesElement.textContent = stats.vulnerabilities;
        }
    }

    // Update results table with banner grabbing information
    function updateResultsTable(results) {
        const host = targetInput.value.trim();
        const currentPortCount = Object.keys(results).length;

        // Only update if we have new results
        if (currentPortCount > resultCount) {
            const newPorts = currentPortCount - resultCount;
            playTechSound('success');
            addLogEntry(`Discovered ${newPorts} new open port${newPorts > 1 ? 's' : ''}`, 'success');

            // Clear and rebuild the table for animation effect
            resultsBody.innerHTML = '';

            // Update with new result count
            resultCount = currentPortCount;

            // Populate table with animation delay
            let delay = 0;
            for (const port in results) {
                // Get full port data (either string or object with banner information)
                const portData = results[port];

                // Parse port data to extract service, version, and server details
                let service, version, server, banner, sslCert;

                // Check if port data is enhanced format (object) or legacy format (string)
                if (typeof portData === 'string') {
                    // Legacy format - just a service name string
                    service = portData;
                    version = '';
                    server = '';
                } else {
                    // Enhanced format - object with detailed banner information
                    service = portData.service || '';
                    version = portData.version || '';
                    server = portData.server || '';
                    banner = portData.banner || '';
                    sslCert = portData.ssl_cert || {};

                    // Log banner data for debugging if needed
                    console.log("Port data JSON:", encodeURIComponent(JSON.stringify(portData)));
                    console.log("Parsed port data:", portData);
                }

                // Create the table row with all available information
                const row = document.createElement('tr');
                row.style.animation = `fadeIn 0.3s ease ${delay}s both`;

                // Build row with service and version information
                // This also adds server information if available
                // Create details button for viewing banner information
                const hasDetails = banner || (sslCert && Object.values(sslCert).some(v => v));
                const detailsBtn = hasDetails ? 
                    `<button class="btn btn-sm btn-info" onclick="showDetailsModal(${port}, '${escape(JSON.stringify(portData))}')">View</button>` : 
                    '';
                
                // Add status indicator with color coding
                const statusIndicator = '<span class="status-indicator status-open"></span>';
                
                row.innerHTML = `
                    <td>${host}</td>
                    <td>${port}</td>
                    <td class="port-open">${statusIndicator}Open</td>
                    <td>${service}</td>
                    <td>${version || ''}</td>
                    <td>${server || ''}</td>
                    <td>${detailsBtn}</td>
                `;

                // Add banner information to log view
                if (banner) {
                    addLogEntry(`Port ${port} banner: ${banner}`, 'info');
                }

                // Add SSL certificate information to log view if available
                if (sslCert && Object.keys(sslCert).length > 0) {
                    let sslInfo = '';
                    for (const [key, value] of Object.entries(sslCert)) {
                        if (value) {
                            const formattedKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                            sslInfo += `${formattedKey}: ${value}, `;
                        }
                    }

                    if (sslInfo) {
                        sslInfo = sslInfo.slice(0, -2); // Remove trailing comma and space
                        addLogEntry(`Port ${port} SSL Certificate: ${sslInfo}`, 'info');
                    }
                }

                resultsBody.appendChild(row);
                delay += 0.05;
            }
        }
    }

    // Show details modal for SSL and banner information
    function showDetailsModal(port, portDataJson) {
        try {
            // Debug
            console.log("Port data JSON:", portDataJson);

            // Safely decode the JSON data
            let portData;
            try {
                portData = JSON.parse(unescape(portDataJson));
            } catch (parseError) {
                console.error("Failed to parse JSON:", parseError);
                // Fallback - try to parse without unescape
                try {
                    portData = JSON.parse(portDataJson);
                } catch (e) {
                    // If all fails, create a default object with the service name
                    portData = {
                        service: "Unknown",
                        banner: "Unable to parse service details."
                    };
                }
            }

            // Debug
            console.log("Parsed port data:", portData);

            const detailsTitle = document.getElementById('details-title');
            const sslContent = document.getElementById('ssl-content');
            const bannerContent = document.getElementById('banner-content');
            const sslSection = document.getElementById('ssl-info');
            const bannerSection = document.getElementById('banner-info');

            // Set the title
            detailsTitle.textContent = `Service Details for Port ${port}`;

            // Display SSL certificate information if available
            const sslCert = portData.ssl_cert || {};
            if (sslCert && Object.keys(sslCert).length > 0 && Object.values(sslCert).some(v => v)) {
                sslSection.style.display = 'block';
                let sslHtml = '<table class="details-table">';

                for (const [key, value] of Object.entries(sslCert)) {
                    if (value) {
                        const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                        sslHtml += `<tr><td>${displayKey}</td><td>${value}</td></tr>`;
                    }
                }

                sslHtml += '</table>';
                sslContent.innerHTML = sslHtml;
            } else {
                sslSection.style.display = 'none';
            }

            // Display banner information if available
            const banner = portData.banner || '';
            if (banner && banner.length > 0) {
                bannerSection.style.display = 'block';
                bannerContent.textContent = banner;
            } else {
                // If we have SSH and a specific version but no banner, create a simple banner
                if (portData.service === "SSH" && portData.version) {
                    bannerSection.style.display = 'block';
                    bannerContent.textContent = `SSH Protocol Version ${portData.version}`;
                } else {
                    bannerSection.style.display = 'none';
                }
            }

            // If both sections are hidden, show a message
            if (sslSection.style.display === 'none' && bannerSection.style.display === 'none') {
                bannerSection.style.display = 'block';
                bannerContent.textContent = "No detailed banner information available for this port.";
            }

            // Show the modal with animation
            const modal = document.getElementById('details-modal');
            modal.classList.add('show');

        } catch (error) {
            console.error('Error displaying port details:', error);
            addLogEntry(`Error displaying details: ${error.message}`, 'error');

            // Show error in the modal instead of just failing silently
            const detailsTitle = document.getElementById('details-title');
            const bannerContent = document.getElementById('banner-content');
            const bannerSection = document.getElementById('banner-info');

            document.getElementById('ssl-info').style.display = 'none';
            bannerSection.style.display = 'block';
            detailsTitle.textContent = `Service Details for Port ${port}`;
            bannerContent.textContent = `Error retrieving details: ${error.message}`;

            // Show the modal with animation
            const modal = document.getElementById('details-modal');
            modal.classList.add('show');
        }
    }

    // Close details modal
    function closeDetailsModal() {
        const modal = document.getElementById('details-modal');
        modal.classList.remove('show');
    }

    // Add log entry
    function addLogEntry(message, level) {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry log-${level}`;
        logEntry.textContent = `[${timestamp}] ${message}`;

        logContainer.appendChild(logEntry);
        logContainer.scrollTop = logContainer.scrollHeight; // Auto-scroll to bottom
    }

    // Reset scan UI
    function resetScanUI() {
        scanButton.disabled = false;
        stopButton.disabled = true;
        scanActive = false;
        clearInterval(updateInterval);
    }

    // Clear results
    function clearResults(clearLogs = true) {
        // Clear table
        resultsBody.innerHTML = '';

        // Reset progress
        progressBar.style.width = '0%';

        // Disable export button
        exportButton.disabled = true;

        // Clear logs if requested
        if (clearLogs) {
            logContainer.innerHTML = '';
            addLogEntry('Results and logs cleared', 'info');
        }

        // Update status
        statusLabel.textContent = 'Ready';
    }

    // Show export options modal
    function showExportOptions() {
        if (resultsBody.innerHTML === '') {
            alert('No results to export.');
            return;
        }

        exportModal.style.display = 'block';
        // Add a small delay to ensure display is set before adding show class
        setTimeout(() => {
            exportModal.classList.add('show');
        }, 10);
    }

    // Close export modal
    function closeExportModal() {
        exportModal.classList.remove('show');
        // Wait for transition to complete before hiding
        setTimeout(() => {
            exportModal.style.display = 'none';
        }, 300);
    }

    // Export results
    function exportResults(format) {
        fetch(`/api/export/${format}?scan_id=${scanId}`)
            .then(response => {
                if (response.ok) {
                    return response.blob();
                }
                throw new Error('Export failed');
            })
            .then(blob => {
                // Create file name
                const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                const host = targetInput.value.trim();
                const fileName = `${host}_scan_${timestamp}.${format}`;

                // Create download link
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = fileName;
                document.body.appendChild(a);
                a.click();

                // Clean up
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);

                addLogEntry(`Results exported to ${format.toUpperCase()}`, 'success');
                closeExportModal();
            })
            .catch(error => {
                addLogEntry(`Export error: ${error}`, 'error');
                alert(`Export failed: ${error}`);
            });
    }

    // Close modal when clicking outside of it
    window.onclick = function(event) {
        if (event.target === exportModal) {
            closeExportModal();
        }
        if (event.target === document.getElementById('details-modal')) {
            closeDetailsModal();
        }
    };