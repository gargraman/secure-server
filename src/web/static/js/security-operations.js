// Security Operations JavaScript Module
const SecurityOperations = {
    // Real-time threat level monitoring
    threatLevelMonitor: null,

    init: function() {
        console.log('Initializing Security Operations...');
        this.initializeThreatLevelMonitoring();
        this.initializeQuickActions();
        this.initializeRealTimeUpdates();
    },

    // Initialize threat level monitoring
    initializeThreatLevelMonitoring: function() {
        this.updateThreatLevel();
        this.threatLevelMonitor = setInterval(() => {
            this.updateThreatLevel();
        }, 60000); // Update every minute
    },

    // Update threat level indicator
    updateThreatLevel: async function() {
        try {
            const threatData = await Utils.apiRequest('/security/threat-level');
            const indicator = document.getElementById('threatLevelIndicator');

            if (!indicator) return;

            const level = threatData.threat_level.current_level.toLowerCase();
            const levelText = threatData.threat_level.current_level;

            // Update indicator class and text
            indicator.className = `badge threat-level-${level}`;
            indicator.innerHTML = `
                <i class="fas fa-shield-alt me-1"></i>
                ${levelText}
            `;

            // Update title with additional info
            indicator.title = `Threat Level: ${levelText}\nLast Updated: ${new Date().toLocaleTimeString()}`;

            // Show notification for threat level changes (placeholder - API doesn't currently support change detection)
            // if (threatData.changed) {
            //     this.showThreatLevelChangeNotification(levelText, threatData.reason);
            // }

        } catch (error) {
            console.error('Error updating threat level:', error);
            const indicator = document.getElementById('threatLevelIndicator');
            if (indicator) {
                indicator.className = 'badge bg-secondary';
                indicator.innerHTML = '<i class="fas fa-question me-1"></i>Unknown';
            }
        }
    },

    // Show threat level change notification
    showThreatLevelChangeNotification: function(level, reason) {
        const severity = level.toLowerCase() === 'critical' ? 'danger' :
                        level.toLowerCase() === 'high' ? 'warning' : 'info';

        Utils.showAlert(`Threat level changed to ${level}: ${reason}`, severity, 10000);
    },

    // Initialize quick actions
    initializeQuickActions: function() {
        // Quick action handlers are defined globally for onclick events
        window.createIncident = this.createIncident;
        window.runThreatHunt = this.runThreatHunt;
        window.exportReport = this.exportReport;
        window.emergencyResponse = this.emergencyResponse;
    },

    // Create incident workflow
    createIncident: function() {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fas fa-fire me-2 text-danger"></i>
                            Create Security Incident
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <form id="createIncidentForm">
                        <div class="modal-body">
                            <div class="mb-3">
                                <label for="incidentTitle" class="form-label">Incident Title *</label>
                                <input type="text" class="form-control" id="incidentTitle" required>
                            </div>
                            <div class="mb-3">
                                <label for="incidentSeverity" class="form-label">Severity *</label>
                                <select class="form-select" id="incidentSeverity" required>
                                    <option value="critical">Critical - Immediate Response Required</option>
                                    <option value="high">High - Response Within 1 Hour</option>
                                    <option value="medium">Medium - Response Within 4 Hours</option>
                                    <option value="low">Low - Response Within 24 Hours</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label for="incidentType" class="form-label">Incident Type</label>
                                <select class="form-select" id="incidentType">
                                    <option value="malware">Malware Infection</option>
                                    <option value="phishing">Phishing Attack</option>
                                    <option value="data_breach">Data Breach</option>
                                    <option value="insider_threat">Insider Threat</option>
                                    <option value="ddos">DDoS Attack</option>
                                    <option value="unauthorized_access">Unauthorized Access</option>
                                    <option value="other">Other</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label for="incidentDescription" class="form-label">Description</label>
                                <textarea class="form-control" id="incidentDescription" rows="4"
                                         placeholder="Describe the incident details..."></textarea>
                            </div>
                            <div class="mb-3">
                                <label for="affectedAssets" class="form-label">Affected Assets</label>
                                <input type="text" class="form-control" id="affectedAssets"
                                       placeholder="List affected systems, IPs, users...">
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="submit" class="btn btn-danger">
                                <i class="fas fa-fire me-1"></i>
                                Create Incident
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();

        // Handle form submission
        document.getElementById('createIncidentForm').addEventListener('submit', async function(e) {
            e.preventDefault();

            const incidentData = {
                title: document.getElementById('incidentTitle').value,
                severity: document.getElementById('incidentSeverity').value,
                type: document.getElementById('incidentType').value,
                description: document.getElementById('incidentDescription').value,
                affected_assets: document.getElementById('affectedAssets').value
            };

            try {
                await Utils.apiRequest('/incidents', {
                    method: 'POST',
                    body: JSON.stringify(incidentData)
                });

                Utils.showAlert('Incident created successfully', 'success');
                bsModal.hide();
                document.body.removeChild(modal);

                // Redirect to incident management page
                window.location.href = '/incidents';

            } catch (error) {
                console.error('Error creating incident:', error);
                Utils.showAlert(`Failed to create incident: ${error.message}`, 'danger');
            }
        });

        // Cleanup when modal is hidden
        modal.addEventListener('hidden.bs.modal', function() {
            document.body.removeChild(modal);
        });
    },

    // Start threat hunting
    runThreatHunt: function() {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fas fa-crosshairs me-2 text-warning"></i>
                            Threat Hunting Session
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row g-3">
                            <div class="col-md-6">
                                <label for="huntType" class="form-label">Hunt Type</label>
                                <select class="form-select" id="huntType">
                                    <option value="ioc_sweep">IOC Sweep</option>
                                    <option value="behavioral_analysis">Behavioral Analysis</option>
                                    <option value="network_anomalies">Network Anomalies</option>
                                    <option value="user_behavior">User Behavior Analysis</option>
                                    <option value="file_analysis">File Analysis</option>
                                    <option value="custom_query">Custom Query</option>
                                </select>
                            </div>
                            <div class="col-md-6">
                                <label for="huntTimeframe" class="form-label">Timeframe</label>
                                <select class="form-select" id="huntTimeframe">
                                    <option value="1h">Last 1 Hour</option>
                                    <option value="24h" selected>Last 24 Hours</option>
                                    <option value="7d">Last 7 Days</option>
                                    <option value="30d">Last 30 Days</option>
                                    <option value="custom">Custom Range</option>
                                </select>
                            </div>
                            <div class="col-12">
                                <label for="huntCriteria" class="form-label">Hunt Criteria</label>
                                <textarea class="form-control" id="huntCriteria" rows="4"
                                         placeholder="Enter specific IOCs, patterns, or queries to hunt for..."></textarea>
                            </div>
                            <div class="col-md-6">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="includeHistorical" checked>
                                    <label class="form-check-label" for="includeHistorical">
                                        Include Historical Data
                                    </label>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="realTimeHunt">
                                    <label class="form-check-label" for="realTimeHunt">
                                        Real-time Monitoring
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-warning" onclick="SecurityOperations.executeThreatHunt(this)">
                            <i class="fas fa-search me-1"></i>
                            Start Hunt
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();

        // Cleanup when modal is hidden
        modal.addEventListener('hidden.bs.modal', function() {
            document.body.removeChild(modal);
        });
    },

    // Execute threat hunt
    executeThreatHunt: async function(button) {
        const huntData = {
            type: document.getElementById('huntType').value,
            timeframe: document.getElementById('huntTimeframe').value,
            criteria: document.getElementById('huntCriteria').value,
            include_historical: document.getElementById('includeHistorical').checked,
            real_time: document.getElementById('realTimeHunt').checked
        };

        try {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Starting Hunt...';

            const response = await Utils.apiRequest('/threat-hunting/start', {
                method: 'POST',
                body: JSON.stringify(huntData)
            });

            Utils.showAlert(`Threat hunt started successfully. Session ID: ${response.session_id}`, 'success', 8000);

            // Close modal and redirect to hunt results
            bootstrap.Modal.getInstance(button.closest('.modal')).hide();

            // Optionally redirect to hunt results page
            setTimeout(() => {
                window.location.href = `/investigations?session=${response.session_id}`;
            }, 2000);

        } catch (error) {
            console.error('Error starting threat hunt:', error);
            Utils.showAlert(`Failed to start threat hunt: ${error.message}`, 'danger');

            button.disabled = false;
            button.innerHTML = '<i class="fas fa-search me-1"></i>Start Hunt';
        }
    },

    // Export security report
    exportReport: function() {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fas fa-download me-2 text-info"></i>
                            Export Security Report
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="reportType" class="form-label">Report Type</label>
                            <select class="form-select" id="reportType">
                                <option value="daily_summary">Daily Security Summary</option>
                                <option value="weekly_summary">Weekly Security Summary</option>
                                <option value="incident_report">Incident Report</option>
                                <option value="threat_intelligence">Threat Intelligence Report</option>
                                <option value="compliance">Compliance Report</option>
                                <option value="vulnerability">Vulnerability Assessment</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label for="reportFormat" class="form-label">Format</label>
                            <select class="form-select" id="reportFormat">
                                <option value="pdf">PDF Document</option>
                                <option value="excel">Excel Spreadsheet</option>
                                <option value="json">JSON Data</option>
                                <option value="csv">CSV File</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label for="reportTimeframe" class="form-label">Timeframe</label>
                            <select class="form-select" id="reportTimeframe">
                                <option value="24h">Last 24 Hours</option>
                                <option value="7d">Last 7 Days</option>
                                <option value="30d">Last 30 Days</option>
                                <option value="90d">Last 90 Days</option>
                            </select>
                        </div>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="includeGraphs" checked>
                            <label class="form-check-label" for="includeGraphs">
                                Include Charts and Graphs
                            </label>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-info" onclick="SecurityOperations.generateReport(this)">
                            <i class="fas fa-download me-1"></i>
                            Generate Report
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();

        // Cleanup when modal is hidden
        modal.addEventListener('hidden.bs.modal', function() {
            document.body.removeChild(modal);
        });
    },

    // Generate and download report
    generateReport: async function(button) {
        const reportData = {
            type: document.getElementById('reportType').value,
            format: document.getElementById('reportFormat').value,
            timeframe: document.getElementById('reportTimeframe').value,
            include_graphs: document.getElementById('includeGraphs').checked
        };

        try {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Generating...';

            const response = await Utils.apiRequest('/reports/generate', {
                method: 'POST',
                body: JSON.stringify(reportData)
            });

            // Create download link
            const downloadLink = document.createElement('a');
            downloadLink.href = response.download_url;
            downloadLink.download = response.filename;
            downloadLink.click();

            Utils.showAlert('Report generated and download started', 'success');
            bootstrap.Modal.getInstance(button.closest('.modal')).hide();

        } catch (error) {
            console.error('Error generating report:', error);
            Utils.showAlert(`Failed to generate report: ${error.message}`, 'danger');

            button.disabled = false;
            button.innerHTML = '<i class="fas fa-download me-1"></i>Generate Report';
        }
    },

    // Emergency response workflow
    emergencyResponse: function() {
        const confirmed = confirm(
            'This will initiate emergency response protocols.\n\n' +
            '• Activate incident response team\n' +
            '• Escalate to security leadership\n' +
            '• Begin containment procedures\n\n' +
            'Are you sure you want to continue?'
        );

        if (!confirmed) return;

        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog modal-lg">
                <div class="modal-content border-danger">
                    <div class="modal-header bg-danger text-white">
                        <h5 class="modal-title">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            Emergency Response Activation
                        </h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            <strong>Emergency Response Activated</strong><br>
                            All relevant personnel have been notified and emergency protocols are now in effect.
                        </div>

                        <div class="mb-3">
                            <label for="emergencyType" class="form-label">Emergency Type *</label>
                            <select class="form-select" id="emergencyType" required>
                                <option value="">Select emergency type...</option>
                                <option value="active_breach">Active Security Breach</option>
                                <option value="ransomware">Ransomware Attack</option>
                                <option value="critical_vuln">Critical Vulnerability</option>
                                <option value="insider_threat">Insider Threat</option>
                                <option value="supply_chain">Supply Chain Attack</option>
                                <option value="nation_state">Nation-State Activity</option>
                                <option value="other">Other Emergency</option>
                            </select>
                        </div>

                        <div class="mb-3">
                            <label for="emergencyDetails" class="form-label">Emergency Details *</label>
                            <textarea class="form-control" id="emergencyDetails" rows="4" required
                                     placeholder="Provide detailed information about the emergency..."></textarea>
                        </div>

                        <div class="mb-3">
                            <label for="impactAssessment" class="form-label">Impact Assessment</label>
                            <textarea class="form-control" id="impactAssessment" rows="3"
                                     placeholder="Describe the potential or observed impact..."></textarea>
                        </div>

                        <div class="row g-3">
                            <div class="col-md-6">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="isolateNetworks">
                                    <label class="form-check-label" for="isolateNetworks">
                                        Isolate Affected Networks
                                    </label>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="alertCustomers">
                                    <label class="form-check-label" for="alertCustomers">
                                        Prepare Customer Notifications
                                    </label>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="contactAuthorities">
                                    <label class="form-check-label" for="contactAuthorities">
                                        Contact Law Enforcement
                                    </label>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="mediaResponse">
                                    <label class="form-check-label" for="mediaResponse">
                                        Activate Media Response
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-danger" onclick="SecurityOperations.activateEmergencyResponse(this)">
                            <i class="fas fa-fire me-1"></i>
                            Activate Emergency Response
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();

        // Cleanup when modal is hidden
        modal.addEventListener('hidden.bs.modal', function() {
            document.body.removeChild(modal);
        });
    },

    // Activate emergency response
    activateEmergencyResponse: async function(button) {
        const emergencyData = {
            type: document.getElementById('emergencyType').value,
            details: document.getElementById('emergencyDetails').value,
            impact_assessment: document.getElementById('impactAssessment').value,
            actions: {
                isolate_networks: document.getElementById('isolateNetworks').checked,
                alert_customers: document.getElementById('alertCustomers').checked,
                contact_authorities: document.getElementById('contactAuthorities').checked,
                media_response: document.getElementById('mediaResponse').checked
            }
        };

        if (!emergencyData.type || !emergencyData.details) {
            Utils.showAlert('Please fill in all required fields', 'warning');
            return;
        }

        try {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Activating...';

            const response = await Utils.apiRequest('/emergency-response/activate', {
                method: 'POST',
                body: JSON.stringify(emergencyData)
            });

            Utils.showAlert(
                `Emergency response activated successfully. Response ID: ${response.response_id}`,
                'success',
                10000
            );

            bootstrap.Modal.getInstance(button.closest('.modal')).hide();

            // Redirect to emergency response dashboard
            setTimeout(() => {
                window.location.href = `/emergency-response/${response.response_id}`;
            }, 2000);

        } catch (error) {
            console.error('Error activating emergency response:', error);
            Utils.showAlert(`Failed to activate emergency response: ${error.message}`, 'danger');

            button.disabled = false;
            button.innerHTML = '<i class="fas fa-fire me-1"></i>Activate Emergency Response';
        }
    },

    // Initialize real-time updates
    initializeRealTimeUpdates: function() {
        if (typeof io !== 'undefined') {
            const socket = io();

            socket.on('threat_level_update', (data) => {
                this.updateThreatLevel();
            });

            socket.on('critical_alert', (data) => {
                this.showCriticalAlertNotification(data);
            });

            socket.on('system_status_update', (data) => {
                this.updateSystemStatus(data);
            });
        }
    },

    // Show critical alert notification
    showCriticalAlertNotification: function(alertData) {
        const notification = document.createElement('div');
        notification.className = 'position-fixed top-0 end-0 p-3';
        notification.style.zIndex = '9999';
        notification.innerHTML = `
            <div class="toast show align-items-center text-white bg-danger border-0" role="alert">
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="fas fa-fire me-2"></i>
                        <strong>Critical Alert:</strong> ${alertData.name}
                        <br>
                        <small>${alertData.description}</small>
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
        `;

        document.body.appendChild(notification);

        // Auto-remove after 10 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 10000);
    },

    // Update system status in navbar
    updateSystemStatus: function(statusData) {
        const statusElement = document.getElementById('systemStatusNavbar');
        if (statusElement) {
            const isHealthy = statusData.status === 'healthy';
            statusElement.className = isHealthy ? 'text-success' : 'text-danger';
            statusElement.textContent = isHealthy ? 'Cloud Active' : 'System Issues';
        }
    },

    // Cleanup
    destroy: function() {
        if (this.threatLevelMonitor) {
            clearInterval(this.threatLevelMonitor);
            this.threatLevelMonitor = null;
        }
    }
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    SecurityOperations.init();
});

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    SecurityOperations.destroy();
});

// Export to global scope
window.SecurityOperations = SecurityOperations;
