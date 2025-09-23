// Incident Response Management JavaScript Module
const IncidentManagement = {
    currentIncidents: [],
    refreshInterval: null,

    init: function() {
        console.log('Initializing Incident Management...');
        this.loadIncidentStatistics();
        this.loadActiveIncidents();
        this.startAutoRefresh();
    },

    // Load incident response statistics
    loadIncidentStatistics: async function() {
        try {
            const stats = await Utils.apiRequest('/incidents/statistics');

            document.getElementById('activeIncidents').textContent = stats.active_incidents || 0;
            document.getElementById('criticalIncidents').textContent = stats.critical_incidents || 0;
            document.getElementById('avgResponseTime').textContent = Utils.formatDuration(stats.avg_response_time || 0);

            document.getElementById('responseTeams').textContent = stats.response_teams || 0;
            document.getElementById('availableTeams').textContent = stats.available_teams || 0;

            document.getElementById('activePlaybooks').textContent = stats.active_playbooks || 0;
            document.getElementById('automatedSteps').textContent = stats.automated_steps || 0;
            document.getElementById('playbookCompletion').textContent = Math.round(stats.playbook_completion_rate || 0);

            document.getElementById('resolvedToday').textContent = stats.resolved_today || 0;
            document.getElementById('mttr').textContent = Math.round(stats.mttr_minutes || 0);
            document.getElementById('resolutionRate').textContent = Math.round(stats.resolution_rate || 0);

            // Update progress bars
            document.getElementById('activeIncidentsProgress').style.width = `${Math.min(100, (stats.active_incidents || 0) * 10)}%`;
            document.getElementById('teamsProgress').style.width = `${stats.team_utilization_rate || 0}%`;
            document.getElementById('playbooksProgress').style.width = `${stats.playbook_completion_rate || 0}%`;
            document.getElementById('resolutionProgress').style.width = `${stats.resolution_rate || 0}%`;

        } catch (error) {
            console.error('Error loading incident statistics:', error);
            Utils.showAlert('Failed to load incident statistics', 'danger');
        }
    },

    // Load active incidents
    loadActiveIncidents: async function() {
        try {
            const response = await Utils.apiRequest('/incidents');
            this.currentIncidents = response.incidents || [];
            this.renderIncidents();

        } catch (error) {
            console.error('Error loading incidents:', error);
            Utils.showAlert('Failed to load incidents', 'danger');
        }
    },

    // Render incidents in current view
    renderIncidents: function() {
        const currentView = document.querySelector('input[name="incidentView"]:checked').id;

        switch (currentView) {
            case 'boardView':
                this.renderBoardView();
                break;
            case 'listView':
                this.renderListView();
                break;
            case 'timelineView':
                this.renderTimelineView();
                break;
        }
    },

    // Render board view (Kanban style)
    renderBoardView: function() {
        const columns = {
            'new': { container: 'newIncidentsColumn', count: 'newIncidentsCount' },
            'investigating': { container: 'inProgressColumn', count: 'inProgressCount' },
            'containment': { container: 'containmentColumn', count: 'containmentCount' },
            'resolved': { container: 'resolvedColumn', count: 'resolvedCount' }
        };

        // Clear all columns
        Object.values(columns).forEach(column => {
            document.getElementById(column.container).innerHTML = '';
            document.getElementById(column.count).textContent = '0';
        });

        // Group incidents by status
        const groupedIncidents = this.groupIncidentsByStatus();

        Object.entries(groupedIncidents).forEach(([status, incidents]) => {
            const column = columns[status];
            if (!column) return;

            document.getElementById(column.count).textContent = incidents.length;

            const incidentCards = incidents.map(incident => this.createIncidentCard(incident)).join('');
            document.getElementById(column.container).innerHTML = incidentCards;
        });
    },

    // Render list view
    renderListView: function() {
        const tbody = document.getElementById('incidentsTableBody');

        if (!this.currentIncidents || this.currentIncidents.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="text-center text-muted py-4">
                        <i class="fas fa-inbox fa-3x mb-3 d-block"></i>
                        No active incidents
                    </td>
                </tr>
            `;
            return;
        }

        const rows = this.currentIncidents.map(incident => {
            const severityBadge = this.getSeverityBadge(incident.severity);
            const statusBadge = this.getStatusBadge(incident.status);
            const assignee = incident.assignee || 'Unassigned';
            const createdAt = Utils.formatTimestamp(incident.created_at);

            return `
                <tr data-incident-id="${incident.id}">
                    <td>
                        <code>${incident.id}</code>
                    </td>
                    <td>
                        <div class="fw-medium">${this.escapeHtml(incident.title)}</div>
                        <small class="text-muted">${this.escapeHtml(incident.type)}</small>
                    </td>
                    <td class="text-center">${severityBadge}</td>
                    <td class="text-center">${statusBadge}</td>
                    <td>
                        <div class="d-flex align-items-center">
                            <i class="fas fa-user-circle me-1 text-muted"></i>
                            <small>${assignee}</small>
                        </div>
                    </td>
                    <td>
                        <small>${createdAt}</small>
                    </td>
                    <td>
                        <div class="btn-group">
                            <button class="btn btn-sm btn-primary"
                                    onclick="IncidentManagement.viewIncident('${incident.id}')"
                                    title="View Details">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button class="btn btn-sm btn-warning"
                                    onclick="IncidentManagement.assignIncident('${incident.id}')"
                                    title="Assign">
                                <i class="fas fa-user"></i>
                            </button>
                            <button class="btn btn-sm btn-danger"
                                    onclick="IncidentManagement.escalateIncident('${incident.id}')"
                                    title="Escalate">
                                <i class="fas fa-arrow-up"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        tbody.innerHTML = rows;
    },

    // Render timeline view
    renderTimelineView: function() {
        const container = document.getElementById('incidentTimeline');

        if (!this.currentIncidents || this.currentIncidents.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted py-5">
                    <i class="fas fa-timeline fa-3x mb-3 d-block"></i>
                    <h5>No incidents in timeline</h5>
                    <p>All incidents will appear here chronologically.</p>
                </div>
            `;
            return;
        }

        // Sort incidents by creation date
        const sortedIncidents = [...this.currentIncidents].sort((a, b) =>
            new Date(b.created_at) - new Date(a.created_at)
        );

        const timelineItems = sortedIncidents.map(incident => {
            const severityBadge = this.getSeverityBadge(incident.severity);
            const statusBadge = this.getStatusBadge(incident.status);
            const createdAt = Utils.formatTimestamp(incident.created_at);

            return `
                <div class="timeline-item ${incident.severity}" data-incident-id="${incident.id}">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <div class="flex-grow-1">
                            <h6 class="mb-1">${this.escapeHtml(incident.title)}</h6>
                            <small class="text-muted">ID: ${incident.id} | Type: ${incident.type}</small>
                        </div>
                        <div>
                            ${severityBadge}
                            ${statusBadge}
                        </div>
                    </div>

                    <p class="text-muted small mb-2">
                        ${this.escapeHtml(incident.description || 'No description available')}
                    </p>

                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <small class="text-muted">
                                <i class="fas fa-clock me-1"></i>
                                ${createdAt}
                            </small>
                            ${incident.assignee ? `
                                <small class="text-muted ms-3">
                                    <i class="fas fa-user me-1"></i>
                                    ${incident.assignee}
                                </small>
                            ` : ''}
                        </div>
                        <div class="btn-group">
                            <button class="btn btn-sm btn-outline-primary"
                                    onclick="IncidentManagement.viewIncident('${incident.id}')">
                                <i class="fas fa-eye"></i> View
                            </button>
                            <button class="btn btn-sm btn-outline-warning"
                                    onclick="IncidentManagement.updateIncidentStatus('${incident.id}', 'investigating')">
                                <i class="fas fa-play"></i> Start Response
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        container.innerHTML = timelineItems;
    },

    // Create incident card for board view
    createIncidentCard: function(incident) {
        const severityIndicator = this.getSeverityIndicator(incident.severity);
        const statusBadge = this.getStatusBadge(incident.status);
        const age = this.calculateAge(incident.created_at);
        const assignee = incident.assignee || 'Unassigned';

        return `
            <div class="incident-card card mb-2" data-incident-id="${incident.id}">
                <div class="card-body p-3">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <div class="flex-grow-1">
                            <div class="d-flex align-items-center mb-1">
                                ${severityIndicator}
                                <h6 class="mb-0">${this.escapeHtml(incident.title)}</h6>
                            </div>
                            <small class="text-muted">ID: ${incident.id}</small>
                        </div>
                        <div class="dropdown">
                            <button class="btn btn-sm btn-outline-secondary" data-bs-toggle="dropdown">
                                <i class="fas fa-ellipsis-v"></i>
                            </button>
                            <ul class="dropdown-menu">
                                <li><a class="dropdown-item" href="#" onclick="IncidentManagement.viewIncident('${incident.id}')">
                                    <i class="fas fa-eye me-2"></i>View Details
                                </a></li>
                                <li><a class="dropdown-item" href="#" onclick="IncidentManagement.assignIncident('${incident.id}')">
                                    <i class="fas fa-user me-2"></i>Assign
                                </a></li>
                                <li><a class="dropdown-item" href="#" onclick="IncidentManagement.escalateIncident('${incident.id}')">
                                    <i class="fas fa-arrow-up me-2"></i>Escalate
                                </a></li>
                                <li><hr class="dropdown-divider"></li>
                                <li><a class="dropdown-item text-danger" href="#" onclick="IncidentManagement.archiveIncident('${incident.id}')">
                                    <i class="fas fa-archive me-2"></i>Archive
                                </a></li>
                            </ul>
                        </div>
                    </div>

                    <p class="card-text small text-muted mb-2">
                        ${this.escapeHtml(incident.description?.substring(0, 80) || 'No description')}${incident.description?.length > 80 ? '...' : ''}
                    </p>

                    <div class="d-flex justify-content-between align-items-center">
                        <small class="text-muted">
                            <i class="fas fa-user me-1"></i>
                            ${assignee}
                        </small>
                        <small class="text-muted">${age}</small>
                    </div>

                    <div class="mt-2 d-flex justify-content-between align-items-center">
                        ${statusBadge}
                        <button class="btn btn-sm btn-primary" onclick="IncidentManagement.viewIncident('${incident.id}')">
                            <i class="fas fa-arrow-right"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
    },

    // View incident details
    viewIncident: async function(incidentId) {
        try {
            const incident = await Utils.apiRequest(`/api/incidents/${incidentId}`);
            this.renderIncidentDetails(incident);

            const modal = new bootstrap.Modal(document.getElementById('incidentDetailModal'));
            modal.show();

        } catch (error) {
            console.error('Error loading incident details:', error);
            Utils.showAlert('Failed to load incident details', 'danger');
        }
    },

    // Render incident details in modal
    renderIncidentDetails: function(incident) {
        const detailContent = document.getElementById('incidentDetailContent');
        const playbook = document.getElementById('responsePlaybook');
        const communicationLog = document.getElementById('communicationLog');

        // Basic incident information
        detailContent.innerHTML = `
            <div class="row g-3">
                <div class="col-md-6">
                    <strong>Incident ID:</strong><br>
                    <code>${incident.id}</code>
                </div>
                <div class="col-md-6">
                    <strong>Type:</strong><br>
                    <span>${incident.type}</span>
                </div>
                <div class="col-md-6">
                    <strong>Severity:</strong><br>
                    ${this.getSeverityBadge(incident.severity)}
                </div>
                <div class="col-md-6">
                    <strong>Status:</strong><br>
                    ${this.getStatusBadge(incident.status)}
                </div>
                <div class="col-md-6">
                    <strong>Created:</strong><br>
                    <span>${Utils.formatTimestamp(incident.created_at)}</span>
                </div>
                <div class="col-md-6">
                    <strong>Assignee:</strong><br>
                    <span>${incident.assignee || 'Unassigned'}</span>
                </div>
                <div class="col-12">
                    <strong>Description:</strong><br>
                    <p class="mt-1">${this.escapeHtml(incident.description || 'No description available')}</p>
                </div>
                ${incident.affected_assets ? `
                    <div class="col-12">
                        <strong>Affected Assets:</strong><br>
                        <p class="mt-1">${this.escapeHtml(incident.affected_assets)}</p>
                    </div>
                ` : ''}
            </div>
        `;

        // Response playbook
        if (incident.playbook && incident.playbook.steps) {
            const playbookSteps = incident.playbook.steps.map((step, index) => {
                const stepClass = step.status === 'completed' ? 'completed' :
                                 step.status === 'active' ? 'active' : '';
                const icon = step.status === 'completed' ? 'fas fa-check-circle text-success' :
                            step.status === 'active' ? 'fas fa-play-circle text-primary' :
                            'fas fa-circle text-muted';

                return `
                    <div class="playbook-step ${stepClass}">
                        <div class="d-flex justify-content-between align-items-start">
                            <div class="flex-grow-1">
                                <div class="d-flex align-items-center mb-1">
                                    <i class="${icon} me-2"></i>
                                    <strong>Step ${index + 1}: ${step.title}</strong>
                                </div>
                                <p class="small text-muted mb-0">${step.description}</p>
                            </div>
                            <div>
                                ${step.automated ? '<span class="badge bg-info">Auto</span>' : ''}
                                ${step.estimated_time ? `<small class="text-muted ms-2">${step.estimated_time}</small>` : ''}
                            </div>
                        </div>
                        <div class="mt-2">
                            <button class="btn btn-sm btn-outline-primary" onclick="IncidentManagement.executeStep('${incident.id}', ${index})">
                                <i class="fas fa-play me-1"></i>Execute
                            </button>
                            ${step.status === 'completed' ? `
                                <button class="btn btn-sm btn-outline-success" onclick="IncidentManagement.viewStepResults('${incident.id}', ${index})">
                                    <i class="fas fa-eye me-1"></i>View Results
                                </button>
                            ` : ''}
                        </div>
                    </div>
                `;
            }).join('');

            playbook.innerHTML = playbookSteps;
        } else {
            playbook.innerHTML = `
                <div class="text-center text-muted py-3">
                    <i class="fas fa-book fa-2x mb-2"></i>
                    <p>No playbook assigned</p>
                    <button class="btn btn-primary" onclick="IncidentManagement.assignPlaybook('${incident.id}')">
                        <i class="fas fa-plus me-1"></i>Assign Playbook
                    </button>
                </div>
            `;
        }

        // Communication log
        if (incident.updates && incident.updates.length > 0) {
            const updates = incident.updates.map(update => `
                <div class="timeline-item">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <div class="fw-medium">${update.author}</div>
                            <small class="text-muted">${Utils.formatTimestamp(update.timestamp)}</small>
                        </div>
                        <div>
                            ${update.type === 'status_change' ? '<span class="badge bg-warning">Status Change</span>' :
                              update.type === 'escalation' ? '<span class="badge bg-danger">Escalation</span>' :
                              '<span class="badge bg-info">Update</span>'}
                        </div>
                    </div>
                    <p class="mt-2 mb-0">${this.escapeHtml(update.content)}</p>
                </div>
            `).join('');
            communicationLog.innerHTML = updates;
        } else {
            communicationLog.innerHTML = '<p class="text-muted">No updates yet</p>';
        }

        // Set form values
        document.getElementById('incidentStatusSelect').value = incident.status;
        document.getElementById('incidentSeveritySelect').value = incident.severity;

        // Update metrics
        document.getElementById('responseTime').textContent = Utils.formatDuration(incident.response_time || 0);
        document.getElementById('investigationTime').textContent = Utils.formatDuration(incident.investigation_time || 0);
        document.getElementById('containmentTime').textContent = Utils.formatDuration(incident.containment_time || 0);
        document.getElementById('recoveryTime').textContent = Utils.formatDuration(incident.recovery_time || 0);
    },

    // Helper functions
    groupIncidentsByStatus: function() {
        const groups = { new: [], investigating: [], containment: [], resolved: [] };

        this.currentIncidents.forEach(incident => {
            const status = incident.status;
            if (status === 'investigating' || status === 'in_progress') {
                groups.investigating.push(incident);
            } else if (status === 'containment' || status === 'eradication' || status === 'recovery') {
                groups.containment.push(incident);
            } else if (status === 'resolved' || status === 'closed') {
                groups.resolved.push(incident);
            } else {
                groups.new.push(incident);
            }
        });

        return groups;
    },

    getSeverityBadge: function(severity) {
        const badges = {
            'critical': '<span class="badge severity-critical">Critical</span>',
            'high': '<span class="badge severity-high">High</span>',
            'medium': '<span class="badge severity-medium">Medium</span>',
            'low': '<span class="badge severity-low">Low</span>'
        };
        return badges[severity] || '<span class="badge bg-secondary">Unknown</span>';
    },

    getSeverityIndicator: function(severity) {
        const colors = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#d97706',
            'low': '#059669'
        };
        return `<span class="severity-indicator" style="background-color: ${colors[severity] || '#6b7280'}"></span>`;
    },

    getStatusBadge: function(status) {
        const badges = {
            'new': '<span class="badge bg-secondary">New</span>',
            'investigating': '<span class="badge bg-primary">Investigating</span>',
            'containment': '<span class="badge bg-warning">Containment</span>',
            'eradication': '<span class="badge bg-info">Eradication</span>',
            'recovery': '<span class="badge bg-success">Recovery</span>',
            'resolved': '<span class="badge bg-success">Resolved</span>',
            'closed': '<span class="badge bg-secondary">Closed</span>'
        };
        return badges[status] || '<span class="badge bg-secondary">Unknown</span>';
    },

    calculateAge: function(createdAt) {
        const now = new Date();
        const created = new Date(createdAt);
        const diffHours = Math.floor((now - created) / (1000 * 60 * 60));

        if (diffHours < 1) return 'Just now';
        if (diffHours < 24) return `${diffHours}h ago`;
        return `${Math.floor(diffHours / 24)}d ago`;
    },

    // View switching
    switchView: function(viewType) {
        document.getElementById('boardViewContainer').style.display =
            viewType === 'boardView' ? 'block' : 'none';
        document.getElementById('listViewContainer').style.display =
            viewType === 'listView' ? 'block' : 'none';
        document.getElementById('timelineViewContainer').style.display =
            viewType === 'timelineView' ? 'block' : 'none';

        this.renderIncidents();
    },

    // Utility functions
    escapeHtml: function(text) {
        if (!text) return '';
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    },

    startAutoRefresh: function() {
        this.refreshInterval = setInterval(() => {
            this.loadIncidentStatistics();
            this.loadActiveIncidents();
        }, 30000); // Refresh every 30 seconds
    },

    stopAutoRefresh: function() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    }
};

// Global functions for template event handlers
function refreshIncidents() {
    IncidentManagement.loadActiveIncidents();
    IncidentManagement.loadIncidentStatistics();
    Utils.showAlert('Incidents refreshed', 'success', 2000);
}

function createEmergencyIncident() {
    // This function is defined in security-operations.js
    if (window.SecurityOperations) {
        SecurityOperations.emergencyResponse();
    }
}

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    IncidentManagement.stopAutoRefresh();
});

// Export to global scope
window.IncidentManagement = IncidentManagement;
