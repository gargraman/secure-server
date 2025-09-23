// Alert Management JavaScript Module
const AlertManagement = {
    selectedAlerts: new Set(),
    currentFilters: {},
    searchTimeout: null,
    refreshInterval: null,
    dataTable: null,

    init: function() {
        console.log('Initializing Alert Management...');

        // Parse URL parameters and set initial filters
        this.parseUrlParameters();

        this.loadAlertStatistics();
        this.loadAlerts();
        this.initializeDataTable();
        this.startAutoRefresh();
        this.loadFilterOptions();
    },

    // Parse URL parameters and set initial filters
    parseUrlParameters: function() {
        const urlParams = new URLSearchParams(window.location.search);

        // Map URL parameters to filter fields
        const paramMappings = {
            'severity': 'severityFilter',
            'status': 'statusFilter',
            'assignee': 'assigneeFilter',
            'time_range': 'timeRangeFilter',
            'search': 'searchFilter'
        };

        // Set filter values from URL parameters
        for (const [param, elementId] of Object.entries(paramMappings)) {
            const value = urlParams.get(param);
            if (value) {
                const element = document.getElementById(elementId);
                if (element) {
                    element.value = value;
                    this.currentFilters[param] = value;
                }
            }
        }

        // Handle special cases
        if (urlParams.get('severity') === 'critical') {
            // Update active filter count display
            this.updateActiveFilterCount();
        }
    },

    // Load alert statistics for dashboard cards
    loadAlertStatistics: async function() {
        try {
            const stats = await Utils.apiRequest('/alerts/statistics');

            document.getElementById('criticalAlerts').textContent = stats.critical_count || 0;
            document.getElementById('criticalUnresolved').textContent = stats.critical_unresolved || 0;
            document.getElementById('highAlerts').textContent = stats.high_count || 0;
            document.getElementById('avgResponseTime').textContent = Utils.formatDuration(stats.avg_response_time || 0);
            document.getElementById('totalInvestigating').textContent = stats.investigating_count || 0;
            document.getElementById('assignedAnalysts').textContent = stats.assigned_analysts || 0;
            document.getElementById('resolvedToday').textContent = stats.resolved_today || 0;
            document.getElementById('mttr').textContent = Math.round(stats.mttr_minutes || 0);

        } catch (error) {
            console.error('Error loading alert statistics:', error);
            Utils.showAlert('Failed to load alert statistics', 'danger');
        }
    },

    // Load alerts data
    loadAlerts: async function() {
        try {
            Utils.setLoading('alertsTableBody', true);

            const queryParams = new URLSearchParams(this.currentFilters);
            const alerts = await Utils.apiRequest(`/api/alerts?${queryParams}`);

            this.renderAlerts(alerts.alerts || []);
            this.updateAlertCount(alerts.total || 0);

        } catch (error) {
            console.error('Error loading alerts:', error);
            Utils.showAlert('Failed to load alerts', 'danger');
            this.renderEmptyState();
        } finally {
            Utils.setLoading('alertsTableBody', false);
        }
    },

    // Initialize DataTables for advanced table features
    initializeDataTable: function() {
        if ($.fn.DataTable) {
            this.dataTable = $('#alertsTable').DataTable({
                paging: true,
                searching: false, // Use custom search
                ordering: true,
                info: true,
                pageLength: 25,
                responsive: true,
                columnDefs: [
                    { orderable: false, targets: [0, 8] }, // Checkbox and actions columns
                    { className: "text-center", targets: [0, 2, 3, 4, 8] }
                ],
                order: [[7, 'desc']], // Sort by created date by default
                language: {
                    emptyTable: "No security alerts found",
                    zeroRecords: "No alerts match your current filters"
                }
            });
        }
    },

    // Render alerts in different views
    renderAlerts: function(alerts) {
        const currentView = document.querySelector('input[name="viewType"]:checked').id;

        switch (currentView) {
            case 'listView':
                this.renderListView(alerts);
                break;
            case 'cardView':
                this.renderCardView(alerts);
                break;
            case 'timelineView':
                this.renderTimelineView(alerts);
                break;
        }
    },

    // Render alerts in list view
    renderListView: function(alerts) {
        const tbody = document.getElementById('alertsTableBody');

        if (!alerts || alerts.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" class="text-center text-muted py-4">
                        <i class="fas fa-inbox fa-3x mb-3 d-block"></i>
                        No alerts match your current filters
                    </td>
                </tr>
            `;
            return;
        }

        const rows = alerts.map(alert => {
            const createdAt = Utils.formatTimestamp(alert.created_at);
            const severityBadge = this.getSeverityBadge(alert.severity);
            const statusBadge = this.getStatusBadge(alert.status);
            const riskScore = this.getRiskScoreDisplay(alert.risk_score);
            const mitreTechniques = this.getMitreTechniquesDisplay(alert.mitre_techniques);
            const assignee = alert.assignee || 'Unassigned';
            const alertPriorityClass = `alert-priority-${alert.severity}`;

            return `
                <tr class="alert-row ${alertPriorityClass}" data-alert-id="${alert.id}">
                    <td>
                        <input type="checkbox" class="alert-checkbox"
                               value="${alert.id}" onchange="AlertManagement.toggleAlertSelection(this)">
                    </td>
                    <td>
                        <div class="fw-medium">${this.escapeHtml(alert.name)}</div>
                        <small class="text-muted">${alert.external_id}</small>
                        <div class="mt-1">
                            ${this.getAlertTags(alert.tags)}
                        </div>
                    </td>
                    <td class="text-center">${severityBadge}</td>
                    <td class="text-center">${statusBadge}</td>
                    <td class="text-center">${riskScore}</td>
                    <td>${mitreTechniques}</td>
                    <td>
                        <div class="d-flex align-items-center">
                            <i class="fas fa-user-circle me-1 text-muted"></i>
                            <small>${assignee}</small>
                        </div>
                    </td>
                    <td>
                        <small>${createdAt}</small>
                    </td>
                    <td class="text-center">
                        <div class="btn-group" role="group">
                            <button class="btn btn-sm btn-outline-primary"
                                    onclick="AlertManagement.viewAlert('${alert.id}')"
                                    title="View Details">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button class="btn btn-sm btn-outline-info"
                                    onclick="AlertManagement.showInvestigationGraph('${alert.id}')"
                                    title="Investigation Graph">
                                <i class="fas fa-project-diagram"></i>
                            </button>
                            <div class="btn-group" role="group">
                                <button class="btn btn-sm btn-outline-secondary dropdown-toggle"
                                        data-bs-toggle="dropdown" aria-expanded="false">
                                    <i class="fas fa-ellipsis-v"></i>
                                </button>
                                <ul class="dropdown-menu">
                                    <li><a class="dropdown-item" href="#" onclick="AlertManagement.assignAlert('${alert.id}')">
                                        <i class="fas fa-user me-2"></i>Assign
                                    </a></li>
                                    <li><a class="dropdown-item" href="#" onclick="AlertManagement.escalateAlert('${alert.id}')">
                                        <i class="fas fa-arrow-up me-2"></i>Escalate
                                    </a></li>
                                    <li><a class="dropdown-item" href="#" onclick="AlertManagement.resolveAlert('${alert.id}')">
                                        <i class="fas fa-check me-2"></i>Resolve
                                    </a></li>
                                    <li><hr class="dropdown-divider"></li>
                                    <li><a class="dropdown-item text-danger" href="#" onclick="AlertManagement.closeAlert('${alert.id}')">
                                        <i class="fas fa-times me-2"></i>Close
                                    </a></li>
                                </ul>
                            </div>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        tbody.innerHTML = rows;

        // Reinitialize DataTable if it exists
        if (this.dataTable) {
            this.dataTable.clear().rows.add($(tbody).find('tr')).draw();
        }
    },

    // Render alerts in card view
    renderCardView: function(alerts) {
        const container = document.getElementById('alertsCardContainer');

        if (!alerts || alerts.length === 0) {
            container.innerHTML = `
                <div class="col-12 text-center text-muted py-5">
                    <i class="fas fa-inbox fa-3x mb-3 d-block"></i>
                    <h5>No alerts match your current filters</h5>
                    <p>Try adjusting your filter criteria or create a new alert.</p>
                </div>
            `;
            return;
        }

        const cards = alerts.map(alert => {
            const severityClass = `security-card-${alert.severity}`;
            const severityBadge = this.getSeverityBadge(alert.severity);
            const statusBadge = this.getStatusBadge(alert.status);
            const riskScore = this.getRiskScoreDisplay(alert.risk_score);
            const createdAt = Utils.formatTimestamp(alert.created_at);

            return `
                <div class="col-md-6 col-lg-4 mb-4">
                    <div class="security-card ${severityClass}" data-alert-id="${alert.id}">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start mb-3">
                                <div class="flex-grow-1">
                                    <h6 class="card-title mb-1">${this.escapeHtml(alert.name)}</h6>
                                    <small class="text-muted">${alert.external_id}</small>
                                </div>
                                <div class="text-end">
                                    ${severityBadge}
                                </div>
                            </div>

                            <div class="row g-2 mb-3">
                                <div class="col-6">
                                    <small class="text-muted d-block">Status</small>
                                    ${statusBadge}
                                </div>
                                <div class="col-6">
                                    <small class="text-muted d-block">Risk Score</small>
                                    ${riskScore}
                                </div>
                            </div>

                            <div class="mb-3">
                                <small class="text-muted d-block mb-1">MITRE Techniques</small>
                                ${this.getMitreTechniquesDisplay(alert.mitre_techniques, 3)}
                            </div>

                            <div class="d-flex justify-content-between align-items-center">
                                <small class="text-muted">
                                    <i class="fas fa-clock me-1"></i>
                                    ${createdAt}
                                </small>
                                <div class="btn-group">
                                    <button class="btn btn-sm btn-primary" onclick="AlertManagement.viewAlert('${alert.id}')">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                    <button class="btn btn-sm btn-outline-primary" onclick="AlertManagement.showInvestigationGraph('${alert.id}')">
                                        <i class="fas fa-project-diagram"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        container.innerHTML = cards;
    },

    // Render alerts in timeline view
    renderTimelineView: function(alerts) {
        const container = document.getElementById('alertsTimeline');

        if (!alerts || alerts.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted py-5">
                    <i class="fas fa-timeline fa-3x mb-3 d-block"></i>
                    <h5>No alerts in timeline</h5>
                    <p>Adjust your filters to see alert timeline.</p>
                </div>
            `;
            return;
        }

        // Sort alerts by created date for timeline
        const sortedAlerts = alerts.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        const timelineItems = sortedAlerts.map(alert => {
            const severityBadge = this.getSeverityBadge(alert.severity);
            const statusBadge = this.getStatusBadge(alert.status);
            const createdAt = Utils.formatTimestamp(alert.created_at);

            return `
                <div class="timeline-item ${alert.severity}" data-alert-id="${alert.id}">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <div class="flex-grow-1">
                            <h6 class="mb-1">${this.escapeHtml(alert.name)}</h6>
                            <small class="text-muted">${alert.external_id}</small>
                        </div>
                        <div>
                            ${severityBadge}
                            ${statusBadge}
                        </div>
                    </div>

                    <p class="text-muted small mb-2">${this.escapeHtml(alert.description || 'No description available')}</p>

                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <small class="text-muted">
                                <i class="fas fa-clock me-1"></i>
                                ${createdAt}
                            </small>
                        </div>
                        <div class="btn-group">
                            <button class="btn btn-sm btn-outline-primary" onclick="AlertManagement.viewAlert('${alert.id}')">
                                <i class="fas fa-eye"></i> View
                            </button>
                            <button class="btn btn-sm btn-outline-info" onclick="AlertManagement.showInvestigationGraph('${alert.id}')">
                                <i class="fas fa-project-diagram"></i> Graph
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        container.innerHTML = timelineItems;
    },

    // Update the active filter count display
    updateActiveFilterCount: function() {
        const activeCount = Object.keys(this.currentFilters).length;
        const countElement = document.getElementById('activeFiltersCount');
        const countBadge = document.getElementById('filterCount');

        if (activeCount > 0) {
            countBadge.textContent = activeCount;
            countElement.style.display = 'inline-block';
        } else {
            countElement.style.display = 'none';
        }
    },

    // Helper functions for rendering
    getSeverityBadge: function(severity) {
        const badges = {
            'critical': '<span class="badge severity-critical">Critical</span>',
            'high': '<span class="badge severity-high">High</span>',
            'medium': '<span class="badge severity-medium">Medium</span>',
            'low': '<span class="badge severity-low">Low</span>'
        };
        return badges[severity] || '<span class="badge bg-secondary">Unknown</span>';
    },

    getStatusBadge: function(status) {
        const badges = {
            'new': '<span class="badge status-new bg-secondary">New</span>',
            'investigating': '<span class="badge status-investigating bg-primary">Investigating</span>',
            'contained': '<span class="badge status-contained bg-warning">Contained</span>',
            'resolved': '<span class="badge status-resolved bg-success">Resolved</span>',
            'false_positive': '<span class="badge bg-info">False Positive</span>'
        };
        return badges[status] || '<span class="badge bg-secondary">Unknown</span>';
    },

    getRiskScoreDisplay: function(riskScore) {
        if (!riskScore) return '<span class="text-muted">--</span>';

        let scoreClass = 'risk-score-low';
        if (riskScore >= 90) scoreClass = 'risk-score-critical';
        else if (riskScore >= 70) scoreClass = 'risk-score-high';
        else if (riskScore >= 40) scoreClass = 'risk-score-medium';

        return `<div class="risk-score ${scoreClass}">${riskScore}</div>`;
    },

    getMitreTechniquesDisplay: function(techniques, limit = null) {
        if (!techniques || techniques.length === 0) {
            return '<span class="text-muted">None</span>';
        }

        const displayTechniques = limit ? techniques.slice(0, limit) : techniques;
        const techniqueElements = displayTechniques.map(technique => {
            const tacticClass = this.getMitreTacticClass(technique.tactic);
            return `<a href="#" class="mitre-technique ${tacticClass}"
                       onclick="AlertManagement.showMitreDetails('${technique.technique_id}')"
                       title="${technique.technique_name}">
                       ${technique.technique_id}
                    </a>`;
        }).join(' ');

        if (limit && techniques.length > limit) {
            const remaining = techniques.length - limit;
            return `${techniqueElements} <small class="text-muted">+${remaining} more</small>`;
        }

        return techniqueElements;
    },

    getMitreTacticClass: function(tactic) {
        const tacticClasses = {
            'Initial Access': 'mitre-initial-access',
            'Execution': 'mitre-execution',
            'Persistence': 'mitre-persistence',
            'Privilege Escalation': 'mitre-privilege-escalation',
            'Defense Evasion': 'mitre-defense-evasion',
            'Credential Access': 'mitre-credential-access',
            'Discovery': 'mitre-discovery',
            'Lateral Movement': 'mitre-lateral-movement',
            'Collection': 'mitre-collection',
            'Impact': 'mitre-impact'
        };
        return tacticClasses[tactic] || 'mitre-execution';
    },

    getAlertTags: function(tags) {
        if (!tags || tags.length === 0) return '';

        return tags.map(tag =>
            `<span class="badge bg-light text-dark border">${this.escapeHtml(tag)}</span>`
        ).join(' ');
    },

    // Filter and search functions
    applyFilters: function() {
        this.currentFilters = {
            severity: document.getElementById('severityFilter').value,
            status: document.getElementById('statusFilter').value,
            assignee: document.getElementById('assigneeFilter').value,
            time_range: document.getElementById('timeRangeFilter').value,
            mitre_technique: document.getElementById('mitreFilter').value,
            risk_score_range: document.getElementById('riskScoreFilter').value,
            search: document.getElementById('searchFilter').value.trim()
        };

        // Remove empty filters
        Object.keys(this.currentFilters).forEach(key => {
            if (!this.currentFilters[key]) {
                delete this.currentFilters[key];
            }
        });

        this.updateActiveFilterCount();
        this.loadAlerts();
    },

    debounceSearch: function() {
        clearTimeout(this.searchTimeout);
        this.searchTimeout = setTimeout(() => {
            this.applyFilters();
        }, 500);
    },

    clearAllFilters: function() {
        document.getElementById('severityFilter').value = '';
        document.getElementById('statusFilter').value = '';
        document.getElementById('assigneeFilter').value = '';
        document.getElementById('timeRangeFilter').value = '24h';
        document.getElementById('mitreFilter').value = '';
        document.getElementById('riskScoreFilter').value = '';
        document.getElementById('searchFilter').value = '';

        this.currentFilters = {};
        this.updateActiveFilterCount();
        this.loadAlerts();
    },

    // Selection and bulk operations
    toggleAlertSelection: function(checkbox) {
        const alertId = checkbox.value;

        if (checkbox.checked) {
            this.selectedAlerts.add(alertId);
            checkbox.closest('tr').classList.add('selected');
        } else {
            this.selectedAlerts.delete(alertId);
            checkbox.closest('tr').classList.remove('selected');
        }

        this.updateBulkActionsBar();
    },

    toggleSelectAll: function() {
        const selectAll = document.getElementById('selectAll');
        const checkboxes = document.querySelectorAll('.alert-checkbox');

        checkboxes.forEach(checkbox => {
            checkbox.checked = selectAll.checked;
            this.toggleAlertSelection(checkbox);
        });
    },

    updateBulkActionsBar: function() {
        const bulkBar = document.getElementById('bulkActionsBar');
        const selectedCount = document.getElementById('selectedCount');

        selectedCount.textContent = this.selectedAlerts.size;

        if (this.selectedAlerts.size > 0) {
            bulkBar.classList.add('show');
        } else {
            bulkBar.classList.remove('show');
        }
    },

    // Alert actions
    viewAlert: function(alertId) {
        // Load and display alert details in modal
        this.loadAlertDetails(alertId);
        const modal = new bootstrap.Modal(document.getElementById('alertDetailModal'));
        modal.show();
    },

    loadAlertDetails: async function(alertId) {
        try {
            const alert = await Utils.apiRequest(`/api/alerts/${alertId}`);
            this.renderAlertDetails(alert);
        } catch (error) {
            console.error('Error loading alert details:', error);
            Utils.showAlert('Failed to load alert details', 'danger');
        }
    },

    renderAlertDetails: function(alert) {
        // Populate alert detail modal with comprehensive information
        const detailContent = document.getElementById('alertDetailContent');
        const iocsContent = document.getElementById('alertIOCs');
        const mitreContent = document.getElementById('alertMitreTechniques');
        const timelineContent = document.getElementById('alertTimeline');

        // Basic alert information
        detailContent.innerHTML = `
            <div class="row g-3">
                <div class="col-md-6">
                    <strong>Alert Name:</strong><br>
                    <span>${this.escapeHtml(alert.name)}</span>
                </div>
                <div class="col-md-6">
                    <strong>External ID:</strong><br>
                    <span class="font-monospace">${alert.external_id}</span>
                </div>
                <div class="col-md-6">
                    <strong>Severity:</strong><br>
                    ${this.getSeverityBadge(alert.severity)}
                </div>
                <div class="col-md-6">
                    <strong>Status:</strong><br>
                    ${this.getStatusBadge(alert.status)}
                </div>
                <div class="col-md-6">
                    <strong>Risk Score:</strong><br>
                    ${this.getRiskScoreDisplay(alert.risk_score)}
                </div>
                <div class="col-md-6">
                    <strong>Assignee:</strong><br>
                    <span>${alert.assignee || 'Unassigned'}</span>
                </div>
                <div class="col-12">
                    <strong>Description:</strong><br>
                    <p class="mt-1">${this.escapeHtml(alert.description || 'No description available')}</p>
                </div>
            </div>
        `;

        // IOCs
        if (alert.iocs && alert.iocs.length > 0) {
            const iocsHtml = alert.iocs.map(ioc => `
                <div class="ioc-container">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="ioc-type ioc-${ioc.type.toLowerCase()}">${ioc.type}</span>
                            <code class="ms-2">${this.escapeHtml(ioc.value)}</code>
                        </div>
                        <div>
                            <button class="btn btn-sm btn-outline-primary" onclick="AlertManagement.enrichIOC('${ioc.value}', '${ioc.type}')">
                                <i class="fas fa-search-plus"></i> Enrich
                            </button>
                        </div>
                    </div>
                </div>
            `).join('');
            iocsContent.innerHTML = iocsHtml;
        } else {
            iocsContent.innerHTML = '<p class="text-muted">No IOCs identified</p>';
        }

        // MITRE techniques
        if (alert.mitre_techniques && alert.mitre_techniques.length > 0) {
            mitreContent.innerHTML = this.getMitreTechniquesDisplay(alert.mitre_techniques);
        } else {
            mitreContent.innerHTML = '<p class="text-muted">No MITRE techniques mapped</p>';
        }

        // Investigation timeline
        if (alert.timeline && alert.timeline.length > 0) {
            const timelineHtml = alert.timeline.map(event => `
                <div class="timeline-item">
                    <div class="fw-medium">${this.escapeHtml(event.action)}</div>
                    <small class="text-muted">${Utils.formatTimestamp(event.timestamp)}</small>
                    <p class="small mb-0">${this.escapeHtml(event.details)}</p>
                </div>
            `).join('');
            timelineContent.innerHTML = timelineHtml;
        } else {
            timelineContent.innerHTML = '<p class="text-muted">No timeline events</p>';
        }
    },

    // View switching
    switchView: function(viewType) {
        document.getElementById('listViewContainer').style.display =
            viewType === 'listView' ? 'block' : 'none';
        document.getElementById('cardViewContainer').style.display =
            viewType === 'cardView' ? 'block' : 'none';
        document.getElementById('timelineViewContainer').style.display =
            viewType === 'timelineView' ? 'block' : 'none';

        // Re-render in the new view
        this.loadAlerts();
    },

    // Investigation graph
    showInvestigationGraph: function(alertId) {
        const modal = new bootstrap.Modal(document.getElementById('investigationGraphModal'));
        modal.show();

        // Initialize graph visualization
        this.loadInvestigationGraph(alertId);
    },

    loadInvestigationGraph: async function(alertId) {
        try {
            const graphData = await Utils.apiRequest(`/api/alerts/${alertId}/graph`);

            // Initialize Cytoscape.js graph
            if (window.GraphVisualization) {
                window.GraphVisualization.renderInvestigationGraph('investigationGraph', graphData);
            }
        } catch (error) {
            console.error('Error loading investigation graph:', error);
            Utils.showAlert('Failed to load investigation graph', 'danger');
        }
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
            this.loadAlertStatistics();
            this.loadAlerts();
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
function refreshAlerts() {
    AlertManagement.loadAlerts();
    AlertManagement.loadAlertStatistics();
}

function toggleSelectAll() {
    AlertManagement.toggleSelectAll();
}

function applyFilters() {
    AlertManagement.applyFilters();
}

function debounceSearch() {
    AlertManagement.debounceSearch();
}

function clearAllFilters() {
    AlertManagement.clearAllFilters();
}

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    AlertManagement.stopAutoRefresh();
});
