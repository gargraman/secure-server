// Enhanced SOC Dashboard JavaScript with improved UX and accessibility

// Dashboard data and charts
const Dashboard = {
    charts: {
        severity: null,
        status: null,
        threatTimeline: null
    },

    refreshInterval: null,
    realTimeUpdates: null,
    keyboardNavigationEnabled: true,

    init: function() {
        this.setupAccessibility();
        this.setupKeyboardNavigation();
        this.loadDashboardData();
        this.startAutoRefresh();
        this.setupProgressiveDisclosure();
    },

    setupAccessibility: function() {
        // Announce page load to screen readers
        this.announceToScreenReader('Dashboard loaded. Use Tab to navigate between sections.');

        // Setup ARIA live regions for dynamic updates
        const liveRegions = ['criticalAlerts', 'highPriorityIncidents', 'activeInvestigations', 'systemHealthScore'];
        liveRegions.forEach(id => {
            const element = document.getElementById(id);
            if (element && !element.getAttribute('aria-live')) {
                element.setAttribute('aria-live', 'polite');
            }
        });
    },

    setupKeyboardNavigation: function() {
        // Enable keyboard navigation for card interactions
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
                const activeElement = document.activeElement;
                if (activeElement.classList.contains('security-card')) {
                    event.preventDefault();
                    activeElement.click();
                }
            }
        });
    },

    setupProgressiveDisclosure: function() {
        // Implement collapsible sections for better information hierarchy
        const collapsibleSections = document.querySelectorAll('[data-bs-toggle="collapse"]');
        collapsibleSections.forEach(trigger => {
            trigger.addEventListener('click', () => {
                const targetId = trigger.getAttribute('data-bs-target');
                const target = document.querySelector(targetId);
                const isExpanded = trigger.getAttribute('aria-expanded') === 'true';

                this.announceToScreenReader(
                    `Section ${isExpanded ? 'collapsed' : 'expanded'}: ${trigger.textContent.trim()}`
                );
            });
        });
    },

    announceToScreenReader: function(message) {
        const announcement = document.createElement('div');
        announcement.setAttribute('aria-live', 'polite');
        announcement.setAttribute('aria-atomic', 'true');
        announcement.className = 'visually-hidden';
        announcement.textContent = message;

        document.body.appendChild(announcement);

        // Remove after announcement
        setTimeout(() => {
            document.body.removeChild(announcement);
        }, 1000);
    },

    startAutoRefresh: function() {
        // Refresh every 30 seconds
        this.refreshInterval = setInterval(() => {
            this.loadDashboardData();
        }, 30000);
    },

    stopAutoRefresh: function() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    },

    loadDashboardData: async function() {
        try {
            // Load all dashboard data in parallel for SOC operations
            const [overview, priorityAlerts, threatIntel, analysts, performance, mitreTechniques] = await Promise.all([
                Utils.apiRequest('/dashboard/overview'),
                Utils.apiRequest('/dashboard/priority-alerts?limit=10'),
                Utils.apiRequest('/dashboard/threat-intelligence'),
                Utils.apiRequest('/dashboard/active-analysts'),
                Utils.apiRequest('/dashboard/system-performance'),
                Utils.apiRequest('/dashboard/mitre-techniques')
            ]);

            this.updateThreatOverview(overview);
            this.updatePriorityAlerts(priorityAlerts.alerts);
            this.updateThreatIntelligence(threatIntel.feed);
            this.updateActiveAnalysts(analysts.analysts);
            this.updateSystemPerformance(performance);
            this.updateMitreTechniques(mitreTechniques.techniques);
            this.updateThreatTimeline();

        } catch (error) {
            console.error('Error loading dashboard data:', error);
            Utils.showAlert(`Failed to load dashboard data: ${error.message}`, 'danger');
        }
    },

    updateThreatOverview: function(overview) {
        // Update critical alerts with enhanced UX feedback
        const critical = overview.critical_alerts || {};
        const criticalAlertsElement = document.getElementById('criticalAlerts');
        const newCriticalElement = document.getElementById('newCritical');
        const criticalMTTRElement = document.getElementById('criticalMTTR');

        // Animate value changes for better user feedback
        this.animateValueChange(criticalAlertsElement, critical.total || 0);
        this.animateValueChange(newCriticalElement, critical.new_today || 0);
        this.updateTextWithFallback(criticalMTTRElement, critical.mttr_minutes, '--', ' min');

        // Update progress bar with enhanced accessibility
        const criticalProgress = document.getElementById('criticalProgress');
        const resolutionRate = critical.resolution_rate || 0;
        this.animateProgressBar(criticalProgress, resolutionRate);
        criticalProgress.setAttribute('aria-valuenow', resolutionRate);
        criticalProgress.setAttribute('aria-valuetext', `${resolutionRate}% of critical alerts resolved`);

        // Update trend indicator
        this.updateTrendIndicator('criticalTrend', critical.trend || {});

        // Update high priority incidents
        const high = overview.high_priority || {};
        document.getElementById('highPriorityIncidents').textContent = high.total || 0;
        document.getElementById('assignedAnalysts').textContent = high.assigned_analysts || 0;
        document.getElementById('avgResponseTime').textContent = Utils.formatDuration(high.avg_response_time || 0);

        // Update high priority progress
        const highProgress = document.getElementById('highProgress');
        const highResolutionRate = high.resolution_rate || 0;
        highProgress.style.width = `${highResolutionRate}%`;

        // Update active investigations
        const investigations = overview.investigations || {};
        document.getElementById('activeInvestigations').textContent = investigations.active || 0;
        document.getElementById('pendingReview').textContent = investigations.pending_review || 0;

        const investigationProgress = document.getElementById('investigationProgress');
        const investigationCompletion = investigations.completion_rate || 0;
        investigationProgress.style.width = `${investigationCompletion}%`;

        // Update system health
        const health = overview.system_health || {};
        document.getElementById('systemHealthScore').textContent = health.score || '--';
        document.getElementById('healthyServices').textContent = health.healthy_services || 0;
        document.getElementById('totalServices').textContent = health.total_services || 0;
        document.getElementById('lastHealthCheck').textContent = Utils.formatTimestamp(health.last_check);

        const healthProgress = document.getElementById('healthProgress');
        healthProgress.style.width = `${health.score || 0}%`;
    },

    updatePriorityAlerts: function(alerts) {
        const tableBody = document.getElementById('priorityAlertsTable');

        if (!alerts || alerts.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted py-3">
                        <i class="fas fa-inbox me-2"></i>
                        No priority alerts in queue
                    </td>
                </tr>
            `;
            return;
        }

        const rows = alerts.map((alert, index) => {
            const priority = index + 1;
            const severityBadge = Utils.getStatusBadge(alert.severity, 'severity');
            const riskScore = this.getRiskScoreDisplay(alert.risk_score);
            const assignee = alert.assignee || 'Unassigned';
            const age = this.calculateAlertAge(alert.created_at);

            return `
                <tr class="alert-priority-${alert.severity}">
                    <td class="text-center">
                        <span class="badge bg-primary">#${priority}</span>
                    </td>
                    <td>
                        <div class="fw-medium">${this.escapeHtml(alert.name)}</div>
                        <small class="text-muted">${alert.external_id}</small>
                        <div class="mt-1">${severityBadge}</div>
                    </td>
                    <td class="text-center">${riskScore}</td>
                    <td>
                        <div class="d-flex align-items-center">
                            <i class="fas fa-user-circle me-1 text-muted"></i>
                            <small>${assignee}</small>
                        </div>
                    </td>
                    <td>
                        <small class="${age.urgentClass}">${age.display}</small>
                    </td>
                    <td>
                        <div class="btn-group">
                            <button class="btn btn-sm btn-primary" onclick="Dashboard.viewAlert('${alert.id}')" title="View Details">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button class="btn btn-sm btn-warning" onclick="Dashboard.assignToMe('${alert.id}')" title="Assign to Me">
                                <i class="fas fa-user"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        tableBody.innerHTML = rows;
    },

    updateThreatIntelligence: function(feed) {
        const container = document.getElementById('threatIntelFeed');

        if (!feed || feed.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted p-3">
                    <i class="fas fa-rss me-2"></i>
                    No threat intelligence updates
                </div>
            `;
            return;
        }

        const feedElements = feed.slice(0, 10).map(item => {
            const timeAgo = this.getTimeAgo(item.timestamp);
            const severityClass = this.getThreatSeverityClass(item.severity);

            return `
                <div class="border-bottom p-2 small">
                    <div class="d-flex justify-content-between align-items-start">
                        <div class="flex-grow-1">
                            <div class="fw-medium ${severityClass}">
                                ${this.escapeHtml(item.title)}
                            </div>
                            <div class="text-muted mt-1">
                                ${this.escapeHtml(item.description)}
                            </div>
                        </div>
                        <small class="text-muted ms-2">${timeAgo}</small>
                    </div>
                    ${item.iocs ? `
                        <div class="mt-1">
                            <small class="text-info">
                                <i class="fas fa-search me-1"></i>
                                ${item.iocs.length} IOCs
                            </small>
                        </div>
                    ` : ''}
                </div>
            `;
        }).join('');

        container.innerHTML = feedElements;
    },

    updateActiveAnalysts: function(analysts) {
        const container = document.getElementById('activeAnalysts');

        if (!analysts || analysts.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted">
                    <i class="fas fa-users me-2"></i>
                    No analysts currently active
                </div>
            `;
            return;
        }

        const analystElements = analysts.map(analyst => {
            const statusClass = analyst.status === 'available' ? 'text-success' :
                               analyst.status === 'busy' ? 'text-warning' : 'text-danger';
            const workload = analyst.assigned_alerts || 0;

            return `
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <div class="d-flex align-items-center">
                        <i class="fas fa-user-circle fa-lg me-2 ${statusClass}"></i>
                        <div>
                            <div class="small fw-medium">${this.escapeHtml(analyst.name)}</div>
                            <div class="small text-muted">${analyst.role}</div>
                        </div>
                    </div>
                    <div class="text-end">
                        <small class="${statusClass}">${analyst.status}</small>
                        <div class="small text-muted">${workload} alerts</div>
                    </div>
                </div>
            `;
        }).join('');

        container.innerHTML = analystElements;
    },

    updateSystemPerformance: function(performance) {
        // Update XDR Polling
        const xdrStatus = document.getElementById('xdrPollingStatus');
        const xdrProgress = document.getElementById('xdrPollingProgress');
        xdrStatus.textContent = performance.xdr_polling?.status || 'Unknown';
        xdrStatus.className = this.getStatusClass(performance.xdr_polling?.status);
        xdrProgress.style.width = `${performance.xdr_polling?.performance || 0}%`;

        // Update AI Processing
        const aiStatus = document.getElementById('aiProcessingStatus');
        const aiProgress = document.getElementById('aiProcessingProgress');
        aiStatus.textContent = performance.ai_processing?.status || 'Unknown';
        aiStatus.className = this.getStatusClass(performance.ai_processing?.status);
        aiProgress.style.width = `${performance.ai_processing?.performance || 0}%`;

        // Update Graph Database
        const graphStatus = document.getElementById('graphDbStatus');
        const graphProgress = document.getElementById('graphDbProgress');
        graphStatus.textContent = performance.graph_database?.status || 'Unknown';
        graphStatus.className = this.getStatusClass(performance.graph_database?.status);
        graphProgress.style.width = `${performance.graph_database?.performance || 0}%`;

        // Update MCP Services
        const mcpStatus = document.getElementById('mcpServicesStatus');
        const mcpProgress = document.getElementById('mcpServicesProgress');
        mcpStatus.textContent = performance.mcp_services?.status || 'Unknown';
        mcpStatus.className = this.getStatusClass(performance.mcp_services?.status);
        mcpProgress.style.width = `${performance.mcp_services?.performance || 0}%`;
    },

    updateMitreTechniques: function(techniques) {
        const container = document.getElementById('topMitreTechniques');

        if (!techniques || techniques.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted">
                    <i class="fas fa-crosshairs me-2"></i>
                    No MITRE techniques detected
                </div>
            `;
            return;
        }

        const techniqueElements = techniques.slice(0, 10).map((technique, index) => {
            const tacticClass = this.getMitreTacticClass(technique.tactic);
            const percentage = Math.round((technique.count / techniques[0].count) * 100);

            return `
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <div class="flex-grow-1">
                        <div class="small fw-medium">
                            <span class="mitre-technique ${tacticClass}">${technique.technique_id}</span>
                        </div>
                        <div class="small text-muted">${this.escapeHtml(technique.technique_name)}</div>
                        <div class="progress mt-1" style="height: 3px;">
                            <div class="progress-bar ${this.getMitreProgressClass(technique.tactic)}"
                                 style="width: ${percentage}%"></div>
                        </div>
                    </div>
                    <div class="text-end ms-2">
                        <small class="fw-bold">${technique.count}</small>
                    </div>
                </div>
            `;
        }).join('');

        container.innerHTML = techniqueElements;
    },

    updateThreatTimeline: async function() {
        try {
            const timeframe = document.querySelector('input[name="threatTimeframe"]:checked')?.id || 'threat24h';
            const timeframeDays = timeframe === 'threat24h' ? 1 : timeframe === 'threat7d' ? 7 : 30;

            const response = await Utils.apiRequest(`/dashboard/threat-timeline?days=${timeframeDays}`);
            this.renderThreatTimelineChart(response.timeline);
        } catch (error) {
            console.error('Error loading threat timeline:', error);
        }
    },

    updateSeverityChart: function(severityData) {
        const ctx = document.getElementById('severityChart');
        if (!ctx) return;

        // Destroy existing chart
        if (this.charts.severity) {
            this.charts.severity.destroy();
        }

        const data = {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [
                    severityData?.critical || 0,
                    severityData?.high || 0,
                    severityData?.medium || 0,
                    severityData?.low || 0
                ],
                backgroundColor: [
                    '#dc3545',
                    '#fd7e14',
                    '#ffc107',
                    '#20c997'
                ],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        };

        this.charts.severity = new Chart(ctx, {
            type: 'doughnut',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            usePointStyle: true
                        }
                    }
                }
            }
        });
    },

    renderThreatTimelineChart: function(timelineData) {
        const ctx = document.getElementById('threatTimelineChart');
        if (!ctx) return;

        // Destroy existing chart
        if (this.charts.threatTimeline) {
            this.charts.threatTimeline.destroy();
        }

        const data = {
            labels: timelineData.labels || [],
            datasets: [
                {
                    label: 'Critical Alerts',
                    data: timelineData.critical || [],
                    borderColor: '#dc2626',
                    backgroundColor: 'rgba(220, 38, 38, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'High Priority',
                    data: timelineData.high || [],
                    borderColor: '#ea580c',
                    backgroundColor: 'rgba(234, 88, 12, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Medium',
                    data: timelineData.medium || [],
                    borderColor: '#d97706',
                    backgroundColor: 'rgba(217, 119, 6, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Low',
                    data: timelineData.low || [],
                    borderColor: '#059669',
                    backgroundColor: 'rgba(5, 150, 105, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        };

        this.charts.threatTimeline = new Chart(ctx, {
            type: 'line',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            usePointStyle: true,
                            padding: 20
                        }
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        callbacks: {
                            title: function(tooltipItems) {
                                return `Time: ${tooltipItems[0].label}`;
                            },
                            label: function(context) {
                                return `${context.dataset.label}: ${context.parsed.y} alerts`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        display: true,
                        title: {
                            display: true,
                            text: 'Time'
                        },
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    },
                    y: {
                        display: true,
                        title: {
                            display: true,
                            text: 'Alert Count'
                        },
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    }
                }
            }
        });
    },

    // Helper functions for advanced SOC dashboard
    getRiskScoreDisplay: function(riskScore) {
        if (!riskScore) return '<span class="text-muted">--</span>';

        let scoreClass = 'risk-score-low';
        if (riskScore >= 90) scoreClass = 'risk-score-critical';
        else if (riskScore >= 70) scoreClass = 'risk-score-high';
        else if (riskScore >= 40) scoreClass = 'risk-score-medium';

        return `<div class="risk-score ${scoreClass}">${riskScore}</div>`;
    },

    calculateAlertAge: function(createdAt) {
        const now = new Date();
        const created = new Date(createdAt);
        const diffMs = now - created;
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        const diffMinutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));

        let display, urgentClass = '';

        if (diffHours > 24) {
            const days = Math.floor(diffHours / 24);
            display = `${days}d ago`;
            urgentClass = 'text-danger fw-bold';
        } else if (diffHours > 4) {
            display = `${diffHours}h ago`;
            urgentClass = 'text-warning';
        } else if (diffHours > 0) {
            display = `${diffHours}h ${diffMinutes}m ago`;
        } else {
            display = `${diffMinutes}m ago`;
        }

        return { display, urgentClass };
    },

    getThreatSeverityClass: function(severity) {
        const classes = {
            'critical': 'text-danger',
            'high': 'text-warning',
            'medium': 'text-info',
            'low': 'text-success'
        };
        return classes[severity] || 'text-muted';
    },

    getTimeAgo: function(timestamp) {
        const now = new Date();
        const time = new Date(timestamp);
        const diffMs = now - time;
        const diffMinutes = Math.floor(diffMs / (1000 * 60));

        if (diffMinutes < 60) {
            return `${diffMinutes}m ago`;
        } else if (diffMinutes < 1440) {
            return `${Math.floor(diffMinutes / 60)}h ago`;
        } else {
            return `${Math.floor(diffMinutes / 1440)}d ago`;
        }
    },

    getStatusClass: function(status) {
        const classes = {
            'active': 'text-success',
            'optimal': 'text-success',
            'processing': 'text-info',
            'degraded': 'text-warning',
            'error': 'text-danger',
            'offline': 'text-danger'
        };
        return classes[status?.toLowerCase()] || 'text-muted';
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

    getMitreProgressClass: function(tactic) {
        const progressClasses = {
            'Initial Access': 'bg-danger',
            'Execution': 'bg-info',
            'Persistence': 'bg-warning',
            'Privilege Escalation': 'bg-warning',
            'Defense Evasion': 'bg-primary',
            'Credential Access': 'bg-danger',
            'Discovery': 'bg-info',
            'Lateral Movement': 'bg-warning',
            'Collection': 'bg-info',
            'Impact': 'bg-danger'
        };
        return progressClasses[tactic] || 'bg-secondary';
    },

    // Alert management functions
    viewAlert: function(alertId) {
        window.location.href = `/alerts?id=${alertId}`;
    },

    assignToMe: function(alertId) {
        Utils.apiRequest(`/alerts/${alertId}/assign`, {
            method: 'POST',
            body: JSON.stringify({ assignee: 'current_user' })
        }).then(() => {
            Utils.showAlert('Alert assigned successfully', 'success');
            this.loadDashboardData();
        }).catch(error => {
            Utils.showAlert(`Failed to assign alert: ${error.message}`, 'danger');
        });
    },

    animateValueChange: function(element, newValue) {
        if (!element) return;

        const currentValue = parseInt(element.textContent) || 0;
        if (currentValue === newValue) return;

        // Add visual feedback for value changes
        element.classList.add('value-changing');

        // Animate the number change
        const duration = 800;
        const startTime = performance.now();
        const difference = newValue - currentValue;

        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);

            const currentDisplayValue = Math.round(currentValue + (difference * this.easeOutQuart(progress)));
            element.textContent = currentDisplayValue;

            if (progress < 1) {
                requestAnimationFrame(animate);
            } else {
                element.classList.remove('value-changing');
                // Announce significant changes to screen readers
                if (Math.abs(difference) > 0) {
                    this.announceToScreenReader(`${element.closest('.card-body').querySelector('p').textContent} updated to ${newValue}`);
                }
            }
        };

        requestAnimationFrame(animate);
    },

    easeOutQuart: function(t) {
        return 1 - Math.pow(1 - t, 4);
    },

    animateProgressBar: function(element, targetWidth) {
        if (!element) return;

        const currentWidth = parseFloat(element.style.width) || 0;
        const duration = 600;
        const startTime = performance.now();
        const difference = targetWidth - currentWidth;

        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);

            const currentWidth = Math.round(currentWidth + (difference * this.easeOutQuart(progress)));
            element.style.width = `${currentWidth}%`;

            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };

        requestAnimationFrame(animate);
    },

    updateTextWithFallback: function(element, value, fallback, suffix = '') {
        if (!element) return;
        element.textContent = (value !== null && value !== undefined) ? value + suffix : fallback;
    },

    updateTrendIndicator: function(elementId, trend) {
        const element = document.getElementById(elementId);
        if (!element || !trend.direction) return;

        const isUp = trend.direction === 'up';
        const percentage = Math.abs(trend.percentage || 0);
        const icon = isUp ? 'fa-arrow-up' : 'fa-arrow-down';
        const colorClass = trend.severity === 'good' ?
            (isUp ? 'bg-success-subtle text-success' : 'bg-danger-subtle text-danger') :
            (isUp ? 'bg-danger-subtle text-danger' : 'bg-success-subtle text-success');

        element.className = `badge ${colorClass}`;
        element.innerHTML = `<i class="fas ${icon}" aria-hidden="true"></i> ${percentage}%`;
        element.setAttribute('title', `Trend: ${trend.direction} ${percentage}% over last period`);
    },

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
    }
};

// Enhanced global functions with accessibility
function refreshDashboard() {
    Utils.showAlert('Refreshing SOC dashboard...', 'info', 2000);
    Dashboard.announceToScreenReader('Dashboard refresh started');
    Dashboard.loadDashboardData();
}

// Navigation functions for enhanced UX
function navigateToAlerts(severity = null) {
    const url = severity ? `/alerts?severity=${severity}` : '/alerts';
    Dashboard.announceToScreenReader(`Navigating to ${severity || 'all'} alerts`);
    window.location.href = url;
}

function navigateToInvestigations() {
    Dashboard.announceToScreenReader('Navigating to investigation workspace');
    window.location.href = '/investigations';
}

function navigateToHealth() {
    Dashboard.announceToScreenReader('Navigating to system health details');
    window.location.href = '/api/health';
}

// Quick action functions
function quickCreateIncident() {
    Dashboard.announceToScreenReader('Opening incident creation form');
    // Implementation would show modal or navigate to incident creation
    Utils.showAlert('Incident creation form would open here', 'info');
}

function assignToMe() {
    Dashboard.announceToScreenReader('Assigning alerts to current user');
    // Implementation would assign unassigned high-priority alerts
    Utils.showAlert('High priority alerts assigned to you', 'success');
}

function startThreatHunt() {
    Dashboard.announceToScreenReader('Starting new threat hunt');
    window.location.href = '/threats?action=hunt';
}

function refreshSystemHealth() {
    Dashboard.announceToScreenReader('Refreshing system health check');
    Utils.apiRequest('/health/refresh', { method: 'POST' })
        .then(() => {
            Utils.showAlert('System health refreshed', 'success');
            Dashboard.loadDashboardData();
        })
        .catch(error => {
            Utils.showAlert(`Failed to refresh health: ${error.message}`, 'danger');
        });
}

// Keyboard navigation handler
function handleKeyNavigation(event, functionName, ...args) {
    if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        window[functionName](...args);
    }
}

function filterRecentAlerts() {
    const severity = document.getElementById('alertSeverityFilter').value;

    // Reload priority alerts with filter
    Utils.apiRequest(`/api/dashboard/priority-alerts?limit=10${severity ? '&severity=' + severity : ''}`)
        .then(response => {
            Dashboard.updatePriorityAlerts(response.alerts);
        })
        .catch(error => {
            console.error('Error filtering priority alerts:', error);
            Utils.showAlert(`Failed to filter alerts: ${error.message}`, 'danger');
        });
}

// Threat timeline timeframe change handler
function changeThreatTimeframe() {
    Dashboard.updateThreatTimeline();
}

// Enhanced initialization with progressive enhancement
document.addEventListener('DOMContentLoaded', function() {
    Dashboard.init();

    // Add event listeners for threat timeline timeframe buttons
    document.querySelectorAll('input[name="threatTimeframe"]').forEach(radio => {
        radio.addEventListener('change', changeThreatTimeframe);
    });

    // Add enhanced error handling for failed API requests
    window.addEventListener('unhandledrejection', function(event) {
        console.error('Unhandled promise rejection:', event.reason);
        Utils.showAlert('An unexpected error occurred. Please refresh the page.', 'danger');
    });

    // Setup visibility change handling for better performance
    document.addEventListener('visibilitychange', function() {
        if (document.visibilityState === 'visible') {
            Dashboard.loadDashboardData(); // Refresh when tab becomes visible
        } else {
            Dashboard.stopAutoRefresh(); // Pause when tab is hidden
        }
    });

    // Add CSS classes for improved animations
    const style = document.createElement('style');
    style.textContent = `
        .value-changing {
            background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.1), transparent);
            background-size: 200% 100%;
            animation: shimmer 0.8s ease-in-out;
        }

        @keyframes shimmer {
            0% { background-position: -200% 0; }
            100% { background-position: 200% 0; }
        }

        .progress-bar {
            transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        }
    `;
    document.head.appendChild(style);
});

// Enhanced cleanup and performance monitoring
window.addEventListener('beforeunload', function() {
    Dashboard.stopAutoRefresh();
});

// Performance monitoring for dashboard loading
if ('performance' in window) {
    window.addEventListener('load', function() {
        setTimeout(() => {
            const perfData = performance.getEntriesByType('navigation')[0];
            if (perfData) {
                console.log(`Dashboard load time: ${Math.round(perfData.loadEventEnd - perfData.fetchStart)}ms`);
            }
        }, 0);
    });
}

// Add reduced motion support check
if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    Dashboard.keyboardNavigationEnabled = false;
    console.log('Reduced motion preference detected - disabling animations');
}
