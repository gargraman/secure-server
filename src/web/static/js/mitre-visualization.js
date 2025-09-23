/**
 * Enhanced MITRE ATT&CK Visualization Component
 * Provides interactive visualization of attack techniques with improved UX
 */

const MITREVisualization = {
    // MITRE ATT&CK Framework Data
    tactics: {
        'TA0001': { name: 'Initial Access', color: '#ff6b6b', priority: 5 },
        'TA0002': { name: 'Execution', color: '#4ecdc4', priority: 4 },
        'TA0003': { name: 'Persistence', color: '#45b7d1', priority: 3 },
        'TA0004': { name: 'Privilege Escalation', color: '#f7b731', priority: 5 },
        'TA0005': { name: 'Defense Evasion', color: '#5f27cd', priority: 4 },
        'TA0006': { name: 'Credential Access', color: '#ff9ff3', priority: 5 },
        'TA0007': { name: 'Discovery', color: '#54a0ff', priority: 2 },
        'TA0008': { name: 'Lateral Movement', color: '#5f27cd', priority: 4 },
        'TA0009': { name: 'Collection', color: '#00d2d3', priority: 3 },
        'TA0010': { name: 'Exfiltration', color: '#ff6348', priority: 5 },
        'TA0011': { name: 'Command and Control', color: '#ff3838', priority: 5 },
        'TA0040': { name: 'Impact', color: '#ff6348', priority: 5 }
    },

    // Common techniques with enhanced metadata
    techniques: {
        'T1078': { name: 'Valid Accounts', tactic: 'TA0001', description: 'Use of legitimate credentials' },
        'T1059': { name: 'Command and Scripting Interpreter', tactic: 'TA0002', description: 'Execute commands via interpreters' },
        'T1547': { name: 'Boot or Logon Autostart Execution', tactic: 'TA0003', description: 'Maintain persistence through autostart' },
        'T1068': { name: 'Exploitation for Privilege Escalation', tactic: 'TA0004', description: 'Exploit vulnerabilities for higher privileges' },
        'T1055': { name: 'Process Injection', tactic: 'TA0005', description: 'Inject code into running processes' },
        'T1003': { name: 'OS Credential Dumping', tactic: 'TA0006', description: 'Extract credentials from operating system' },
        'T1018': { name: 'Remote System Discovery', tactic: 'TA0007', description: 'Discover remote systems on network' },
        'T1021': { name: 'Remote Services', tactic: 'TA0008', description: 'Use remote services for lateral movement' },
        'T1005': { name: 'Data from Local System', tactic: 'TA0009', description: 'Collect data from local system' },
        'T1041': { name: 'Exfiltration Over C2 Channel', tactic: 'TA0010', description: 'Exfiltrate data over command and control channel' },
        'T1071': { name: 'Application Layer Protocol', tactic: 'TA0011', description: 'Communicate using application layer protocols' },
        'T1486': { name: 'Data Encrypted for Impact', tactic: 'TA0040', description: 'Encrypt data to impact availability' }
    },

    activeAlerts: [],
    selectedTechniques: new Set(),

    /**
     * Initialize MITRE visualization component
     */
    init: function() {
        this.setupEventListeners();
        this.loadAlertTechniques();
    },

    /**
     * Setup event listeners for interactive features
     */
    setupEventListeners: function() {
        // Technique selection handling
        document.addEventListener('click', (event) => {
            if (event.target.classList.contains('mitre-technique')) {
                this.handleTechniqueClick(event.target);
            }
        });

        // Keyboard navigation for accessibility
        document.addEventListener('keydown', (event) => {
            if (event.target.classList.contains('mitre-technique') &&
                (event.key === 'Enter' || event.key === ' ')) {
                event.preventDefault();
                this.handleTechniqueClick(event.target);
            }
        });
    },

    /**
     * Load techniques from current alerts
     */
    loadAlertTechniques: async function() {
        try {
            const response = await Utils.apiRequest('/alerts/mitre-techniques');
            this.activeAlerts = response.techniques || [];
            this.renderTechniqueMatrix();
            this.updateTechniqueSummary();
        } catch (error) {
            console.error('Error loading MITRE techniques:', error);
        }
    },

    /**
     * Render interactive MITRE technique matrix
     */
    renderTechniqueMatrix: function() {
        const container = document.getElementById('mitreMatrix');
        if (!container) return;

        // Create tactic columns
        const tactics = Object.keys(this.tactics);
        const matrixHTML = `
            <div class="mitre-matrix-container" role="grid" aria-label="MITRE ATT&CK Technique Matrix">
                <div class="mitre-tactics-header">
                    ${tactics.map(tacticId => this.renderTacticHeader(tacticId)).join('')}
                </div>
                <div class="mitre-techniques-grid">
                    ${tactics.map(tacticId => this.renderTacticColumn(tacticId)).join('')}
                </div>
            </div>
        `;

        container.innerHTML = matrixHTML;
        this.addMatrixInteractivity();
    },

    /**
     * Render tactic header with priority indication
     */
    renderTacticHeader: function(tacticId) {
        const tactic = this.tactics[tacticId];
        const alertCount = this.getAlertCountForTactic(tacticId);
        const priorityClass = this.getPriorityClass(tactic.priority);

        return `
            <div class="mitre-tactic-header ${priorityClass}"
                 style="border-top-color: ${tactic.color}"
                 role="columnheader"
                 tabindex="0"
                 aria-label="${tactic.name} - ${alertCount} alerts">
                <div class="tactic-name">${tactic.name}</div>
                <div class="tactic-id">${tacticId}</div>
                ${alertCount > 0 ? `
                    <div class="alert-count-badge" aria-label="${alertCount} active alerts">
                        ${alertCount}
                    </div>
                ` : ''}
                <div class="priority-indicator"
                     title="Priority Level: ${tactic.priority}/5"
                     aria-label="Priority ${tactic.priority} out of 5">
                    ${'★'.repeat(tactic.priority)}${'☆'.repeat(5 - tactic.priority)}
                </div>
            </div>
        `;
    },

    /**
     * Render tactic column with techniques
     */
    renderTacticColumn: function(tacticId) {
        const techniques = this.getTechniquesForTactic(tacticId);

        return `
            <div class="mitre-tactic-column" data-tactic="${tacticId}" role="gridcell">
                ${techniques.map(technique => this.renderTechnique(technique)).join('')}
            </div>
        `;
    },

    /**
     * Render individual technique with enhanced UX
     */
    renderTechnique: function(technique) {
        const isActive = this.isActiveTechnique(technique.id);
        const alertCount = this.getAlertCountForTechnique(technique.id);
        const tactic = this.tactics[technique.tactic];
        const riskLevel = this.calculateTechniqueRisk(technique.id);

        return `
            <div class="mitre-technique ${isActive ? 'active' : ''} risk-${riskLevel}"
                 data-technique="${technique.id}"
                 data-tactic="${technique.tactic}"
                 style="border-left-color: ${tactic.color}"
                 role="button"
                 tabindex="0"
                 aria-label="${technique.name} (${technique.id}) - ${alertCount} alerts, risk level ${riskLevel}"
                 title="${technique.description}">

                <div class="technique-header">
                    <div class="technique-id">${technique.id}</div>
                    ${alertCount > 0 ? `
                        <div class="technique-alert-count" aria-hidden="true">${alertCount}</div>
                    ` : ''}
                </div>

                <div class="technique-name">${technique.name}</div>

                ${isActive ? `
                    <div class="technique-indicators">
                        <div class="risk-indicator risk-${riskLevel}"
                             title="Risk Level: ${riskLevel.toUpperCase()}"
                             aria-label="Risk level ${riskLevel}">
                        </div>
                        <div class="activity-pulse" aria-hidden="true"></div>
                    </div>
                ` : ''}

                <div class="technique-details" aria-hidden="true">
                    <small class="text-muted">${technique.description}</small>
                </div>
            </div>
        `;
    },

    /**
     * Handle technique click for detailed view
     */
    handleTechniqueClick: function(element) {
        const techniqueId = element.dataset.technique;
        const tacticId = element.dataset.tactic;

        // Toggle selection
        if (this.selectedTechniques.has(techniqueId)) {
            this.selectedTechniques.delete(techniqueId);
            element.classList.remove('selected');
        } else {
            this.selectedTechniques.add(techniqueId);
            element.classList.add('selected');
        }

        // Update selection count
        this.updateSelectionCount();

        // Show technique details
        this.showTechniqueDetails(techniqueId);

        // Announce to screen readers
        const technique = this.techniques[techniqueId];
        const action = element.classList.contains('selected') ? 'selected' : 'deselected';
        this.announceToScreenReader(`${technique.name} ${action}`);
    },

    /**
     * Show detailed technique information
     */
    showTechniqueDetails: function(techniqueId) {
        const technique = this.techniques[techniqueId];
        const tactic = this.tactics[technique.tactic];
        const alerts = this.getAlertsForTechnique(techniqueId);

        const modal = this.createTechniqueModal(technique, tactic, alerts);
        document.body.appendChild(modal);

        // Initialize modal
        const bootstrapModal = new bootstrap.Modal(modal);
        bootstrapModal.show();

        // Cleanup on close
        modal.addEventListener('hidden.bs.modal', () => {
            document.body.removeChild(modal);
        });
    },

    /**
     * Create technique detail modal
     */
    createTechniqueModal: function(technique, tactic, alerts) {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.tabIndex = -1;
        modal.setAttribute('aria-labelledby', 'techniqueModalLabel');
        modal.setAttribute('aria-hidden', 'true');

        modal.innerHTML = `
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="techniqueModalLabel">
                            <span class="mitre-technique ${this.getMitreTacticClass(tactic.name)}">${technique.id}</span>
                            ${technique.name}
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row">
                            <div class="col-md-8">
                                <div class="technique-info">
                                    <h6>Description</h6>
                                    <p>${technique.description}</p>

                                    <h6>Tactic</h6>
                                    <span class="badge" style="background-color: ${tactic.color}">
                                        ${tactic.name}
                                    </span>

                                    <h6 class="mt-3">Risk Assessment</h6>
                                    <div class="risk-assessment">
                                        ${this.renderRiskAssessment(technique.id)}
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="alert-summary">
                                    <h6>Related Alerts</h6>
                                    <div class="alert-count">
                                        <span class="display-6">${alerts.length}</span>
                                        <small class="text-muted">active alerts</small>
                                    </div>
                                    ${alerts.length > 0 ? `
                                        <div class="recent-alerts mt-3">
                                            ${alerts.slice(0, 5).map(alert => `
                                                <div class="alert-item">
                                                    <div class="fw-medium">${this.escapeHtml(alert.name)}</div>
                                                    <small class="text-muted">${this.formatTimestamp(alert.created_at)}</small>
                                                </div>
                                            `).join('')}
                                        </div>
                                        ${alerts.length > 5 ? `
                                            <button class="btn btn-sm btn-outline-primary mt-2"
                                                    onclick="window.location.href='/alerts?technique=${technique.id}'">
                                                View All ${alerts.length} Alerts
                                            </button>
                                        ` : ''}
                                    ` : `
                                        <div class="text-muted text-center mt-3">
                                            <i class="fas fa-check-circle fa-2x mb-2"></i>
                                            <p>No active alerts for this technique</p>
                                        </div>
                                    `}
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <div class="btn-group">
                            <button type="button" class="btn btn-primary"
                                    onclick="window.location.href='/threats?technique=${technique.id}'">
                                Start Threat Hunt
                            </button>
                            <button type="button" class="btn btn-info"
                                    onclick="window.location.href='/mitre/${technique.id}'">
                                View Full Details
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        return modal;
    },

    /**
     * Render risk assessment for technique
     */
    renderRiskAssessment: function(techniqueId) {
        const riskLevel = this.calculateTechniqueRisk(techniqueId);
        const frequency = this.getTechniqueFrequency(techniqueId);
        const impact = this.getTechniqueImpact(techniqueId);

        return `
            <div class="risk-metrics">
                <div class="risk-metric">
                    <div class="metric-label">Overall Risk</div>
                    <div class="risk-score risk-${riskLevel}">${riskLevel.toUpperCase()}</div>
                </div>
                <div class="risk-metric">
                    <div class="metric-label">Frequency</div>
                    <div class="frequency-indicator">
                        <div class="frequency-bar">
                            <div class="frequency-fill" style="width: ${frequency}%"></div>
                        </div>
                        <small>${frequency}%</small>
                    </div>
                </div>
                <div class="risk-metric">
                    <div class="metric-label">Impact</div>
                    <div class="impact-indicator">
                        <div class="impact-stars">
                            ${'★'.repeat(impact)}${'☆'.repeat(5 - impact)}
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Add interactive features to matrix
     */
    addMatrixInteractivity: function() {
        // Hover effects for techniques
        document.querySelectorAll('.mitre-technique').forEach(technique => {
            technique.addEventListener('mouseenter', (e) => {
                this.highlightRelatedTechniques(e.target.dataset.technique);
            });

            technique.addEventListener('mouseleave', () => {
                this.clearHighlights();
            });
        });

        // Tactic column filtering
        document.querySelectorAll('.mitre-tactic-header').forEach(header => {
            header.addEventListener('click', (e) => {
                const tacticColumn = e.target.closest('.mitre-tactic-header');
                const tacticId = tacticColumn.parentNode.querySelector('[data-tactic]').dataset.tactic;
                this.toggleTacticFilter(tacticId);
            });
        });
    },

    /**
     * Highlight related techniques based on attack patterns
     */
    highlightRelatedTechniques: function(techniqueId) {
        // Clear existing highlights
        this.clearHighlights();

        // Highlight current technique
        const currentTechnique = document.querySelector(`[data-technique="${techniqueId}"]`);
        if (currentTechnique) {
            currentTechnique.classList.add('highlighted');
        }

        // Highlight related techniques in attack chain
        const relatedTechniques = this.getRelatedTechniques(techniqueId);
        relatedTechniques.forEach(relatedId => {
            const element = document.querySelector(`[data-technique="${relatedId}"]`);
            if (element) {
                element.classList.add('related-highlight');
            }
        });
    },

    /**
     * Clear all technique highlights
     */
    clearHighlights: function() {
        document.querySelectorAll('.mitre-technique').forEach(technique => {
            technique.classList.remove('highlighted', 'related-highlight');
        });
    },

    /**
     * Update technique summary statistics
     */
    updateTechniqueSummary: function() {
        const container = document.getElementById('techniqueSummary');
        if (!container) return;

        const activeTechniques = this.activeAlerts.length;
        const criticalTechniques = this.activeAlerts.filter(t => this.calculateTechniqueRisk(t.technique_id) === 'critical').length;
        const tacticsCovered = new Set(this.activeAlerts.map(t => t.tactic)).size;

        container.innerHTML = `
            <div class="technique-summary-cards">
                <div class="summary-card">
                    <div class="summary-number">${activeTechniques}</div>
                    <div class="summary-label">Active Techniques</div>
                </div>
                <div class="summary-card critical">
                    <div class="summary-number">${criticalTechniques}</div>
                    <div class="summary-label">Critical Risk</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">${tacticsCovered}</div>
                    <div class="summary-label">Tactics Covered</div>
                </div>
            </div>
        `;
    },

    // Helper functions
    getAlertCountForTactic: function(tacticId) {
        return this.activeAlerts.filter(alert => alert.tactic === tacticId).length;
    },

    getAlertCountForTechnique: function(techniqueId) {
        return this.activeAlerts.filter(alert => alert.technique_id === techniqueId).length;
    },

    getTechniquesForTactic: function(tacticId) {
        return Object.entries(this.techniques)
            .filter(([id, technique]) => technique.tactic === tacticId)
            .map(([id, technique]) => ({ ...technique, id }));
    },

    isActiveTechnique: function(techniqueId) {
        return this.activeAlerts.some(alert => alert.technique_id === techniqueId);
    },

    calculateTechniqueRisk: function(techniqueId) {
        const alertCount = this.getAlertCountForTechnique(techniqueId);
        const technique = this.techniques[techniqueId];
        const tactic = this.tactics[technique?.tactic];

        if (!tactic) return 'low';

        if (alertCount >= 3 && tactic.priority >= 4) return 'critical';
        if (alertCount >= 2 && tactic.priority >= 3) return 'high';
        if (alertCount >= 1) return 'medium';
        return 'low';
    },

    getTechniqueFrequency: function(techniqueId) {
        // Mock implementation - would calculate based on historical data
        return Math.random() * 100;
    },

    getTechniqueImpact: function(techniqueId) {
        const technique = this.techniques[techniqueId];
        const tactic = this.tactics[technique?.tactic];
        return tactic?.priority || 1;
    },

    getAlertsForTechnique: function(techniqueId) {
        return this.activeAlerts.filter(alert => alert.technique_id === techniqueId);
    },

    getRelatedTechniques: function(techniqueId) {
        // Mock implementation - would return techniques commonly seen together
        return [];
    },

    getPriorityClass: function(priority) {
        if (priority >= 5) return 'priority-critical';
        if (priority >= 4) return 'priority-high';
        if (priority >= 3) return 'priority-medium';
        return 'priority-low';
    },

    getMitreTacticClass: function(tacticName) {
        const classMap = {
            'Initial Access': 'mitre-initial-access',
            'Execution': 'mitre-execution',
            'Persistence': 'mitre-persistence',
            'Privilege Escalation': 'mitre-privilege-escalation',
            'Defense Evasion': 'mitre-defense-evasion',
            'Credential Access': 'mitre-credential-access',
            'Discovery': 'mitre-discovery',
            'Lateral Movement': 'mitre-lateral-movement',
            'Collection': 'mitre-collection',
            'Exfiltration': 'mitre-exfiltration',
            'Command and Control': 'mitre-command-control',
            'Impact': 'mitre-impact'
        };
        return classMap[tacticName] || 'mitre-technique';
    },

    updateSelectionCount: function() {
        const count = this.selectedTechniques.size;
        const counter = document.getElementById('selectedTechniquesCount');
        if (counter) {
            counter.textContent = count;
            counter.style.display = count > 0 ? 'inline' : 'none';
        }
    },

    announceToScreenReader: function(message) {
        const announcement = document.createElement('div');
        announcement.setAttribute('aria-live', 'polite');
        announcement.setAttribute('aria-atomic', 'true');
        announcement.className = 'visually-hidden';
        announcement.textContent = message;
        document.body.appendChild(announcement);
        setTimeout(() => document.body.removeChild(announcement), 1000);
    },

    escapeHtml: function(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    },

    formatTimestamp: function(timestamp) {
        return new Date(timestamp).toLocaleString();
    }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('mitreMatrix') || document.getElementById('topMitreTechniques')) {
        MITREVisualization.init();
    }
});

// Export for use in other modules
window.MITREVisualization = MITREVisualization;
