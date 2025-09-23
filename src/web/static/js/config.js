// Configuration management JavaScript functionality

const ConfigManager = {
    configurations: [],
    filters: {
        environment: '',
        status: '',
        pollEnabled: ''
    },

    init: function() {
        this.loadConfigurations();
        this.initializeFormHandlers();
    },

    loadConfigurations: async function() {
        try {
            Utils.setLoading('configurationsTable', true);

            // Build filter query string
            const params = new URLSearchParams();
            if (this.filters.environment) params.append('environment', this.filters.environment);
            if (this.filters.status) params.append('status', this.filters.status);
            if (this.filters.pollEnabled) params.append('poll_enabled', this.filters.pollEnabled);

            const queryString = params.toString();
            const endpoint = '/config/xdr' + (queryString ? '?' + queryString : '');

            const response = await Utils.apiRequest(endpoint);
            this.configurations = response;
            this.renderConfigurationsTable();

        } catch (error) {
            console.error('Error loading configurations:', error);
            Utils.showAlert(`Failed to load configurations: ${error.message}`, 'danger');
            this.renderConfigurationsError(error.message);
        } finally {
            Utils.setLoading('configurationsTable', false);
        }
    },

    renderConfigurationsTable: function() {
        const tableBody = document.getElementById('configurationsTable');

        if (!this.configurations || this.configurations.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="7" class="text-center text-muted">
                        <i class="fas fa-inbox me-2"></i>
                        No configurations found
                    </td>
                </tr>
            `;
            return;
        }

        const rows = this.configurations.map(config => {
            const statusBadge = Utils.getStatusBadge(config.status, 'status');
            const pollBadge = config.poll_enabled ?
                '<span class="badge bg-success">Enabled</span>' :
                '<span class="badge bg-secondary">Disabled</span>';
            const lastPoll = config.last_poll_at ?
                Utils.formatTimestamp(config.last_poll_at) :
                '<span class="text-muted">Never</span>';

            return `
                <tr>
                    <td>
                        <div class="fw-medium">${this.escapeHtml(config.name)}</div>
                        ${config.description ? `<small class="text-muted">${this.escapeHtml(config.description)}</small>` : ''}
                    </td>
                    <td>
                        <span class="badge bg-info">${config.environment}</span>
                    </td>
                    <td>
                        <small>${this.escapeHtml(config.base_url)}</small>
                    </td>
                    <td>
                        ${pollBadge}
                        ${config.poll_enabled ? `<br><small class="text-muted">${config.poll_interval}s interval</small>` : ''}
                    </td>
                    <td>${statusBadge}</td>
                    <td>${lastPoll}</td>
                    <td>
                        <div class="btn-group btn-group-sm" role="group">
                            <button class="btn btn-outline-primary" onclick="ConfigManager.editConfiguration('${config.id}')" title="Edit">
                                <i class="fas fa-edit"></i>
                            </button>
                            ${config.status === 'active' && !config.poll_enabled ?
                                `<button class="btn btn-outline-success" onclick="ConfigManager.startPolling('${config.id}')" title="Start Polling">
                                    <i class="fas fa-play"></i>
                                </button>` : ''
                            }
                            ${config.poll_enabled ?
                                `<button class="btn btn-outline-warning" onclick="ConfigManager.stopPolling('${config.id}')" title="Stop Polling">
                                    <i class="fas fa-stop"></i>
                                </button>` : ''
                            }
                            <button class="btn btn-outline-info" onclick="ConfigManager.testConnection('${config.id}')" title="Test Connection">
                                <i class="fas fa-plug"></i>
                            </button>
                            <button class="btn btn-outline-danger" onclick="ConfigManager.deleteConfiguration('${config.id}')" title="Delete">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        tableBody.innerHTML = rows;
    },

    renderConfigurationsError: function(errorMessage) {
        const tableBody = document.getElementById('configurationsTable');
        tableBody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center text-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    Error loading configurations: ${this.escapeHtml(errorMessage)}
                </td>
            </tr>
        `;
    },

    initializeFormHandlers: function() {
        // New configuration form
        const newConfigForm = document.getElementById('newConfigForm');
        if (newConfigForm) {
            newConfigForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.createConfiguration();
            });
        }

        // Edit configuration form
        const editConfigForm = document.getElementById('editConfigForm');
        if (editConfigForm) {
            editConfigForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.updateConfiguration();
            });
        }
    },

    createConfiguration: async function() {
        try {
            const form = document.getElementById('newConfigForm');
            const formData = new FormData(form);

            // Build configuration object
            const configData = {
                name: formData.get('name'),
                description: formData.get('description'),
                base_url: formData.get('base_url'),
                auth_token_secret_name: formData.get('auth_token_secret_name'),
                poll_interval: parseInt(formData.get('poll_interval')) || 30,
                max_alerts_per_poll: parseInt(formData.get('max_alerts_per_poll')) || 100,
                poll_enabled: formData.has('poll_enabled'),
                environment: formData.get('environment'),
                entity_types: {
                    fetch_assets: formData.has('fetch_assets'),
                    fetch_events: formData.has('fetch_events'),
                    fetch_intel: formData.has('fetch_intel'),
                    fetch_endpoint_data: formData.has('fetch_endpoint_data')
                }
            };

            // Build severity filter
            const severityFilter = [];
            if (formData.has('severity_low')) severityFilter.push('low');
            if (formData.has('severity_medium')) severityFilter.push('medium');
            if (formData.has('severity_high')) severityFilter.push('high');
            if (formData.has('severity_critical')) severityFilter.push('critical');

            if (severityFilter.length > 0) {
                configData.severity_filter = severityFilter;
            }

            // Create configuration
            await Utils.apiRequest('/config/xdr', {
                method: 'POST',
                body: JSON.stringify(configData)
            });

            Utils.showAlert('Configuration created successfully', 'success');

            // Close modal and refresh table
            const modal = bootstrap.Modal.getInstance(document.getElementById('newConfigModal'));
            modal.hide();
            form.reset();

            this.loadConfigurations();

        } catch (error) {
            console.error('Error creating configuration:', error);
            Utils.showAlert(`Failed to create configuration: ${error.message}`, 'danger');
        }
    },

    editConfiguration: function(configId) {
        // TODO: Implement edit functionality
        // For now, show a placeholder
        Utils.showAlert('Configuration editing will be implemented in the next iteration', 'info');
    },

    updateConfiguration: async function() {
        // TODO: Implement update functionality
        Utils.showAlert('Configuration update will be implemented in the next iteration', 'info');
    },

    deleteConfiguration: async function(configId) {
        if (!confirm('Are you sure you want to delete this configuration? This action cannot be undone.')) {
            return;
        }

        try {
            await Utils.apiRequest(`/config/xdr/${configId}`, {
                method: 'DELETE'
            });

            Utils.showAlert('Configuration deleted successfully', 'success');
            this.loadConfigurations();

        } catch (error) {
            console.error('Error deleting configuration:', error);
            Utils.showAlert(`Failed to delete configuration: ${error.message}`, 'danger');
        }
    },

    startPolling: async function(configId) {
        try {
            await Utils.apiRequest(`/config/xdr/${configId}/start-polling`, {
                method: 'POST'
            });

            Utils.showAlert('Polling started successfully', 'success');
            this.loadConfigurations();

        } catch (error) {
            console.error('Error starting polling:', error);
            Utils.showAlert(`Failed to start polling: ${error.message}`, 'danger');
        }
    },

    stopPolling: async function(configId) {
        if (!confirm('Are you sure you want to stop polling for this configuration?')) {
            return;
        }

        try {
            await Utils.apiRequest(`/config/xdr/${configId}/stop-polling`, {
                method: 'POST'
            });

            Utils.showAlert('Polling stopped successfully', 'success');
            this.loadConfigurations();

        } catch (error) {
            console.error('Error stopping polling:', error);
            Utils.showAlert(`Failed to stop polling: ${error.message}`, 'danger');
        }
    },

    testConnection: async function(configId) {
        try {
            Utils.showAlert('Testing connection...', 'info', 2000);

            const result = await Utils.apiRequest('/config/test-connection', {
                method: 'POST',
                body: JSON.stringify({ configuration_id: configId })
            });

            if (result.connection_status === 'success') {
                Utils.showAlert(
                    `Connection successful! Response time: ${result.response_time_ms}ms`,
                    'success'
                );
            } else {
                Utils.showAlert(
                    `Connection failed: ${result.error_message}`,
                    'danger'
                );
            }

        } catch (error) {
            console.error('Error testing connection:', error);
            Utils.showAlert(`Connection test failed: ${error.message}`, 'danger');
        }
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
        return text.toString().replace(/[&<>"']/g, function(m) { return map[m]; });
    }
};

// Global functions
function filterConfigurations() {
    // Update filters from form inputs
    ConfigManager.filters.environment = document.getElementById('environmentFilter').value;
    ConfigManager.filters.status = document.getElementById('statusFilter').value;
    ConfigManager.filters.pollEnabled = document.getElementById('pollEnabledFilter').value;

    // Reload configurations with new filters
    ConfigManager.loadConfigurations();
}

function refreshConfigurations() {
    Utils.showAlert('Refreshing configurations...', 'info', 2000);
    ConfigManager.loadConfigurations();
}

function testConnection() {
    // Test connection for new configuration form
    const baseUrl = document.getElementById('configBaseUrl').value;
    const secretName = document.getElementById('configAuthSecret').value;

    if (!baseUrl || !secretName) {
        Utils.showAlert('Please enter Base URL and Auth Secret Name first', 'warning');
        return;
    }

    // TODO: Implement test connection for new configuration
    Utils.showAlert('Connection test for new configurations will be implemented in the next iteration', 'info');
}

// Initialize configuration manager when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    ConfigManager.init();
});
