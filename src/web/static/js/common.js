// Common JavaScript utilities for AI-SOAR Platform

// Global configuration
const API_BASE_URL = '/api';
const REFRESH_INTERVAL = 30000; // 30 seconds

// Utility functions
const Utils = {
    // Show alert message
    showAlert: function(message, type = 'info', timeout = 5000) {
        const alertContainer = document.getElementById('alertContainer');
        const alertId = 'alert_' + Date.now();

        const alertHTML = `
            <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
                <i class="fas fa-${this.getAlertIcon(type)} me-2"></i>
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;

        alertContainer.insertAdjacentHTML('beforeend', alertHTML);

        // Auto dismiss
        if (timeout > 0) {
            setTimeout(() => {
                const alert = document.getElementById(alertId);
                if (alert) {
                    const bsAlert = new bootstrap.Alert(alert);
                    bsAlert.close();
                }
            }, timeout);
        }
    },

    getAlertIcon: function(type) {
        const icons = {
            'success': 'check-circle',
            'info': 'info-circle',
            'warning': 'exclamation-triangle',
            'danger': 'exclamation-circle'
        };
        return icons[type] || 'info-circle';
    },

    // Format timestamp
    formatTimestamp: function(timestamp) {
        if (!timestamp) return '--';
        const date = new Date(timestamp);
        return date.toLocaleString();
    },

    // Format duration
    formatDuration: function(seconds) {
        if (!seconds || seconds <= 0) return '--';

        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = Math.floor(seconds % 60);

        if (hours > 0) {
            return `${hours}h ${minutes}m ${secs}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${secs}s`;
        } else {
            return `${secs}s`;
        }
    },

    // Format bytes
    formatBytes: function(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';

        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];

        const i = Math.floor(Math.log(bytes) / Math.log(k));

        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    },

    // Get status badge HTML
    getStatusBadge: function(status, type = 'status') {
        const badges = {
            status: {
                'active': '<span class="badge bg-success">Active</span>',
                'inactive': '<span class="badge bg-secondary">Inactive</span>',
                'error': '<span class="badge bg-danger">Error</span>',
                'pending': '<span class="badge bg-warning text-dark">Pending</span>'
            },
            severity: {
                'critical': '<span class="badge severity-critical">Critical</span>',
                'high': '<span class="badge severity-high">High</span>',
                'medium': '<span class="badge severity-medium">Medium</span>',
                'low': '<span class="badge severity-low">Low</span>'
            },
            processing: {
                'completed': '<span class="badge bg-success">Completed</span>',
                'processing': '<span class="badge bg-primary">Processing</span>',
                'pending': '<span class="badge bg-secondary">Pending</span>',
                'failed': '<span class="badge bg-danger">Failed</span>'
            }
        };

        return badges[type]?.[status] || `<span class="badge bg-secondary">${status || 'Unknown'}</span>`;
    },

    // Get health indicator HTML
    getHealthIndicator: function(status) {
        const indicators = {
            'healthy': '<span class="health-indicator health-healthy"></span>Healthy',
            'unhealthy': '<span class="health-indicator health-unhealthy"></span>Unhealthy',
            'unknown': '<span class="health-indicator health-unknown"></span>Unknown'
        };

        return indicators[status] || indicators['unknown'];
    },

    // API request wrapper
    apiRequest: async function(endpoint, options = {}) {
        const url = API_BASE_URL + endpoint;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            }
        };

        const finalOptions = { ...defaultOptions, ...options };

        try {
            const response = await fetch(url, finalOptions);

            if (!response.ok) {
                let errorMessage = `HTTP Error ${response.status}`;
                try {
                    const errorData = await response.json();
                    errorMessage = errorData.detail || errorMessage;
                } catch (e) {
                    // Use default error message
                }
                throw new Error(errorMessage);
            }

            return await response.json();
        } catch (error) {
            console.error('API Request failed:', error);
            throw error;
        }
    },

    // Loading state management
    setLoading: function(element, loading = true) {
        if (typeof element === 'string') {
            element = document.getElementById(element);
        }

        if (!element) return;

        if (loading) {
            element.classList.add('loading');
            element.style.pointerEvents = 'none';
        } else {
            element.classList.remove('loading');
            element.style.pointerEvents = 'auto';
        }
    },

    // Debounce function
    debounce: function(func, wait, immediate) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                timeout = null;
                if (!immediate) func(...args);
            };
            const callNow = immediate && !timeout;
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
            if (callNow) func(...args);
        };
    }
};

// System status management
const SystemStatus = {
    checkInterval: null,

    start: function() {
        this.check();
        this.checkInterval = setInterval(() => this.check(), 60000); // Every minute
    },

    stop: function() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
        }
    },

    check: async function() {
        try {
            const status = await Utils.apiRequest('/health/detailed');
            this.updateDisplay(status);
        } catch (error) {
            console.error('System status check failed:', error);
            this.updateDisplay({ status: 'unhealthy', error: error.message });
        }
    },

    updateDisplay: function(status) {
        const statusElement = document.getElementById('systemStatus');
        if (!statusElement) return;

        const isHealthy = status.status === 'healthy';
        const statusText = isHealthy ? 'System Healthy' : 'System Issues';
        const statusClass = isHealthy ? 'text-success' : 'text-danger';

        statusElement.innerHTML = `<span class="${statusClass}">${statusText}</span>`;
        statusElement.title = `Last checked: ${new Date().toLocaleTimeString()}`;
    }
};

// Global functions
function loadSystemStatus() {
    SystemStatus.start();
}

// Initialize common functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
});

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    SystemStatus.stop();
});

// Export utilities to global scope
window.Utils = Utils;
window.SystemStatus = SystemStatus;
