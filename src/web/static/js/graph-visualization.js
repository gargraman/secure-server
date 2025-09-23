// Graph Visualization JavaScript Module using Cytoscape.js
const GraphVisualization = {
    instances: new Map(),

    // Initialize graph visualization
    init: function(containerId, options = {}) {
        const container = document.getElementById(containerId);
        if (!container) {
            console.error(`Graph container not found: ${containerId}`);
            return null;
        }

        const defaultOptions = {
            layout: { name: 'cose' },
            style: this.getDefaultStyle(),
            wheelSensitivity: 0.2,
            minZoom: 0.1,
            maxZoom: 3.0
        };

        const config = { ...defaultOptions, ...options };

        const cy = cytoscape({
            container: container,
            elements: [],
            style: config.style,
            layout: config.layout,
            wheelSensitivity: config.wheelSensitivity,
            minZoom: config.minZoom,
            maxZoom: config.maxZoom,
            boxSelectionEnabled: true,
            userZoomingEnabled: true,
            userPanningEnabled: true,
            autounselectify: false
        });

        // Store instance
        this.instances.set(containerId, cy);

        // Add event handlers
        this.addEventHandlers(cy, containerId);

        // Add controls
        this.addGraphControls(containerId, cy);

        // Add legend
        this.addGraphLegend(containerId);

        return cy;
    },

    // Get default Cytoscape style
    getDefaultStyle: function() {
        return [
            // Node styles
            {
                selector: 'node',
                style: {
                    'background-color': '#3182ce',
                    'border-width': 2,
                    'border-color': '#2c5aa0',
                    'label': 'data(label)',
                    'color': '#2d3748',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'font-size': '12px',
                    'font-weight': 'bold',
                    'text-wrap': 'wrap',
                    'text-max-width': '120px',
                    'width': 'mapData(importance, 1, 10, 20, 80)',
                    'height': 'mapData(importance, 1, 10, 20, 80)',
                    'overlay-padding': '6px',
                    'z-index': 10
                }
            },
            // Alert nodes
            {
                selector: 'node[type="alert"]',
                style: {
                    'background-color': '#e53e3e',
                    'border-color': '#c53030',
                    'shape': 'triangle'
                }
            },
            // Asset nodes
            {
                selector: 'node[type="asset"]',
                style: {
                    'background-color': '#38a169',
                    'border-color': '#2f855a',
                    'shape': 'rectangle'
                }
            },
            // User nodes
            {
                selector: 'node[type="user"]',
                style: {
                    'background-color': '#3182ce',
                    'border-color': '#2c5aa0',
                    'shape': 'ellipse'
                }
            },
            // Threat actor nodes
            {
                selector: 'node[type="threat_actor"]',
                style: {
                    'background-color': '#9f1239',
                    'border-color': '#881337',
                    'shape': 'diamond',
                    'width': 60,
                    'height': 60
                }
            },
            // Attack nodes (MITRE techniques)
            {
                selector: 'node[type="attack"]',
                style: {
                    'background-color': '#d69e2e',
                    'border-color': '#b7791f',
                    'shape': 'hexagon'
                }
            },
            // Intelligence context nodes
            {
                selector: 'node[type="intel_context"]',
                style: {
                    'background-color': '#805ad5',
                    'border-color': '#6b46c1',
                    'shape': 'octagon'
                }
            },
            // Severity-based styling
            {
                selector: 'node[severity="critical"]',
                style: {
                    'border-width': 4,
                    'border-color': '#e53e3e',
                    'background-color': '#fed7d7'
                }
            },
            {
                selector: 'node[severity="high"]',
                style: {
                    'border-width': 3,
                    'border-color': '#dd6b20',
                    'background-color': '#feebc8'
                }
            },
            // Edge styles
            {
                selector: 'edge',
                style: {
                    'width': 'mapData(weight, 1, 10, 2, 8)',
                    'line-color': '#a0aec0',
                    'target-arrow-color': '#a0aec0',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'arrow-scale': 1.2,
                    'label': 'data(relationship)',
                    'font-size': '10px',
                    'text-rotation': 'autorotate',
                    'text-margin-y': -10
                }
            },
            // Correlation edges
            {
                selector: 'edge[type="CORRELATED_TO"]',
                style: {
                    'line-color': '#4299e1',
                    'target-arrow-color': '#4299e1',
                    'line-style': 'dashed'
                }
            },
            // Attribution edges
            {
                selector: 'edge[type="ATTRIBUTED_TO"]',
                style: {
                    'line-color': '#e53e3e',
                    'target-arrow-color': '#e53e3e',
                    'width': 4
                }
            },
            // Progression edges
            {
                selector: 'edge[type="PROGRESSES_TO"]',
                style: {
                    'line-color': '#d69e2e',
                    'target-arrow-color': '#d69e2e',
                    'curve-style': 'straight'
                }
            },
            // Affects edges
            {
                selector: 'edge[type="AFFECTS"]',
                style: {
                    'line-color': '#38a169',
                    'target-arrow-color': '#38a169'
                }
            },
            // Highlighted elements
            {
                selector: '.highlighted',
                style: {
                    'border-width': 4,
                    'border-color': '#3182ce',
                    'z-index': 999
                }
            },
            {
                selector: 'edge.highlighted',
                style: {
                    'width': 6,
                    'line-color': '#3182ce',
                    'target-arrow-color': '#3182ce',
                    'z-index': 999
                }
            },
            // Selected elements
            {
                selector: ':selected',
                style: {
                    'border-width': 4,
                    'border-color': '#805ad5',
                    'z-index': 999
                }
            },
            // Faded elements
            {
                selector: '.faded',
                style: {
                    'opacity': 0.3,
                    'z-index': 1
                }
            }
        ];
    },

    // Add event handlers to graph
    addEventHandlers: function(cy, containerId) {
        let selectedNode = null;

        // Node selection
        cy.on('tap', 'node', (evt) => {
            const node = evt.target;
            this.selectNode(cy, node, containerId);
        });

        // Edge selection
        cy.on('tap', 'edge', (evt) => {
            const edge = evt.target;
            this.selectEdge(cy, edge, containerId);
        });

        // Background tap
        cy.on('tap', (evt) => {
            if (evt.target === cy) {
                this.clearSelection(cy, containerId);
            }
        });

        // Mouse hover effects
        cy.on('mouseover', 'node', (evt) => {
            const node = evt.target;
            const connectedEdges = node.connectedEdges();
            const connectedNodes = connectedEdges.connectedNodes();

            node.addClass('highlighted');
            connectedEdges.addClass('highlighted');
            connectedNodes.addClass('highlighted');
        });

        cy.on('mouseout', 'node', (evt) => {
            cy.elements().removeClass('highlighted');
        });

        // Double click to center
        cy.on('dblclick', 'node', (evt) => {
            const node = evt.target;
            cy.center(node);
            cy.fit(node, 100);
        });
    },

    // Select node and show details
    selectNode: function(cy, node, containerId) {
        cy.elements().removeClass('faded');
        cy.elements().removeClass('highlighted');

        const nodeData = node.data();
        this.showNodeDetails(nodeData, containerId);

        // Highlight connected elements
        const connectedEdges = node.connectedEdges();
        const connectedNodes = connectedEdges.connectedNodes();

        // Fade unconnected elements
        cy.elements().not(node).not(connectedEdges).not(connectedNodes).addClass('faded');

        // Highlight connected elements
        node.addClass('highlighted');
        connectedEdges.addClass('highlighted');
        connectedNodes.addClass('highlighted');
    },

    // Select edge and show details
    selectEdge: function(cy, edge, containerId) {
        cy.elements().removeClass('faded');
        cy.elements().removeClass('highlighted');

        const edgeData = edge.data();
        this.showEdgeDetails(edgeData, containerId);

        // Highlight edge and connected nodes
        const connectedNodes = edge.connectedNodes();

        cy.elements().not(edge).not(connectedNodes).addClass('faded');
        edge.addClass('highlighted');
        connectedNodes.addClass('highlighted');
    },

    // Clear selection
    clearSelection: function(cy, containerId) {
        cy.elements().removeClass('faded');
        cy.elements().removeClass('highlighted');
        this.hideInfoPanel(containerId);
    },

    // Show node details in info panel
    showNodeDetails: function(nodeData, containerId) {
        const infoPanel = document.querySelector(`#${containerId}`).parentElement.querySelector('.graph-info-panel');
        if (!infoPanel) return;

        const typeIcons = {
            'alert': 'fas fa-exclamation-triangle',
            'asset': 'fas fa-server',
            'user': 'fas fa-user',
            'threat_actor': 'fas fa-mask',
            'attack': 'fas fa-crosshairs',
            'intel_context': 'fas fa-brain'
        };

        const icon = typeIcons[nodeData.type] || 'fas fa-circle';

        infoPanel.innerHTML = `
            <div class="info-panel-header">
                <i class="${icon} me-2"></i>
                ${nodeData.label || nodeData.id}
            </div>
            <div class="info-panel-content">
                <div class="info-panel-section">
                    <div class="info-panel-label">Type</div>
                    <div class="info-panel-value">${nodeData.type || 'Unknown'}</div>
                </div>
                ${nodeData.severity ? `
                    <div class="info-panel-section">
                        <div class="info-panel-label">Severity</div>
                        <div class="info-panel-value">
                            <span class="badge severity-${nodeData.severity}">${nodeData.severity}</span>
                        </div>
                    </div>
                ` : ''}
                ${nodeData.risk_score ? `
                    <div class="info-panel-section">
                        <div class="info-panel-label">Risk Score</div>
                        <div class="info-panel-value">${nodeData.risk_score}</div>
                    </div>
                ` : ''}
                ${nodeData.description ? `
                    <div class="info-panel-section">
                        <div class="info-panel-label">Description</div>
                        <div class="info-panel-value">${nodeData.description}</div>
                    </div>
                ` : ''}
                ${nodeData.created_at ? `
                    <div class="info-panel-section">
                        <div class="info-panel-label">Created</div>
                        <div class="info-panel-value">${Utils.formatTimestamp(nodeData.created_at)}</div>
                    </div>
                ` : ''}
                <div class="info-panel-section">
                    <button class="btn btn-sm btn-primary" onclick="GraphVisualization.expandNode('${containerId}', '${nodeData.id}')">
                        <i class="fas fa-expand me-1"></i>Expand
                    </button>
                    <button class="btn btn-sm btn-outline-primary ms-2" onclick="GraphVisualization.investigateNode('${containerId}', '${nodeData.id}')">
                        <i class="fas fa-search me-1"></i>Investigate
                    </button>
                </div>
            </div>
        `;

        infoPanel.classList.add('show');
    },

    // Show edge details in info panel
    showEdgeDetails: function(edgeData, containerId) {
        const infoPanel = document.querySelector(`#${containerId}`).parentElement.querySelector('.graph-info-panel');
        if (!infoPanel) return;

        infoPanel.innerHTML = `
            <div class="info-panel-header">
                <i class="fas fa-link me-2"></i>
                Relationship
            </div>
            <div class="info-panel-content">
                <div class="info-panel-section">
                    <div class="info-panel-label">Type</div>
                    <div class="info-panel-value">${edgeData.type || 'Unknown'}</div>
                </div>
                ${edgeData.relationship ? `
                    <div class="info-panel-section">
                        <div class="info-panel-label">Relationship</div>
                        <div class="info-panel-value">${edgeData.relationship}</div>
                    </div>
                ` : ''}
                ${edgeData.confidence ? `
                    <div class="info-panel-section">
                        <div class="info-panel-label">Confidence</div>
                        <div class="info-panel-value">${(edgeData.confidence * 100).toFixed(1)}%</div>
                    </div>
                ` : ''}
                ${edgeData.weight ? `
                    <div class="info-panel-section">
                        <div class="info-panel-label">Weight</div>
                        <div class="info-panel-value">${edgeData.weight}</div>
                    </div>
                ` : ''}
            </div>
        `;

        infoPanel.classList.add('show');
    },

    // Hide info panel
    hideInfoPanel: function(containerId) {
        const infoPanel = document.querySelector(`#${containerId}`).parentElement.querySelector('.graph-info-panel');
        if (infoPanel) {
            infoPanel.classList.remove('show');
        }
    },

    // Add graph controls
    addGraphControls: function(containerId, cy) {
        const container = document.getElementById(containerId);

        const controlsHtml = `
            <div class="graph-controls">
                <button class="graph-control-btn" onclick="GraphVisualization.zoomIn('${containerId}')" title="Zoom In">
                    <i class="fas fa-plus"></i>
                </button>
                <button class="graph-control-btn" onclick="GraphVisualization.zoomOut('${containerId}')" title="Zoom Out">
                    <i class="fas fa-minus"></i>
                </button>
                <button class="graph-control-btn" onclick="GraphVisualization.fitToScreen('${containerId}')" title="Fit to Screen">
                    <i class="fas fa-expand-arrows-alt"></i>
                </button>
                <button class="graph-control-btn" onclick="GraphVisualization.centerGraph('${containerId}')" title="Center">
                    <i class="fas fa-crosshairs"></i>
                </button>
                <button class="graph-control-btn" onclick="GraphVisualization.toggleFullscreen('${containerId}')" title="Toggle Fullscreen">
                    <i class="fas fa-expand"></i>
                </button>
                <button class="graph-control-btn" onclick="GraphVisualization.exportGraph('${containerId}')" title="Export">
                    <i class="fas fa-download"></i>
                </button>
            </div>
            <div class="graph-search-container">
                <input type="text" class="graph-search-input" placeholder="Search nodes..."
                       onkeyup="GraphVisualization.searchNodes('${containerId}', this.value)">
                <select class="graph-filter-dropdown" onchange="GraphVisualization.filterNodes('${containerId}', this.value)">
                    <option value="">All Types</option>
                    <option value="alert">Alerts</option>
                    <option value="asset">Assets</option>
                    <option value="user">Users</option>
                    <option value="threat_actor">Threat Actors</option>
                    <option value="attack">Attacks</option>
                </select>
            </div>
            <div class="graph-info-panel">
                <!-- Dynamic content -->
            </div>
        `;

        container.insertAdjacentHTML('afterbegin', controlsHtml);
    },

    // Add graph legend
    addGraphLegend: function(containerId) {
        const container = document.getElementById(containerId);

        const legendHtml = `
            <div class="graph-legend">
                <div class="graph-legend-title">Legend</div>
                <div class="legend-item">
                    <div class="legend-color node-alert"></div>
                    <span>Security Alert</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color node-asset"></div>
                    <span>Asset/System</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color node-user"></div>
                    <span>User</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color node-threat-actor"></div>
                    <span>Threat Actor</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color node-attack"></div>
                    <span>Attack Technique</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color node-intel"></div>
                    <span>Intelligence</span>
                </div>
            </div>
            <div class="graph-stats-panel">
                <div class="graph-stats-item">
                    <span>Nodes:</span>
                    <span id="${containerId}-node-count">0</span>
                </div>
                <div class="graph-stats-item">
                    <span>Edges:</span>
                    <span id="${containerId}-edge-count">0</span>
                </div>
                <div class="graph-stats-item">
                    <span>Selected:</span>
                    <span id="${containerId}-selected-count">0</span>
                </div>
            </div>
        `;

        container.insertAdjacentHTML('beforeend', legendHtml);
    },

    // Load and render graph data
    loadGraph: function(containerId, data) {
        const cy = this.instances.get(containerId);
        if (!cy) return;

        // Show loading state
        this.showLoadingState(containerId);

        try {
            // Clear existing data
            cy.elements().remove();

            // Add nodes and edges
            if (data.elements) {
                cy.add(data.elements);
            } else {
                // Handle separate nodes and edges
                if (data.nodes) cy.add(data.nodes);
                if (data.edges) cy.add(data.edges);
            }

            // Apply layout
            const layout = cy.layout({
                name: 'cose',
                idealEdgeLength: 100,
                nodeOverlap: 20,
                refresh: 20,
                randomize: false,
                componentSpacing: 100,
                nodeRepulsion: 400000,
                edgeElasticity: 100,
                nestingFactor: 5,
                gravity: 80,
                numIter: 1000,
                initialTemp: 200,
                coolingFactor: 0.95,
                minTemp: 1.0
            });

            layout.run();

            // Update statistics
            this.updateGraphStats(containerId, cy);

            // Hide loading state
            this.hideLoadingState(containerId);

            // Fit to screen after layout completes
            layout.on('layoutstop', () => {
                cy.fit(null, 50);
            });

        } catch (error) {
            console.error('Error loading graph data:', error);
            this.hideLoadingState(containerId);
            this.showErrorState(containerId, error.message);
        }
    },

    // Control functions
    zoomIn: function(containerId) {
        const cy = this.instances.get(containerId);
        if (cy) cy.zoom(cy.zoom() * 1.25);
    },

    zoomOut: function(containerId) {
        const cy = this.instances.get(containerId);
        if (cy) cy.zoom(cy.zoom() * 0.8);
    },

    fitToScreen: function(containerId) {
        const cy = this.instances.get(containerId);
        if (cy) cy.fit(null, 50);
    },

    centerGraph: function(containerId) {
        const cy = this.instances.get(containerId);
        if (cy) cy.center();
    },

    toggleFullscreen: function(containerId) {
        const container = document.getElementById(containerId);
        container.classList.toggle('graph-fullscreen');

        // Update button icon
        const button = container.querySelector('.graph-control-btn:nth-child(5)');
        const icon = button.querySelector('i');
        if (container.classList.contains('graph-fullscreen')) {
            icon.className = 'fas fa-compress';
            button.title = 'Exit Fullscreen';
        } else {
            icon.className = 'fas fa-expand';
            button.title = 'Toggle Fullscreen';
        }

        // Resize graph
        const cy = this.instances.get(containerId);
        if (cy) {
            setTimeout(() => {
                cy.resize();
                cy.fit(null, 50);
            }, 300);
        }
    },

    exportGraph: function(containerId) {
        const cy = this.instances.get(containerId);
        if (!cy) return;

        const png64 = cy.png({ scale: 2, full: true });
        const link = document.createElement('a');
        link.download = `security-graph-${Date.now()}.png`;
        link.href = png64;
        link.click();
    },

    // Search and filter functions
    searchNodes: function(containerId, query) {
        const cy = this.instances.get(containerId);
        if (!cy) return;

        cy.elements().removeClass('highlighted').removeClass('faded');

        if (!query.trim()) return;

        const matchingNodes = cy.nodes().filter(node => {
            const data = node.data();
            return (data.label && data.label.toLowerCase().includes(query.toLowerCase())) ||
                   (data.id && data.id.toLowerCase().includes(query.toLowerCase())) ||
                   (data.description && data.description.toLowerCase().includes(query.toLowerCase()));
        });

        if (matchingNodes.length > 0) {
            cy.elements().not(matchingNodes).addClass('faded');
            matchingNodes.addClass('highlighted');
        }
    },

    filterNodes: function(containerId, type) {
        const cy = this.instances.get(containerId);
        if (!cy) return;

        cy.elements().removeClass('highlighted').removeClass('faded');

        if (!type) return;

        const matchingNodes = cy.nodes(`[type="${type}"]`);
        const relatedEdges = matchingNodes.connectedEdges();

        cy.elements().not(matchingNodes).not(relatedEdges).addClass('faded');
        matchingNodes.addClass('highlighted');
    },

    // Specialized graph renderers
    renderInvestigationGraph: function(containerId, data) {
        const cy = this.init(containerId, {
            layout: { name: 'dagre', rankDir: 'TB' }
        });

        this.loadGraph(containerId, data);
        return cy;
    },

    renderThreatCorrelationGraph: function(containerId, data) {
        const cy = this.init(containerId, {
            layout: { name: 'circle' }
        });

        this.loadGraph(containerId, data);
        return cy;
    },

    renderAttackChainGraph: function(containerId, data) {
        const cy = this.init(containerId, {
            layout: { name: 'breadthfirst', directed: true }
        });

        this.loadGraph(containerId, data);
        return cy;
    },

    // Helper functions
    showLoadingState: function(containerId) {
        const container = document.getElementById(containerId);
        const loadingHtml = `
            <div class="graph-loading">
                <div class="graph-loading-spinner"></div>
                <div class="graph-loading-text">Loading graph data...</div>
            </div>
        `;
        container.insertAdjacentHTML('beforeend', loadingHtml);
    },

    hideLoadingState: function(containerId) {
        const container = document.getElementById(containerId);
        const loading = container.querySelector('.graph-loading');
        if (loading) loading.remove();
    },

    showErrorState: function(containerId, message) {
        const container = document.getElementById(containerId);
        const errorHtml = `
            <div class="position-absolute top-50 start-50 translate-middle text-center">
                <i class="fas fa-exclamation-triangle fa-3x text-danger mb-3"></i>
                <h5>Error Loading Graph</h5>
                <p class="text-muted">${message}</p>
                <button class="btn btn-primary" onclick="location.reload()">
                    <i class="fas fa-refresh me-1"></i>Retry
                </button>
            </div>
        `;
        container.insertAdjacentHTML('beforeend', errorHtml);
    },

    updateGraphStats: function(containerId, cy) {
        const nodeCount = cy.nodes().length;
        const edgeCount = cy.edges().length;

        document.getElementById(`${containerId}-node-count`).textContent = nodeCount;
        document.getElementById(`${containerId}-edge-count`).textContent = edgeCount;
    },

    // Node expansion and investigation
    expandNode: async function(containerId, nodeId) {
        const cy = this.instances.get(containerId);
        if (!cy) return;

        try {
            const response = await Utils.apiRequest(`/api/graph/expand/${nodeId}`);

            // Add new nodes and edges
            cy.add(response.elements);

            // Update layout
            const layout = cy.layout({ name: 'cose' });
            layout.run();

            this.updateGraphStats(containerId, cy);

        } catch (error) {
            console.error('Error expanding node:', error);
            Utils.showAlert('Failed to expand node', 'danger');
        }
    },

    investigateNode: function(containerId, nodeId) {
        // Open investigation panel or redirect to detailed view
        window.location.href = `/investigations?node=${nodeId}`;
    },

    // Cleanup
    destroy: function(containerId) {
        const cy = this.instances.get(containerId);
        if (cy) {
            cy.destroy();
            this.instances.delete(containerId);
        }
    }
};

// Export to global scope
window.GraphVisualization = GraphVisualization;
