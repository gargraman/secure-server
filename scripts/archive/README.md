# Archived Deployment Scripts

This folder contains deployment scripts that were previously used but are no longer needed for the simplified development/testing deployment model.

## Archived Scripts

- `deploy_gcp.sh` - Complex unified deployment system with multiple modes
- `deploy_minimal_gcp.sh` - Minimal infrastructure deployment variant
- `deploy_simple_gcp.sh` - Simple deployment variant
- `deploy_to_gcp_restricted.sh` - SSH tunneling deployment mode
- `deploy_with_startup.sh` - Deployment with startup script automation
- `manage_gcp.sh` - Complex management operations script
- `README_MINIMIZED.md` - Documentation for the complex deployment system

## Current Active Scripts

The following scripts in the parent directory are the only ones needed for development:

- `deploy_to_gcp.sh` - Simple GCP VM deployment
- `cleanup_gcp.sh` - Resource cleanup
- `common.sh` - Common utility functions

These archived scripts can be restored if more complex deployment scenarios are needed in the future.
