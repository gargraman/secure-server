# Minimized Deployment Scripts

This directory contains the new minimized and consolidated deployment scripts that replace the previous redundant scripts.

## New Structure

### Core Scripts
- **`common.sh`** - Shared functions and configuration used by all scripts
- **`deploy_gcp.sh`** - Unified deployment script with multiple modes
- **`manage_gcp.sh`** - Management operations (cleanup, status, restart, etc.)

### Deployment Modes
The `deploy_gcp.sh` script supports multiple deployment modes:

```bash
# Standard deployment with full firewall access
./scripts/deploy_gcp.sh --standard

# Restricted deployment using SSH tunneling
./scripts/deploy_gcp.sh --restricted

# Minimal infrastructure only
./scripts/deploy_gcp.sh --minimal

# Everything via startup script (no SSH required)
./scripts/deploy_gcp.sh --startup-only
```

### Management Operations
```bash
# Check deployment status
./scripts/manage_gcp.sh status

# Clean up all resources
./scripts/manage_gcp.sh cleanup --force

# Restart VM and services
./scripts/manage_gcp.sh restart

# Create SSH tunnels
./scripts/manage_gcp.sh tunnel

# Connect to VM
./scripts/manage_gcp.sh connect

# View logs
./scripts/manage_gcp.sh logs
```

## Replaced Scripts

The following scripts have been consolidated into the new structure:

### Removed (Redundant):
- `deploy_to_gcp.sh` → Use `deploy_gcp.sh --standard`
- `deploy_to_gcp_restricted.sh` → Use `deploy_gcp.sh --restricted`
- `deploy_simple_gcp.sh` → Use `manage_gcp.sh status` + manual steps
- `deploy_minimal_gcp.sh` → Use `deploy_gcp.sh --minimal`
- `deploy_with_startup.sh` → Use `deploy_gcp.sh --startup-only`
- `cleanup_gcp.sh` → Use `manage_gcp.sh cleanup`

### File Consolidation:
The old scripts contained ~1,500 lines of mostly duplicate code. The new structure reduces this to ~400 lines with shared functions, eliminating 75% redundancy.


## Benefits

1. **Reduced Complexity**: Single unified script instead of 5 separate ones
2. **DRY Principle**: Shared functions eliminate code duplication
3. **Better Maintainability**: Changes only need to be made in one place
4. **Consistent Interface**: Same command-line options across all modes
5. **Easier Testing**: Single script to test different deployment scenarios

## Migration Guide

### Before:
```bash
# Multiple scripts with different interfaces
./scripts/deploy_to_gcp.sh
./scripts/deploy_to_gcp_restricted.sh
./scripts/cleanup_gcp.sh --force
```

### After:
```bash
# Single unified interface
./scripts/deploy_gcp.sh --standard
./scripts/deploy_gcp.sh --restricted
./scripts/manage_gcp.sh cleanup --force
```

## Usage Examples

```bash
# Quick minimal deployment
./scripts/deploy_gcp.sh --minimal --force

# Full deployment with custom project
./scripts/deploy_gcp.sh --standard --project my-project-id

# Check what's currently deployed
./scripts/manage_gcp.sh status

# Clean up everything including secrets
./scripts/manage_gcp.sh cleanup --delete-secrets --force
```
