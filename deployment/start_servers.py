#!/usr/bin/env python3
"""
Container startup script for MCP servers
"""

import asyncio
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path


class ServerManager:
    def __init__(self):
        self.processes = []
        self.running = True

    def start_server(self, module_path, port, name):
        """Start a single MCP server"""
        print(f"Starting {name} server on port {port}...")

        try:
            # Set environment for each server
            env = os.environ.copy()
            env["PORT"] = str(port)
            env["SERVER_NAME"] = name

            process = subprocess.Popen(
                [sys.executable, "-m", module_path], env=env, cwd="/app"
            )

            self.processes.append((process, name, port))
            print(f"✓ {name} server started (PID: {process.pid})")
            return process

        except Exception as e:
            print(f"✗ Failed to start {name} server: {e}")
            return None

    def health_check(self):
        """Check if all servers are running"""
        import requests

        servers = [
            ("VirusTotal", 8001),
            ("ServiceNow", 8002),
            ("CyberReason", 8003),
            ("Cloud IVX", 8005),
        ]

        while self.running:
            for name, port in servers:
                try:
                    response = requests.get(f"http://localhost:{port}/meta", timeout=5)
                    if response.status_code != 200:
                        print(f"⚠ {name} server health check failed")
                except requests.RequestException:
                    print(f"⚠ {name} server not responding on port {port}")

            time.sleep(30)  # Check every 30 seconds

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\nReceived signal {signum}, shutting down servers...")
        self.running = False
        self.shutdown()

    def shutdown(self):
        """Gracefully shutdown all servers"""
        print("Shutting down all servers...")

        for process, name, port in self.processes:
            if process.poll() is None:  # Process is still running
                print(f"Stopping {name} server...")
                process.terminate()

                # Wait for graceful shutdown
                try:
                    process.wait(timeout=10)
                    print(f"✓ {name} server stopped")
                except subprocess.TimeoutExpired:
                    print(f"Force killing {name} server...")
                    process.kill()
                    process.wait()


def main():
    """Main server startup function"""
    print("🚀 Starting MCP Cybersecurity Servers...")
    print("=" * 50)

    manager = ServerManager()

    # Register signal handlers
    signal.signal(signal.SIGTERM, manager.signal_handler)
    signal.signal(signal.SIGINT, manager.signal_handler)

    # Server configurations
    servers = [
        ("src.servers.virustotal_server", 8001, "VirusTotal"),
        ("src.servers.servicenow_server", 8002, "ServiceNow"),
        ("src.servers.cyberreason_server", 8003, "CyberReason"),
        ("src.servers.cloud_ivx_server", 8005, "Cloud IVX"),
    ]

    # Start all servers
    for module_path, port, name in servers:
        manager.start_server(module_path, port, name)
        time.sleep(2)  # Brief delay between starts

    print("\n" + "=" * 50)
    print(f"✓ Started {len(manager.processes)} servers")

    print("\nServer URLs:")
    for _, name, port in servers:
        print(f"  {name}: http://localhost:{port}")

    # Start health check in background
    health_thread = threading.Thread(target=manager.health_check, daemon=True)
    health_thread.start()

    print("\n📊 Health checks running every 30 seconds")
    print("🔄 Servers running... (Ctrl+C to stop)")

    try:
        # Keep main thread alive
        while manager.running:
            time.sleep(1)

            # Check if any process died
            for process, name, port in manager.processes:
                if process.poll() is not None:
                    print(f"⚠ {name} server (PID: {process.pid}) has stopped")

    except KeyboardInterrupt:
        pass
    finally:
        manager.shutdown()
        print("All servers stopped.")


if __name__ == "__main__":
    main()
