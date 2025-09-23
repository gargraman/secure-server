"""
XDR API CLI Interface
==================

Command Line Interface for XDR APIs.
"""

import asyncio
import json
import logging
import os
import sys
from uuid import UUID

import click

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from client.xdr.alerts import XDRAlertClient
from client.xdr.assets import XDRAssetClient
from client.xdr.client import XDRConfig
from client.xdr.events import XDREventClient
from client.xdr.intel import XDRIntelClient
from client.xdr.mitreattack import XDRMitreAttackClient


# CLI Interface
@click.group()
@click.option("--base-url", default=None, help="XDR API base URL")
@click.option("--auth-token", default=None, help="Authentication token")
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.option("--poll", is_flag=True, help="Enable alert polling")
@click.option(
    "--poll-interval", type=int, default=30, help="Polling interval in seconds"
)
@click.pass_context
def cli(ctx, base_url, auth_token, debug, poll, poll_interval):
    """XDR API Command Line Interface"""
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create configuration
    config = XDRConfig.from_environment()
    if base_url:
        config.base_url = base_url
    if auth_token:
        config.auth_token = auth_token
    if poll:
        config.poll_enabled = True
        config.poll_interval = poll_interval

    ctx.ensure_object(dict)
    ctx.obj["config"] = config


# Alerts commands
@cli.group()
def alerts():
    """Commands for XDR Alerts API"""
    pass


@alerts.command()
@click.option("--limit", default=10, help="Number of alerts to fetch")
@click.option("--offset", default=0, help="Page offset")
@click.option("--status", default=None, help="Filter by status (e.g., NEW,IN_PROGRESS)")
@click.option("--severity", default=None, help="Filter by severity")
@click.pass_context
def list(ctx, limit, offset, status, severity):
    """List all alerts"""

    async def _list_alerts():
        config = ctx.obj["config"]

        # Build filters
        filters = {}
        if status:
            filters["status"] = status
        if severity:
            filters["severity"] = f'{{"eq":"{severity}"}}'

        async with XDRAlertClient(config) as client:
            try:
                response = await client.get_all_alerts(
                    page_limit=limit,
                    page_offset=offset,
                    filters=filters if filters else None,
                )

                # Display results
                meta = response.get("meta", {})
                data = response.get("data", [])

                click.echo(f"Total Records: {meta.get('totalRecords', 'Unknown')}")
                click.echo(f"Showing {len(data)} alerts:")
                click.echo("-" * 80)

                for alert in data:
                    attrs = alert.get("attributes", {})
                    click.echo(f"ID: {alert.get('id')}")
                    click.echo(f"Name: {attrs.get('name', 'N/A')}")
                    click.echo(f"Message: {attrs.get('message', 'N/A')}")
                    click.echo(f"Risk: {attrs.get('risk', 'N/A')}")
                    click.echo(f"Status: {attrs.get('status', {}).get('value', 'N/A')}")
                    click.echo(f"Created: {attrs.get('createdAt', 'N/A')}")
                    click.echo("-" * 40)

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_list_alerts())


@alerts.command()
@click.argument("alert_id")
@click.pass_context
def get(ctx, alert_id):
    """Get details of a specific alert by ID"""

    async def _get_alert():
        config = ctx.obj["config"]

        async with XDRAlertClient(config) as client:
            try:
                response = await client.get_alert_by_id(alert_id)

                # Display result
                data_list = response.get("data", [])
                if not isinstance(data_list, list):
                    data_list = [data_list]
                for data in data_list:
                    attrs = data.get("attributes", {})
                    relationships = data.get("relationship", {})
                    click.echo(f"Alert ID: {data.get('id')}")
                    click.echo(f"Type: {data.get('type')}")
                    click.echo("-" * 40)
                    click.echo("Attributes:")
                    for key, value in attrs.items():
                        if isinstance(value, dict):
                            click.echo(f"  {key}: {json.dumps(value, indent=4)}")
                        else:
                            click.echo(f"  {key}: {value}")
                    if relationships:
                        click.echo("-" * 40)
                        click.echo("Relationships:")
                        for key, value in relationships.items():
                            click.echo(f"  {key}: {value}")

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_get_alert())


@alerts.command()
@click.argument("alert_id")
@click.pass_context
def common_fields(ctx, alert_id):
    """Show common fields for a specific alert"""

    async def _common_fields():
        config = ctx.obj["config"]

        async with XDRAlertClient(config) as client:
            try:
                response = await client.get_alert_common_fields(alert_id)
                extracted = client.extract_common_fields(response)

                click.echo(f"Common Fields for Alert: {alert_id}")
                click.echo("-" * 40)
                click.echo(f"Field1: {extracted['field1']}")
                click.echo(f"Field2: {extracted['field2']}")

                # Also show raw response for debugging
                if response:
                    click.echo("\\nRaw Response:")
                    click.echo(json.dumps(response, indent=2))

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_common_fields())


@alerts.command()
@click.pass_context
def start_poll(ctx):
    """Start polling for new alerts"""

    async def _start_polling():
        config = ctx.obj["config"]

        async def alert_callback(alerts):
            click.echo(f"\\n==== {len(alerts)} NEW ALERTS FOUND ====\\n")
            for alert in alerts:
                attrs = alert.get("attributes", {})
                click.echo(f"ID: {alert.get('id')}")
                click.echo(f"Name: {attrs.get('name', 'N/A')}")
                click.echo(f"Message: {attrs.get('message', 'N/A')}")
                click.echo(f"Created: {attrs.get('createdAt', 'N/A')}")
                click.echo("-" * 40)

        async with XDRAlertClient(config) as client:
            try:
                await client.start_polling(config.poll_interval, alert_callback)
                # Keep the polling running until user interrupts
                click.echo(
                    f"Polling for new alerts every {config.poll_interval} seconds... (Ctrl+C to stop)"
                )
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                click.echo("Stopping alert polling...")
                await client.stop_polling()
            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    try:
        asyncio.run(_start_polling())
    except KeyboardInterrupt:
        click.echo("\\nPolling stopped.")


# Events commands
@cli.group()
def events():
    """Commands for XDR Events API"""
    pass


@events.command()
@click.argument("alert_id")
@click.option("--limit", default=10, help="Number of events to fetch")
@click.option("--offset", default=0, help="Page offset")
@click.option("--type", default=None, help="Filter by event type")
@click.pass_context
def list(ctx, alert_id, limit, offset, type):
    """List events for a specific alert"""

    async def _list_events():
        config = ctx.obj["config"]

        # Build filters
        filters = {}
        if type:
            filters["type"] = type

        async with XDREventClient(config) as client:
            try:
                response = await client.get_alert_events(
                    alert_id,
                    page_limit=limit,
                    page_offset=offset,
                    filters=filters if filters else None,
                )

                # Display results
                meta = response.get("meta", {})
                data = response.get("data", [])

                click.echo(f"Total Records: {meta.get('totalRecords', 'Unknown')}")
                click.echo(f"Showing {len(data)} events for alert {alert_id}:")
                click.echo("-" * 80)

                for event in data:
                    attrs = event.get("attributes", {})
                    click.echo(f"ID: {event.get('id')}")
                    click.echo(f"Type: {attrs.get('type', 'N/A')}")
                    click.echo(f"Time: {attrs.get('time', 'N/A')}")
                    click.echo(f"Source: {attrs.get('source', 'N/A')}")
                    click.echo("Details:")
                    details = attrs.get("details", {})
                    if details:
                        click.echo(json.dumps(details, indent=4))
                    click.echo("-" * 40)

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_list_events())


@events.command()
@click.argument("alert_id")
@click.pass_context
def stats(ctx, alert_id):
    """Get event statistics for a specific alert"""

    async def _event_stats():
        config = ctx.obj["config"]

        async with XDREventClient(config) as client:
            try:
                response = await client.get_event_stats(alert_id)

                # Display results
                data = response.get("data", {})
                attrs = data.get("attributes", {})

                click.echo(f"Event Statistics for Alert {alert_id}:")
                click.echo("-" * 80)

                for key, value in attrs.items():
                    if isinstance(value, dict):
                        click.echo(f"{key}:")
                        click.echo(json.dumps(value, indent=4))
                    else:
                        click.echo(f"{key}: {value}")

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_event_stats())


@events.command()
@click.option("--query", required=True, help="Search query for events")
@click.option("--limit", default=10, help="Number of events to fetch")
@click.option("--offset", default=0, help="Page offset")
@click.pass_context
def search(ctx, query, limit, offset):
    """Search for events across all alerts"""

    async def _search_events():
        config = ctx.obj["config"]

        async with XDREventClient(config) as client:
            try:
                response = await client.search_events(
                    search_text=query, page_limit=limit, page_offset=offset
                )

                # Display results
                meta = response.get("meta", {})
                data = response.get("data", [])

                click.echo(f"Total Records: {meta.get('totalRecords', 'Unknown')}")
                click.echo(f"Showing {len(data)} events matching '{query}':")
                click.echo("-" * 80)

                for event in data:
                    attrs = event.get("attributes", {})
                    click.echo(f"ID: {event.get('id')}")
                    click.echo(f"Alert ID: {attrs.get('alertId', 'N/A')}")
                    click.echo(f"Type: {attrs.get('type', 'N/A')}")
                    click.echo(f"Time: {attrs.get('time', 'N/A')}")
                    click.echo(f"Source: {attrs.get('source', 'N/A')}")
                    click.echo("-" * 40)

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_search_events())


# Assets commands
@cli.group()
def assets():
    """Commands for XDR Assets API"""
    pass


@assets.command()
@click.argument("alert_id")
@click.option("--limit", default=10, help="Number of assets to fetch")
@click.option("--offset", default=0, help="Page offset")
@click.option("--type", default=None, help="Filter by asset type")
@click.pass_context
def list(ctx, alert_id, limit, offset, type):
    """List assets for a specific alert"""

    async def _list_assets():
        config = ctx.obj["config"]

        # Build filters
        filters = {}
        if type:
            filters["type"] = type

        async with XDRAssetClient(config) as client:
            try:
                response = await client.get_alert_assets(
                    alert_id,
                    page_limit=limit,
                    page_offset=offset,
                    filters=filters if filters else None,
                )

                # Display results
                meta = response.get("meta", {})
                data = response.get("data", [])

                click.echo(f"Total Records: {meta.get('totalRecords', 'Unknown')}")
                click.echo(f"Showing {len(data)} assets for alert {alert_id}:")
                click.echo("-" * 80)

                for asset in data:
                    attrs = asset.get("attributes", {})
                    click.echo(f"ID: {asset.get('id')}")
                    click.echo(f"Name: {attrs.get('name', 'N/A')}")
                    click.echo(f"Hostname: {attrs.get('hostname', 'N/A')}")
                    click.echo(f"IP Address: {attrs.get('ipAddress', 'N/A')}")
                    click.echo(f"Type: {attrs.get('type', 'N/A')}")
                    click.echo(f"Risk: {attrs.get('risk', 'N/A')}")
                    click.echo("-" * 40)

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_list_assets())


@assets.command()
@click.argument("alert_id")
@click.pass_context
def stats(ctx, alert_id):
    """Get asset statistics for a specific alert"""

    async def _asset_stats():
        config = ctx.obj["config"]

        async with XDRAssetClient(config) as client:
            try:
                response = await client.get_asset_stats(alert_id)

                # Display results
                data = response.get("data", {})
                attrs = data.get("attributes", {})

                click.echo(f"Asset Statistics for Alert {alert_id}:")
                click.echo("-" * 80)

                for key, value in attrs.items():
                    if isinstance(value, dict):
                        click.echo(f"{key}:")
                        click.echo(json.dumps(value, indent=4))
                    else:
                        click.echo(f"{key}: {value}")

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_asset_stats())


@assets.command()
@click.argument("asset_id")
@click.pass_context
def get(ctx, asset_id):
    """Get details of a specific asset by ID"""

    async def _get_asset():
        config = ctx.obj["config"]

        async with XDRAssetClient(config) as client:
            try:
                response = await client.get_asset_details(asset_id)

                # Display result
                data = response.get("data", {})
                attrs = data.get("attributes", {})
                relationships = data.get("relationship", {})

                click.echo(f"Asset ID: {data.get('id')}")
                click.echo(f"Type: {data.get('type')}")
                click.echo("-" * 40)
                click.echo("Attributes:")
                for key, value in attrs.items():
                    if isinstance(value, dict):
                        click.echo(f"  {key}: {json.dumps(value, indent=4)}")
                    else:
                        click.echo(f"  {key}: {value}")
                if relationships:
                    click.echo("-" * 40)
                    click.echo("Relationships:")
                    for key, value in relationships.items():
                        click.echo(f"  {key}: {value}")

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_get_asset())


# Intel commands
@cli.group()
def intel():
    """Commands for XDR Intel API"""
    pass


@intel.command()
@click.argument("alert_id")
@click.pass_context
def get(ctx, alert_id):
    """Get intelligence information for a specific alert"""

    async def _get_intel():
        config = ctx.obj["config"]

        async with XDRIntelClient(config) as client:
            try:
                response = await client.get_alert_intel(alert_id)

                # Display result
                data = response.get("data", {})
                attrs = data.get("attributes", {})

                click.echo(f"Intelligence for Alert {alert_id}:")
                click.echo("-" * 80)

                click.echo("Analysis:")
                click.echo(attrs.get("analysis", "N/A"))
                click.echo()

                click.echo("Source:")
                click.echo(attrs.get("source", "N/A"))
                click.echo()

                click.echo("Indicators:")
                indicators = attrs.get("indicators", {})
                click.echo(json.dumps(indicators, indent=4))
                click.echo()

                click.echo("Tactics:")
                tactics = attrs.get("tactics", [])
                for tactic in tactics:
                    click.echo(f"- {tactic.get('name', '')} ({tactic.get('id', '')})")
                click.echo()

                click.echo("Techniques:")
                techniques = attrs.get("techniques", [])
                for technique in techniques:
                    click.echo(
                        f"- {technique.get('name', '')} ({technique.get('id', '')})"
                    )

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_get_intel())


@intel.command()
@click.argument("case_id")
@click.pass_context
def case(ctx, case_id):
    """Get intelligence for a specific case"""

    async def _get_case_intel():
        config = ctx.obj["config"]

        async with XDRIntelClient(config) as client:
            try:
                response = await client.get_case_intel(case_id)

                # Display result
                data = response.get("data", {})
                attrs = data.get("attributes", {})

                click.echo(f"Intelligence for Case {case_id}:")
                click.echo("-" * 80)

                click.echo("Analysis:")
                click.echo(attrs.get("analysis", "N/A"))
                click.echo()

                click.echo("Source:")
                click.echo(attrs.get("source", "N/A"))
                click.echo()

                click.echo("Indicators:")
                indicators = attrs.get("indicators", {})
                click.echo(json.dumps(indicators, indent=4))

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_get_case_intel())


@intel.command()
@click.option("--query", required=True, help="Search query for intelligence")
@click.option("--limit", default=10, help="Number of results to fetch")
@click.option("--offset", default=0, help="Page offset")
@click.pass_context
def search(ctx, query, limit, offset):
    """Search for intelligence across all alerts"""

    async def _search_intel():
        config = ctx.obj["config"]

        async with XDRIntelClient(config) as client:
            try:
                response = await client.search_intel(
                    search_text=query, page_limit=limit, page_offset=offset
                )

                # Display results
                meta = response.get("meta", {})
                data = response.get("data", [])

                click.echo(f"Total Records: {meta.get('totalRecords', 'Unknown')}")
                click.echo(
                    f"Showing {len(data)} intelligence items matching '{query}':"
                )
                click.echo("-" * 80)

                for item in data:
                    attrs = item.get("attributes", {})
                    click.echo(f"ID: {item.get('id')}")
                    click.echo(f"Alert ID: {attrs.get('alertId', 'N/A')}")
                    click.echo(f"Source: {attrs.get('source', 'N/A')}")

                    # Show snippet of analysis
                    analysis = attrs.get("analysis", "")
                    if analysis:
                        if len(analysis) > 100:
                            analysis = analysis[:100] + "..."
                        click.echo(f"Analysis: {analysis}")

                    click.echo("-" * 40)

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_search_intel())


# MITRE ATT&CK commands
@cli.group()
def mitre():
    """Commands for XDR MITRE ATT&CK API"""
    pass


@mitre.command()
@click.option("--version", default=None, help="MITRE ATT&CK version")
@click.pass_context
def matrix(ctx, version):
    """Get MITRE ATT&CK matrix details"""

    async def _get_matrix():
        config = ctx.obj["config"]

        async with XDRMitreAttackClient(config) as client:
            try:
                response = await client.get_mitre_matrix(version)

                # Display result
                data = response.get("data", {})
                attrs = data.get("attributes", {})

                click.echo(
                    f"MITRE ATT&CK Matrix (Version: {attrs.get('version', 'Latest')}):"
                )
                click.echo("-" * 80)

                click.echo("Tactics:")
                tactics = attrs.get("tactics", [])
                for tactic in tactics:
                    click.echo(f"- {tactic.get('name', '')} ({tactic.get('id', '')})")
                click.echo()

                click.echo("Techniques Count:")
                click.echo(f"{len(attrs.get('techniques', []))} techniques available")

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_get_matrix())


@mitre.command()
@click.argument("technique_id")
@click.option("--version", default=None, help="MITRE ATT&CK version")
@click.pass_context
def technique(ctx, technique_id, version):
    """Get details of a specific MITRE ATT&CK technique"""

    async def _get_technique():
        config = ctx.obj["config"]

        async with XDRMitreAttackClient(config) as client:
            try:
                response = await client.get_technique_details(technique_id, version)

                # Display result
                data = response.get("data", {})
                attrs = data.get("attributes", {})

                click.echo(
                    f"MITRE ATT&CK Technique: {attrs.get('name', '')} ({attrs.get('id', '')})"
                )
                click.echo("-" * 80)

                click.echo("Description:")
                click.echo(attrs.get("description", "N/A"))
                click.echo()

                click.echo("Tactics:")
                tactics = attrs.get("tactics", [])
                for tactic in tactics:
                    click.echo(f"- {tactic.get('name', '')} ({tactic.get('id', '')})")
                click.echo()

                if attrs.get("subtechniques"):
                    click.echo("Subtechniques:")
                    subtechniques = attrs.get("subtechniques", [])
                    for sub in subtechniques:
                        click.echo(f"- {sub.get('name', '')} ({sub.get('id', '')})")
                    click.echo()

                click.echo("Detection:")
                click.echo(attrs.get("detection", "N/A"))
                click.echo()

                click.echo("Mitigation:")
                click.echo(attrs.get("mitigation", "N/A"))

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_get_technique())


@mitre.command()
@click.pass_context
def versions(ctx):
    """Get available MITRE ATT&CK versions"""

    async def _get_versions():
        config = ctx.obj["config"]

        async with XDRMitreAttackClient(config) as client:
            try:
                response = await client.get_mitre_versions()

                # Display result
                data = response.get("data", [])

                click.echo("Available MITRE ATT&CK Versions:")
                click.echo("-" * 80)

                for version in data:
                    attrs = version.get("attributes", {})
                    click.echo(f"- {attrs.get('version', 'Unknown')}")
                    click.echo(f"  Released: {attrs.get('releaseDate', 'Unknown')}")
                    click.echo()

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_get_versions())


@mitre.command()
@click.argument("technique_id")
@click.option("--limit", default=10, help="Number of alerts to fetch")
@click.option("--offset", default=0, help="Page offset")
@click.pass_context
def alerts(ctx, technique_id, limit, offset):
    """Get alerts associated with a specific MITRE ATT&CK technique"""

    async def _get_alerts():
        config = ctx.obj["config"]

        async with XDRMitreAttackClient(config) as client:
            try:
                response = await client.get_alerts_by_technique(
                    technique_id, page_limit=limit, page_offset=offset
                )

                # Display results
                meta = response.get("meta", {})
                data = response.get("data", [])

                click.echo(f"Total Records: {meta.get('totalRecords', 'Unknown')}")
                click.echo(f"Showing {len(data)} alerts for technique {technique_id}:")
                click.echo("-" * 80)

                for alert in data:
                    attrs = alert.get("attributes", {})
                    click.echo(f"ID: {alert.get('id')}")
                    click.echo(f"Name: {attrs.get('name', 'N/A')}")
                    click.echo(f"Severity: {attrs.get('severity', 'N/A')}")
                    click.echo(f"Status: {attrs.get('status', {}).get('value', 'N/A')}")
                    click.echo(f"Time: {attrs.get('time', 'N/A')}")
                    click.echo("-" * 40)

            except Exception as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

    asyncio.run(_get_alerts())


if __name__ == "__main__":
    cli()
