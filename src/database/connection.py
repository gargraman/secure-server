"""
Neo4j Database Connection Management for AI-SOAR Platform

Manages Neo4j database connections with support for Neo4j AuraDB and local development.
Provides async connection pooling and health monitoring for graph database operations.

Author: AI-SOAR Platform Team
Created: 2025-09-10
Refactored: 2025-09-10 - Migrated from PostgreSQL to Neo4j
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, Optional

from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncSession, GraphDatabase
from neo4j.exceptions import Neo4jError

from ..config.settings import get_settings

logger = logging.getLogger(__name__)


class Neo4jDatabaseManager:
    """Manages Neo4j database connections and sessions for the AI-SOAR platform"""

    def __init__(self):
        self.settings = get_settings()
        self.driver: Optional[AsyncDriver] = None
        self._connection_pool_size = self.settings.neo4j_max_connection_pool_size
        self._max_connection_lifetime = self.settings.neo4j_max_connection_lifetime
        self._connection_timeout = self.settings.neo4j_connection_timeout
        self._active_sessions = 0
        self._max_active_sessions = self._connection_pool_size

    async def initialize(self):
        """Initialize Neo4j database connection based on environment"""
        try:
            if getattr(self.settings, "use_cloud_neo4j", False):
                await self._init_cloud_neo4j()
            else:
                await self._init_local_neo4j()

            # Test connection
            await self._test_connection()
            logger.info("Neo4j database initialization completed successfully")

        except Exception as e:
            logger.error(f"Neo4j database initialization failed: {e}")
            raise

    async def _init_cloud_neo4j(self):
        """Initialize Neo4j AuraDB connection"""
        logger.info("Initializing Neo4j AuraDB connection...")

        # Neo4j AuraDB connection URI
        neo4j_uri = self.settings.neo4j_uri
        neo4j_user = self.settings.neo4j_username
        neo4j_password = self.settings.neo4j_password

        if not neo4j_password:
            raise ValueError("Neo4j password is required for cloud connection")

        # Create async Neo4j driver for AuraDB
        self.driver = AsyncGraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password),
            max_connection_pool_size=self._connection_pool_size,
            max_connection_lifetime=self._max_connection_lifetime,
            connection_timeout=self._connection_timeout,
            encrypted=self.settings.neo4j_encrypted,
            max_transaction_retry_time=15.0,
        )

        logger.info(f"Neo4j AuraDB driver created for: {neo4j_uri}")

    async def _init_local_neo4j(self):
        """Initialize local Neo4j connection"""
        logger.info("Initializing local Neo4j connection...")

        # Local Neo4j connection configuration
        neo4j_uri = self.settings.neo4j_uri
        neo4j_user = self.settings.neo4j_username
        neo4j_password = self.settings.neo4j_password

        # Create async Neo4j driver for local development
        self.driver = AsyncGraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password),
            max_connection_pool_size=self._connection_pool_size,
            max_connection_lifetime=self._max_connection_lifetime,
            connection_timeout=self._connection_timeout,
            encrypted=self.settings.neo4j_encrypted,
            max_transaction_retry_time=15.0,
        )

        logger.info(f"Local Neo4j driver created for: {neo4j_uri}")

    async def _test_connection(self):
        """Test Neo4j database connection"""
        try:
            async with self.driver.session() as session:
                result = await session.run("RETURN 1 as test")
                record = await result.single()
                assert record["test"] == 1
            logger.info("Neo4j connection test successful")
        except Exception as e:
            logger.error(f"Neo4j connection test failed: {e}")
            raise

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get Neo4j session with automatic cleanup and resource tracking"""
        if self._active_sessions >= self._max_active_sessions:
            logger.warning(
                f"Maximum active sessions ({self._max_active_sessions}) reached"
            )
            # Wait briefly for sessions to free up
            await asyncio.sleep(0.1)

        self._active_sessions += 1
        async with self.driver.session(
            database=self.settings.neo4j_database
        ) as session:
            try:
                logger.debug(
                    f"Neo4j session acquired (active: {self._active_sessions})"
                )
                yield session
            except Exception as e:
                logger.error(f"Neo4j session error: {e}")
                raise
            finally:
                self._active_sessions -= 1
                logger.debug(
                    f"Neo4j session released (active: {self._active_sessions})"
                )

    async def get_driver(self) -> AsyncDriver:
        """Get Neo4j driver for dependency injection"""
        return self.driver

    async def health_check(self) -> Dict[str, Any]:
        """Perform Neo4j database health check"""
        try:
            async with self.driver.session() as session:
                # Get database version and basic info
                result = await session.run(
                    "CALL dbms.components() YIELD name, versions, edition"
                )
                components = []
                async for record in result:
                    components.append(
                        {
                            "name": record["name"],
                            "versions": record["versions"],
                            "edition": record["edition"],
                        }
                    )

                # Get basic database stats
                stats_result = await session.run(
                    "MATCH (n) RETURN count(n) as nodeCount"
                )
                node_count = (await stats_result.single())["nodeCount"]

                return {
                    "status": "healthy",
                    "database_type": "Neo4j",
                    "connection_type": "cloud_neo4j"
                    if getattr(self.settings, "use_cloud_neo4j", False)
                    else "local",
                    "components": components,
                    "node_count": node_count,
                    "pool_size": self._connection_pool_size,
                    "active_sessions": self._active_sessions,
                    "max_sessions": self._max_active_sessions,
                    "connection_timeout": self._connection_timeout,
                    "max_connection_lifetime": self._max_connection_lifetime,
                }
        except Exception as e:
            logger.error(f"Neo4j health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "connection_type": "cloud_neo4j"
                if getattr(self.settings, "use_cloud_neo4j", False)
                else "local",
            }

    async def close(self):
        """Close Neo4j connections and cleanup"""
        try:
            if self.driver:
                await self.driver.close()
                logger.info("Neo4j driver closed")

        except Exception as e:
            logger.error(f"Error during Neo4j cleanup: {e}")

    async def execute_query(
        self, query: str, parameters: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Execute a Cypher query and return results"""
        async with self.get_session() as session:
            try:
                result = await session.run(query, parameters or {})
                return await result.data()
            except Neo4jError as e:
                logger.error(f"Neo4j query execution failed: {e}")
                raise

    async def execute_write_query(
        self, query: str, parameters: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Execute a write Cypher query in a transaction"""
        async with self.get_session() as session:
            try:
                async with session.begin_transaction() as tx:
                    result = await tx.run(query, parameters or {})
                    await tx.commit()
                    return await result.data()
            except Neo4jError as e:
                logger.error(f"Neo4j write query execution failed: {e}")
                raise


# Global Neo4j database manager instance
_db_manager: Optional[Neo4jDatabaseManager] = None


async def get_database_manager() -> Neo4jDatabaseManager:
    """Get or create Neo4j database manager instance"""
    global _db_manager
    if _db_manager is None:
        _db_manager = Neo4jDatabaseManager()
        await _db_manager.initialize()
    return _db_manager


async def get_db_session():
    """Dependency function to get Neo4j session for FastAPI"""
    db_manager = await get_database_manager()
    async with db_manager.get_session() as session:
        yield session
