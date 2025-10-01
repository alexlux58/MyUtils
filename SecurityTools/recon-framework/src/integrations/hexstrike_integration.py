"""
HexStrike AI Integration Module
Provides integration capabilities with HexStrike AI MCP framework.
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

try:
    import requests
    from mcp.server.fastmcp import FastMCP
    HEXSTRIKE_AVAILABLE = True
except ImportError:
    HEXSTRIKE_AVAILABLE = False


class HexStrikeIntegration:
    """
    Integration module for HexStrike AI MCP framework.
    Provides seamless data exchange and workflow integration.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize HexStrike integration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.hexstrike_available = HEXSTRIKE_AVAILABLE
        self.hexstrike_server_url = config.get('hexstrike', {}).get('server_url', 'http://localhost:8888')
        self.hexstrike_api_key = config.get('hexstrike', {}).get('api_key')
        
        if not self.hexstrike_available:
            self.logger.warning("HexStrike dependencies not available. Integration disabled.")

    async def is_hexstrike_available(self) -> bool:
        """Check if HexStrike AI server is available."""
        if not self.hexstrike_available:
            return False
        
        try:
            response = requests.get(f"{self.hexstrike_server_url}/health", timeout=5)
            return response.status_code == 200
        except Exception as e:
            self.logger.debug(f"HexStrike server not available: {e}")
            return False

    async def send_intelligence_data(self, intelligence_data: Dict[str, Any]) -> bool:
        """Send intelligence data to HexStrike AI for enhanced analysis."""
        if not await self.is_hexstrike_available():
            self.logger.warning("HexStrike server not available, skipping data transfer")
            return False
        
        try:
            # Prepare data for HexStrike
            hexstrike_payload = self._prepare_hexstrike_payload(intelligence_data)
            
            # Send to HexStrike intelligence endpoint
            response = requests.post(
                f"{self.hexstrike_server_url}/api/intelligence/analyze-target",
                json=hexstrike_payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            if response.status_code == 200:
                self.logger.info("Intelligence data sent to HexStrike successfully")
                return True
            else:
                self.logger.error(f"Failed to send data to HexStrike: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending data to HexStrike: {e}")
            return False

    async def get_hexstrike_recommendations(self, target: str, intelligence_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get tool recommendations from HexStrike based on intelligence data."""
        if not await self.is_hexstrike_available():
            return []
        
        try:
            payload = {
                'target': target,
                'intelligence_data': intelligence_data,
                'analysis_type': 'tool_recommendations'
            }
            
            response = requests.post(
                f"{self.hexstrike_server_url}/api/intelligence/select-tools",
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('recommended_tools', [])
            else:
                self.logger.error(f"Failed to get HexStrike recommendations: {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.error(f"Error getting HexStrike recommendations: {e}")
            return []

    async def execute_hexstrike_tools(self, target: str, tools: List[str], parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute HexStrike tools based on our intelligence recommendations."""
        if not await self.is_hexstrike_available():
            return {'error': 'HexStrike server not available'}
        
        try:
            payload = {
                'target': target,
                'tools': tools,
                'parameters': parameters or {},
                'source': 'recon_framework'
            }
            
            response = requests.post(
                f"{self.hexstrike_server_url}/api/command",
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=60
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'HexStrike execution failed: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'Error executing HexStrike tools: {e}'}

    async def get_hexstrike_results(self, execution_id: str) -> Dict[str, Any]:
        """Get results from HexStrike tool execution."""
        if not await self.is_hexstrike_available():
            return {'error': 'HexStrike server not available'}
        
        try:
            response = requests.get(
                f"{self.hexstrike_server_url}/api/results/{execution_id}",
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'Failed to get results: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'Error getting HexStrike results: {e}'}

    def _prepare_hexstrike_payload(self, intelligence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare intelligence data for HexStrike consumption."""
        payload = {
            'target': intelligence_data.get('input_value', ''),
            'analysis_type': 'comprehensive',
            'intelligence_data': {
                'domain_intelligence': intelligence_data.get('correlated_data', {}).get('domain_intelligence', {}),
                'ip_intelligence': intelligence_data.get('correlated_data', {}).get('ip_intelligence', {}),
                'digital_footprint': intelligence_data.get('correlated_data', {}).get('digital_footprint', {}),
                'attack_surface': intelligence_data.get('attack_surface', {}),
                'threat_indicators': intelligence_data.get('correlated_data', {}).get('threat_indicators', [])
            },
            'metadata': {
                'source': 'recon_framework',
                'timestamp': datetime.utcnow().isoformat(),
                'sensitivity_level': intelligence_data.get('sensitivity_level', 'unknown')
            }
        }
        
        return payload

    async def create_hexstrike_workflow(self, targets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a comprehensive HexStrike workflow based on our intelligence."""
        if not await self.is_hexstrike_available():
            return {'error': 'HexStrike server not available'}
        
        try:
            # Analyze targets and create workflow
            workflow = {
                'name': f'Recon Framework Workflow - {datetime.now().strftime("%Y%m%d_%H%M%S")}',
                'targets': [],
                'phases': [],
                'created_by': 'recon_framework',
                'created_at': datetime.utcnow().isoformat()
            }
            
            for target in targets:
                target_workflow = await self._create_target_workflow(target)
                workflow['targets'].append(target_workflow)
            
            # Send workflow to HexStrike
            response = requests.post(
                f"{self.hexstrike_server_url}/api/workflows/create",
                json=workflow,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'Failed to create HexStrike workflow: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'Error creating HexStrike workflow: {e}'}

    async def _create_target_workflow(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Create workflow for a specific target."""
        target_workflow = {
            'target': target.get('input_value', ''),
            'type': target.get('input_type', ''),
            'sensitivity_level': target.get('sensitivity_level', 'unknown'),
            'phases': []
        }
        
        # Phase 1: Initial reconnaissance
        if target.get('input_type') in ['domain', 'subdomain']:
            target_workflow['phases'].append({
                'name': 'Domain Reconnaissance',
                'tools': ['nmap_scan', 'gobuster_scan', 'nuclei_scan'],
                'priority': 'high'
            })
        
        # Phase 2: Vulnerability assessment
        if target.get('attack_surface', {}).get('attack_surface_score', 0) > 5:
            target_workflow['phases'].append({
                'name': 'Vulnerability Assessment',
                'tools': ['sqlmap_scan', 'nikto_scan', 'wpscan_scan'],
                'priority': 'high'
            })
        
        # Phase 3: Social engineering (if applicable)
        if target.get('input_type') in ['email', 'username']:
            target_workflow['phases'].append({
                'name': 'Social Engineering Assessment',
                'tools': ['phishing_simulation', 'credential_harvesting'],
                'priority': 'medium'
            })
        
        return target_workflow

    async def sync_results(self, hexstrike_results: Dict[str, Any]) -> Dict[str, Any]:
        """Sync HexStrike results back into our framework format."""
        try:
            synced_results = {
                'hexstrike_execution': hexstrike_results,
                'sync_timestamp': datetime.utcnow().isoformat(),
                'framework_integration': True
            }
            
            # Convert HexStrike results to our format
            if 'tool_results' in hexstrike_results:
                synced_results['tool_outputs'] = hexstrike_results['tool_results']
            
            if 'vulnerabilities' in hexstrike_results:
                synced_results['vulnerabilities'] = hexstrike_results['vulnerabilities']
            
            if 'recommendations' in hexstrike_results:
                synced_results['hexstrike_recommendations'] = hexstrike_results['recommendations']
            
            return synced_results
            
        except Exception as e:
            self.logger.error(f"Error syncing HexStrike results: {e}")
            return {'error': str(e)}

    def get_integration_status(self) -> Dict[str, Any]:
        """Get current integration status."""
        return {
            'hexstrike_available': self.hexstrike_available,
            'server_url': self.hexstrike_server_url,
            'api_key_configured': bool(self.hexstrike_api_key),
            'integration_enabled': self.config.get('hexstrike', {}).get('enabled', False)
        }

    async def test_integration(self) -> Dict[str, Any]:
        """Test the integration with HexStrike."""
        test_results = {
            'hexstrike_available': await self.is_hexstrike_available(),
            'api_connectivity': False,
            'tool_execution': False,
            'data_sync': False
        }
        
        if test_results['hexstrike_available']:
            try:
                # Test API connectivity
                response = requests.get(f"{self.hexstrike_server_url}/api/telemetry", timeout=5)
                test_results['api_connectivity'] = response.status_code == 200
                
                # Test tool execution
                test_execution = await self.execute_hexstrike_tools(
                    'test.example.com',
                    ['nmap_scan'],
                    {'ports': '80,443'}
                )
                test_results['tool_execution'] = 'error' not in test_execution
                
                # Test data sync
                test_data = {'input_value': 'test.example.com', 'attack_surface': {}}
                sync_result = await self.sync_results({'test': 'data'})
                test_results['data_sync'] = 'error' not in sync_result
                
            except Exception as e:
                test_results['error'] = str(e)
        
        return test_results
