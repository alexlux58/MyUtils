"""
Enhanced Security Reconnaissance & OSINT Automation Framework
Main reconnaissance engine with security features and operational controls.
"""

import asyncio
import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from src.collectors.domain_intelligence import DomainIntelligenceCollector
from src.collectors.ip_intelligence import IPIntelligenceCollector
from src.collectors.digital_footprint import DigitalFootprintCollector
from src.analyzers.attack_surface_analyzer import AttackSurfaceAnalyzer
from src.analyzers.correlation_engine import CorrelationEngine
from src.output.google_sheets_handler import GoogleSheetsHandler
from src.output.jsonl_handler import JSONLHandler
from src.output.sqlite_handler import SQLiteHandler
from src.utils.rate_limiter import AdaptiveRateLimiter
from src.utils.credential_manager import SecureCredentialManager
from src.integrations.hexstrike_integration import HexStrikeIntegration


class ReconEngine:
    """
    Main reconnaissance engine with enhanced security considerations.
    """

    def __init__(
        self,
        config: Dict[str, Any],
        opsec_validator,
        rate_limit: float = 1.0,
        dry_run: bool = False
    ):
        """Initialize the reconnaissance engine."""
        self.config = config
        self.opsec_validator = opsec_validator
        self.rate_limit = rate_limit
        self.dry_run = dry_run
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.rate_limiter = AdaptiveRateLimiter(rate_limit)
        self.credential_manager = SecureCredentialManager(config)

        # Initialize collectors
        self.domain_collector = DomainIntelligenceCollector(
            config, self.rate_limiter, self.credential_manager, dry_run
        )
        self.ip_collector = IPIntelligenceCollector(
            config, self.rate_limiter, self.credential_manager, dry_run
        )
        self.footprint_collector = DigitalFootprintCollector(
            config, self.rate_limiter, self.credential_manager, dry_run
        )

        # Initialize analyzers
        self.attack_surface_analyzer = AttackSurfaceAnalyzer(config)
        self.correlation_engine = CorrelationEngine(config)

        # Initialize output handlers
        self.google_sheets_handler = GoogleSheetsHandler(config)
        self.jsonl_handler = JSONLHandler()
        self.sqlite_handler = SQLiteHandler(config)
        
        # Initialize integrations (optional)
        self.hexstrike_integration = None
        if config.get('integrations', {}).get('hexstrike', {}).get('enabled', False):
            try:
                self.hexstrike_integration = HexStrikeIntegration(config)
                self.logger.info("HexStrike integration enabled")
            except Exception as e:
                self.logger.warning(f"Failed to initialize HexStrike integration: {e}")
                self.hexstrike_integration = None

    async def load_inventory(self, inventory_path: Path) -> List[Dict[str, Any]]:
        """Load and validate inventory from CSV file."""
        self.logger.info(f"Loading inventory from: {inventory_path}")
        
        inventory = []
        try:
            with open(inventory_path, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                for row_num, row in enumerate(reader, start=2):
                    # Validate required columns
                    required_columns = [
                        'inventory_id', 'input_value', 'input_type', 
                        'notes', 'sensitivity_level', 'authorized_scan'
                    ]
                    
                    missing_columns = [col for col in required_columns if col not in row]
                    if missing_columns:
                        self.logger.warning(
                            f"Row {row_num}: Missing columns: {missing_columns}"
                        )
                        continue

                    # Validate sensitivity level
                    if row['sensitivity_level'] not in ['public', 'low', 'med', 'high']:
                        self.logger.warning(
                            f"Row {row_num}: Invalid sensitivity_level: {row['sensitivity_level']}"
                        )
                        row['sensitivity_level'] = 'med'  # Default fallback

                    # Validate authorized_scan
                    row['authorized_scan'] = row['authorized_scan'].lower() in ['true', '1', 'yes']

                    inventory.append(row)

            self.logger.info(f"Successfully loaded {len(inventory)} targets")
            return inventory

        except Exception as e:
            self.logger.error(f"Failed to load inventory: {e}")
            raise

    async def execute_reconnaissance(
        self,
        inventory: List[Dict[str, Any]],
        output_path: Path,
        default_sensitivity: str = "med"
    ) -> List[Dict[str, Any]]:
        """Execute reconnaissance on all targets in inventory."""
        results = []
        
        self.logger.info(f"Starting reconnaissance on {len(inventory)} targets")
        
        for target in inventory:
            try:
                self.logger.info(f"Processing target: {target['input_value']}")
                
                # OPSEC validation
                if not self.opsec_validator.validate_scan(
                    target['input_value'], 
                    target['sensitivity_level']
                ):
                    self.logger.warning(
                        f"OPSEC validation failed for {target['input_value']}"
                    )
                    continue

                # Execute tiered reconnaissance
                result = await self.tiered_recon(target, default_sensitivity)
                results.append(result)

                # Save intermediate results
                await self.save_intermediate_results(result, output_path)

            except Exception as e:
                self.logger.error(
                    f"Error processing target {target['input_value']}: {e}",
                    exc_info=True
                )
                # Add error result
                results.append({
                    'inventory_id': target['inventory_id'],
                    'input_value': target['input_value'],
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                })

        return results

    async def tiered_recon(
        self, 
        target: Dict[str, Any], 
        default_sensitivity: str
    ) -> Dict[str, Any]:
        """Execute reconnaissance based on sensitivity and authorization."""
        sensitivity = target.get('sensitivity_level', default_sensitivity)
        authorized = target.get('authorized_scan', False)
        
        self.logger.info(
            f"Executing {sensitivity} level reconnaissance for {target['input_value']}"
        )

        # Base data collection (always performed)
        base_data = await self.passive_collection(target)
        
        # Enhanced collection for medium/high sensitivity with authorization
        enhanced_data = {}
        if sensitivity in ['med', 'high'] and authorized:
            self.logger.info("Performing enhanced collection with authorization")
            enhanced_data = await self.enhanced_collection(target)
        
        # Correlate findings
        correlated_data = self.correlation_engine.correlate_findings(
            base_data, enhanced_data
        )
        
        # Analyze attack surface
        attack_surface = self.attack_surface_analyzer.analyze(
            correlated_data, sensitivity
        )
        
        # Compile final result
        result = {
            'inventory_id': target['inventory_id'],
            'input_value': target['input_value'],
            'input_type': target['input_type'],
            'sensitivity_level': sensitivity,
            'authorized_scan': authorized,
            'timestamp': datetime.utcnow().isoformat(),
            'base_data': base_data,
            'enhanced_data': enhanced_data,
            'correlated_data': correlated_data,
            'attack_surface': attack_surface,
            'defensive_recommendations': self._generate_defensive_recommendations(
                correlated_data, attack_surface
            )
        }
        
        return result

    async def passive_collection(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Perform passive data collection (no authorization required)."""
        input_value = target['input_value']
        input_type = target['input_type']
        
        self.logger.info(f"Performing passive collection for {input_value}")
        
        data = {
            'target': input_value,
            'type': input_type,
            'collection_timestamp': datetime.utcnow().isoformat()
        }
        
        # Collect based on input type
        if input_type in ['domain', 'subdomain']:
            data.update(await self.domain_collector.collect_passive(input_value))
        elif input_type in ['ip', 'ip_range']:
            data.update(await self.ip_collector.collect_passive(input_value))
        elif input_type in ['email', 'username']:
            data.update(await self.footprint_collector.collect_passive(input_value))
        
        return data

    async def enhanced_collection(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Perform enhanced data collection (requires authorization)."""
        input_value = target['input_value']
        input_type = target['input_type']
        
        self.logger.info(f"Performing enhanced collection for {input_value}")
        
        data = {
            'target': input_value,
            'type': input_type,
            'collection_timestamp': datetime.utcnow().isoformat()
        }
        
        # Collect based on input type
        if input_type in ['domain', 'subdomain']:
            data.update(await self.domain_collector.collect_enhanced(input_value))
        elif input_type in ['ip', 'ip_range']:
            data.update(await self.ip_collector.collect_enhanced(input_value))
        elif input_type in ['email', 'username']:
            data.update(await self.footprint_collector.collect_enhanced(input_value))
        
        return data

    def _generate_defensive_recommendations(
        self, 
        correlated_data: Dict[str, Any], 
        attack_surface: Dict[str, Any]
    ) -> List[str]:
        """Generate defensive recommendations based on findings."""
        recommendations = []
        
        # Immediate actions (24-48 hours)
        if attack_surface.get('high_risk_vectors'):
            recommendations.append(
                "IMMEDIATE: Address high-risk attack vectors within 24-48 hours"
            )
        
        # Medium-term improvements (1-4 weeks)
        if correlated_data.get('security_headers', {}).get('missing_headers'):
            recommendations.append(
                "MEDIUM-TERM: Implement missing security headers within 1-4 weeks"
            )
        
        # Strategic changes (1-6 months)
        if attack_surface.get('attack_surface_score', 0) > 7:
            recommendations.append(
                "STRATEGIC: Reduce attack surface through architectural changes"
            )
        
        return recommendations

    async def save_intermediate_results(
        self, 
        result: Dict[str, Any], 
        output_path: Path
    ) -> None:
        """Save intermediate results to prevent data loss."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"intermediate_{result['inventory_id']}_{timestamp}.json"
        filepath = output_path / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, default=str)

    async def generate_summary_report(
        self, 
        results: List[Dict[str, Any]], 
        output_path: Path
    ) -> None:
        """Generate comprehensive summary report."""
        self.logger.info("Generating summary report")
        
        # Generate all output formats
        await self.google_sheets_handler.save_results(results, output_path)
        await self.jsonl_handler.save_results(results, output_path)
        await self.sqlite_handler.save_results(results, output_path)
        
        # Generate executive summary
        await self._generate_executive_summary(results, output_path)
        
        self.logger.info(f"Summary report generated in: {output_path}")

    async def _generate_executive_summary(
        self, 
        results: List[Dict[str, Any]], 
        output_path: Path
    ) -> None:
        """Generate executive summary with risk heat map."""
        summary = {
            'report_metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'total_targets': len(results),
                'successful_scans': len([r for r in results if 'error' not in r]),
                'failed_scans': len([r for r in results if 'error' in r])
            },
            'risk_heat_map': self._generate_risk_heat_map(results),
            'key_findings': self._extract_key_findings(results),
            'recommendations': self._extract_recommendations(results)
        }
        
        summary_path = output_path / "executive_summary.json"
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, default=str)

    def _generate_risk_heat_map(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate risk heat map from results."""
        risk_levels = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        
        for result in results:
            if 'attack_surface' in result:
                score = result['attack_surface'].get('attack_surface_score', 0)
                if score >= 8:
                    risk_levels['critical'] += 1
                elif score >= 6:
                    risk_levels['high'] += 1
                elif score >= 4:
                    risk_levels['medium'] += 1
                else:
                    risk_levels['low'] += 1
        
        return risk_levels

    def _extract_key_findings(self, results: List[Dict[str, Any]]) -> List[str]:
        """Extract key findings from results."""
        findings = []
        
        for result in results:
            if 'correlated_data' in result:
                data = result['correlated_data']
                
                # High-risk findings
                if data.get('vulnerabilities', {}).get('critical_count', 0) > 0:
                    findings.append(
                        f"Critical vulnerabilities found in {result['input_value']}"
                    )
                
                # Security misconfigurations
                if data.get('security_headers', {}).get('missing_headers'):
                    findings.append(
                        f"Missing security headers in {result['input_value']}"
                    )
        
        return findings

    def _extract_recommendations(self, results: List[Dict[str, Any]]) -> List[str]:
        """Extract recommendations from results."""
        recommendations = []
        
        for result in results:
            if 'defensive_recommendations' in result:
                recommendations.extend(result['defensive_recommendations'])
        
        # Remove duplicates and return unique recommendations
        return list(set(recommendations))

    # Integration Methods
    async def sync_with_hexstrike(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Sync reconnaissance results with HexStrike AI for enhanced analysis."""
        if not self.hexstrike_integration:
            return {'error': 'HexStrike integration not enabled'}
        
        try:
            sync_results = []
            for result in results:
                # Send intelligence data to HexStrike
                success = await self.hexstrike_integration.send_intelligence_data(result)
                if success:
                    sync_results.append({
                        'target': result.get('input_value'),
                        'sync_status': 'success',
                        'timestamp': datetime.utcnow().isoformat()
                    })
                else:
                    sync_results.append({
                        'target': result.get('input_value'),
                        'sync_status': 'failed',
                        'timestamp': datetime.utcnow().isoformat()
                    })
            
            return {
                'hexstrike_sync': sync_results,
                'total_synced': len([r for r in sync_results if r['sync_status'] == 'success']),
                'total_failed': len([r for r in sync_results if r['sync_status'] == 'failed'])
            }
            
        except Exception as e:
            self.logger.error(f"Error syncing with HexStrike: {e}")
            return {'error': str(e)}

    async def get_hexstrike_recommendations(self, target: str, intelligence_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get tool recommendations from HexStrike based on intelligence data."""
        if not self.hexstrike_integration:
            return []
        
        try:
            recommendations = await self.hexstrike_integration.get_hexstrike_recommendations(
                target, intelligence_data
            )
            return recommendations
        except Exception as e:
            self.logger.error(f"Error getting HexStrike recommendations: {e}")
            return []

    async def execute_hexstrike_workflow(self, targets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create and execute a HexStrike workflow based on reconnaissance results."""
        if not self.hexstrike_integration:
            return {'error': 'HexStrike integration not enabled'}
        
        try:
            # Create workflow
            workflow = await self.hexstrike_integration.create_hexstrike_workflow(targets)
            
            if 'error' in workflow:
                return workflow
            
            # Execute workflow
            execution_result = await self.hexstrike_integration.execute_hexstrike_tools(
                workflow.get('workflow_id', ''),
                workflow.get('tools', []),
                workflow.get('parameters', {})
            )
            
            return {
                'workflow_created': True,
                'workflow_id': workflow.get('workflow_id'),
                'execution_result': execution_result
            }
            
        except Exception as e:
            self.logger.error(f"Error executing HexStrike workflow: {e}")
            return {'error': str(e)}

    async def get_integration_status(self) -> Dict[str, Any]:
        """Get status of all integrations."""
        status = {
            'hexstrike': {
                'enabled': self.hexstrike_integration is not None,
                'status': 'disabled'
            }
        }
        
        if self.hexstrike_integration:
            try:
                hexstrike_status = self.hexstrike_integration.get_integration_status()
                status['hexstrike'].update(hexstrike_status)
            except Exception as e:
                status['hexstrike']['status'] = f'error: {e}'
        
        return status

    async def test_integrations(self) -> Dict[str, Any]:
        """Test all enabled integrations."""
        test_results = {}
        
        if self.hexstrike_integration:
            try:
                hexstrike_test = await self.hexstrike_integration.test_integration()
                test_results['hexstrike'] = hexstrike_test
            except Exception as e:
                test_results['hexstrike'] = {'error': str(e)}
        
        return test_results
