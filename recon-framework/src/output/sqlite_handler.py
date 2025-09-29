"""
SQLite Handler
Handles output to SQLite database for advanced analysis.
"""

import sqlite3
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime


class SQLiteHandler:
    """Handles output to SQLite database for advanced analysis."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize the SQLite handler."""
        self.config = config
        self.logger = logging.getLogger(__name__)

    async def save_results(self, results: List[Dict[str, Any]], output_path: str) -> bool:
        """Save results to SQLite database."""
        try:
            output_dir = Path(output_path)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Create database file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            db_file = output_dir / f"reconnaissance_{timestamp}.db"
            
            # Initialize database
            await self._initialize_database(db_file)
            
            # Insert results
            await self._insert_results(db_file, results)
            
            # Create views for common queries
            await self._create_analysis_views(db_file)
            
            self.logger.info(f"Results saved to SQLite database: {db_file}")
            return True

        except Exception as e:
            self.logger.error(f"Error saving to SQLite: {e}")
            return False

    async def _initialize_database(self, db_file: Path) -> None:
        """Initialize SQLite database with required tables."""
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        try:
            # Main results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS reconnaissance_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    inventory_id TEXT NOT NULL,
                    input_value TEXT NOT NULL,
                    input_type TEXT NOT NULL,
                    sensitivity_level TEXT NOT NULL,
                    authorized_scan BOOLEAN NOT NULL,
                    collection_timestamp TEXT NOT NULL,
                    attack_surface_score INTEGER,
                    risk_level TEXT,
                    phishing_risk_level TEXT,
                    error_message TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Attack vectors table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_vectors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    result_id INTEGER NOT NULL,
                    vector_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    mitigation TEXT,
                    mitre_technique TEXT,
                    tactic TEXT,
                    FOREIGN KEY (result_id) REFERENCES reconnaissance_results (id)
                )
            ''')
            
            # Initial access vectors table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS initial_access_vectors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    result_id INTEGER NOT NULL,
                    vector_name TEXT NOT NULL,
                    priority INTEGER,
                    description TEXT,
                    FOREIGN KEY (result_id) REFERENCES reconnaissance_results (id)
                )
            ''')
            
            # Password spray candidates table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_spray_candidates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    result_id INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    breach_date TEXT,
                    password_patterns TEXT,
                    target_accounts TEXT,
                    FOREIGN KEY (result_id) REFERENCES reconnaissance_results (id)
                )
            ''')
            
            # Defensive recommendations table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS defensive_recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    result_id INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    action TEXT NOT NULL,
                    timeline TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    description TEXT,
                    FOREIGN KEY (result_id) REFERENCES reconnaissance_results (id)
                )
            ''')
            
            # Domain intelligence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domain_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    result_id INTEGER NOT NULL,
                    domain TEXT,
                    dns_records TEXT,
                    whois_info TEXT,
                    security_headers TEXT,
                    vulnerabilities TEXT,
                    subdomains TEXT,
                    technology_stack TEXT,
                    certificate_analysis TEXT,
                    FOREIGN KEY (result_id) REFERENCES reconnaissance_results (id)
                )
            ''')
            
            # IP intelligence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    result_id INTEGER NOT NULL,
                    ip_address TEXT,
                    geolocation TEXT,
                    asn_info TEXT,
                    reputation_scores TEXT,
                    passive_dns TEXT,
                    port_correlations TEXT,
                    threat_intelligence TEXT,
                    FOREIGN KEY (result_id) REFERENCES reconnaissance_results (id)
                )
            ''')
            
            # Digital footprint table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS digital_footprint (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    result_id INTEGER NOT NULL,
                    identifier TEXT,
                    identifier_type TEXT,
                    breach_analysis TEXT,
                    social_media TEXT,
                    repositories TEXT,
                    professional_networks TEXT,
                    threat_profile TEXT,
                    FOREIGN KEY (result_id) REFERENCES reconnaissance_results (id)
                )
            ''')
            
            # Threat indicators table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    result_id INTEGER NOT NULL,
                    indicator TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    description TEXT,
                    mitigation TEXT,
                    FOREIGN KEY (result_id) REFERENCES reconnaissance_results (id)
                )
            ''')
            
            # Intelligence summary table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS intelligence_summary (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    result_id INTEGER NOT NULL,
                    executive_summary TEXT,
                    key_findings TEXT,
                    risk_assessment TEXT,
                    recommendations TEXT,
                    intelligence_gaps TEXT,
                    FOREIGN KEY (result_id) REFERENCES reconnaissance_results (id)
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_inventory_id ON reconnaissance_results (inventory_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_input_value ON reconnaissance_results (input_value)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_risk_level ON reconnaissance_results (risk_level)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_surface_score ON reconnaissance_results (attack_surface_score)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vector_type ON attack_vectors (vector_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON attack_vectors (severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_risk_level ON threat_indicators (risk_level)')
            
            conn.commit()
            
        finally:
            conn.close()

    async def _insert_results(self, db_file: Path, results: List[Dict[str, Any]]) -> None:
        """Insert results into SQLite database."""
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        try:
            for result in results:
                # Insert main result
                result_id = await self._insert_main_result(cursor, result)
                
                if result_id:
                    # Insert related data
                    await self._insert_attack_vectors(cursor, result_id, result)
                    await self._insert_initial_access_vectors(cursor, result_id, result)
                    await self._insert_password_spray_candidates(cursor, result_id, result)
                    await self._insert_defensive_recommendations(cursor, result_id, result)
                    await self._insert_domain_intelligence(cursor, result_id, result)
                    await self._insert_ip_intelligence(cursor, result_id, result)
                    await self._insert_digital_footprint(cursor, result_id, result)
                    await self._insert_threat_indicators(cursor, result_id, result)
                    await self._insert_intelligence_summary(cursor, result_id, result)
            
            conn.commit()
            
        finally:
            conn.close()

    async def _insert_main_result(self, cursor, result: Dict[str, Any]) -> Optional[int]:
        """Insert main result record."""
        try:
            attack_surface = result.get('attack_surface', {})
            
            cursor.execute('''
                INSERT INTO reconnaissance_results (
                    inventory_id, input_value, input_type, sensitivity_level,
                    authorized_scan, collection_timestamp, attack_surface_score,
                    risk_level, phishing_risk_level, error_message, raw_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.get('inventory_id', ''),
                result.get('input_value', ''),
                result.get('input_type', ''),
                result.get('sensitivity_level', ''),
                result.get('authorized_scan', False),
                result.get('timestamp', ''),
                attack_surface.get('attack_surface_score', 0),
                attack_surface.get('risk_level', 'unknown'),
                attack_surface.get('phishing_risk_level', 'unknown'),
                result.get('error', ''),
                json.dumps(result, default=str)
            ))
            
            return cursor.lastrowid
            
        except Exception as e:
            self.logger.error(f"Error inserting main result: {e}")
            return None

    async def _insert_attack_vectors(self, cursor, result_id: int, result: Dict[str, Any]) -> None:
        """Insert attack vectors."""
        try:
            attack_vectors = result.get('attack_surface', {}).get('attack_vectors', [])
            
            for vector in attack_vectors:
                mitre_mapping = result.get('attack_surface', {}).get('mitre_attack_mapping', [])
                mitre_info = next(
                    (m for m in mitre_mapping if m.get('attack_vector') == vector.get('name', '')),
                    {}
                )
                
                cursor.execute('''
                    INSERT INTO attack_vectors (
                        result_id, vector_type, name, severity, description,
                        mitigation, mitre_technique, tactic
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result_id,
                    vector.get('vector_type', ''),
                    vector.get('name', ''),
                    vector.get('severity', ''),
                    vector.get('description', ''),
                    vector.get('mitigation', ''),
                    mitre_info.get('mitre_technique', ''),
                    mitre_info.get('tactic', '')
                ))
                
        except Exception as e:
            self.logger.error(f"Error inserting attack vectors: {e}")

    async def _insert_initial_access_vectors(self, cursor, result_id: int, result: Dict[str, Any]) -> None:
        """Insert initial access vectors."""
        try:
            initial_access_vectors = result.get('attack_surface', {}).get('initial_access_vectors', [])
            
            for i, vector in enumerate(initial_access_vectors):
                cursor.execute('''
                    INSERT INTO initial_access_vectors (
                        result_id, vector_name, priority, description
                    ) VALUES (?, ?, ?, ?)
                ''', (
                    result_id,
                    vector,
                    i + 1,
                    f"Initial access vector: {vector}"
                ))
                
        except Exception as e:
            self.logger.error(f"Error inserting initial access vectors: {e}")

    async def _insert_password_spray_candidates(self, cursor, result_id: int, result: Dict[str, Any]) -> None:
        """Insert password spray candidates."""
        try:
            password_candidates = result.get('attack_surface', {}).get('password_spray_candidates', [])
            
            for candidate in password_candidates:
                cursor.execute('''
                    INSERT INTO password_spray_candidates (
                        result_id, source, breach_date, password_patterns, target_accounts
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    result_id,
                    candidate.get('source', ''),
                    candidate.get('breach_date', ''),
                    json.dumps(candidate.get('password_patterns', [])),
                    json.dumps(candidate.get('target_accounts', []))
                ))
                
        except Exception as e:
            self.logger.error(f"Error inserting password spray candidates: {e}")

    async def _insert_defensive_recommendations(self, cursor, result_id: int, result: Dict[str, Any]) -> None:
        """Insert defensive recommendations."""
        try:
            recommendations = result.get('attack_surface', {}).get('defensive_recommendations', [])
            
            for rec in recommendations:
                if isinstance(rec, dict) and 'actions' in rec:
                    for action in rec.get('actions', []):
                        cursor.execute('''
                            INSERT INTO defensive_recommendations (
                                result_id, category, action, timeline, priority, description
                            ) VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            result_id,
                            rec.get('category', ''),
                            action.get('action', ''),
                            action.get('timeline', ''),
                            action.get('priority', ''),
                            action.get('description', '')
                        ))
                
        except Exception as e:
            self.logger.error(f"Error inserting defensive recommendations: {e}")

    async def _insert_domain_intelligence(self, cursor, result_id: int, result: Dict[str, Any]) -> None:
        """Insert domain intelligence data."""
        try:
            correlated_data = result.get('correlated_data', {})
            domain_intel = correlated_data.get('domain_intelligence', {})
            
            if domain_intel:
                cursor.execute('''
                    INSERT INTO domain_intelligence (
                        result_id, domain, dns_records, whois_info, security_headers,
                        vulnerabilities, subdomains, technology_stack, certificate_analysis
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result_id,
                    domain_intel.get('domain', ''),
                    json.dumps(domain_intel.get('dns_records', {})),
                    json.dumps(domain_intel.get('whois_info', {})),
                    json.dumps(domain_intel.get('security_headers', {})),
                    json.dumps(domain_intel.get('vulnerabilities', {})),
                    json.dumps(domain_intel.get('subdomains', [])),
                    json.dumps(domain_intel.get('technology_stack', {})),
                    json.dumps(domain_intel.get('certificate_analysis', {}))
                ))
                
        except Exception as e:
            self.logger.error(f"Error inserting domain intelligence: {e}")

    async def _insert_ip_intelligence(self, cursor, result_id: int, result: Dict[str, Any]) -> None:
        """Insert IP intelligence data."""
        try:
            correlated_data = result.get('correlated_data', {})
            ip_intel = correlated_data.get('ip_intelligence', {})
            
            if ip_intel:
                cursor.execute('''
                    INSERT INTO ip_intelligence (
                        result_id, ip_address, geolocation, asn_info, reputation_scores,
                        passive_dns, port_correlations, threat_intelligence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result_id,
                    ip_intel.get('ip_address', ''),
                    json.dumps(ip_intel.get('geolocation', {})),
                    json.dumps(ip_intel.get('asn_info', {})),
                    json.dumps(ip_intel.get('reputation_scores', {})),
                    json.dumps(ip_intel.get('passive_dns', {})),
                    json.dumps(ip_intel.get('port_correlations', {})),
                    json.dumps(ip_intel.get('threat_intelligence', {}))
                ))
                
        except Exception as e:
            self.logger.error(f"Error inserting IP intelligence: {e}")

    async def _insert_digital_footprint(self, cursor, result_id: int, result: Dict[str, Any]) -> None:
        """Insert digital footprint data."""
        try:
            correlated_data = result.get('correlated_data', {})
            footprint_intel = correlated_data.get('digital_footprint', {})
            
            if footprint_intel:
                cursor.execute('''
                    INSERT INTO digital_footprint (
                        result_id, identifier, identifier_type, breach_analysis,
                        social_media, repositories, professional_networks, threat_profile
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result_id,
                    footprint_intel.get('identifier', ''),
                    footprint_intel.get('identifier_type', ''),
                    json.dumps(footprint_intel.get('breach_analysis', {})),
                    json.dumps(footprint_intel.get('platforms', {})),
                    json.dumps(footprint_intel.get('repositories', [])),
                    json.dumps(footprint_intel.get('professional_networks', {})),
                    json.dumps(footprint_intel.get('threat_profile', {}))
                ))
                
        except Exception as e:
            self.logger.error(f"Error inserting digital footprint: {e}")

    async def _insert_threat_indicators(self, cursor, result_id: int, result: Dict[str, Any]) -> None:
        """Insert threat indicators."""
        try:
            correlated_data = result.get('correlated_data', {})
            threat_indicators = correlated_data.get('threat_indicators', [])
            
            for indicator in threat_indicators:
                cursor.execute('''
                    INSERT INTO threat_indicators (
                        result_id, indicator, risk_level, description, mitigation
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    result_id,
                    indicator.get('indicator', ''),
                    indicator.get('risk_level', ''),
                    indicator.get('description', ''),
                    indicator.get('mitigation', '')
                ))
                
        except Exception as e:
            self.logger.error(f"Error inserting threat indicators: {e}")

    async def _insert_intelligence_summary(self, cursor, result_id: int, result: Dict[str, Any]) -> None:
        """Insert intelligence summary."""
        try:
            correlated_data = result.get('correlated_data', {})
            intelligence_summary = correlated_data.get('intelligence_summary', {})
            
            if intelligence_summary:
                cursor.execute('''
                    INSERT INTO intelligence_summary (
                        result_id, executive_summary, key_findings, risk_assessment,
                        recommendations, intelligence_gaps
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    result_id,
                    intelligence_summary.get('executive_summary', ''),
                    json.dumps(intelligence_summary.get('key_findings', [])),
                    json.dumps(intelligence_summary.get('risk_assessment', {})),
                    json.dumps(intelligence_summary.get('recommendations', [])),
                    json.dumps(intelligence_summary.get('intelligence_gaps', []))
                ))
                
        except Exception as e:
            self.logger.error(f"Error inserting intelligence summary: {e}")

    async def _create_analysis_views(self, db_file: Path) -> None:
        """Create views for common analysis queries."""
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        try:
            # High-risk targets view
            cursor.execute('''
                CREATE VIEW IF NOT EXISTS high_risk_targets AS
                SELECT 
                    inventory_id,
                    input_value,
                    input_type,
                    attack_surface_score,
                    risk_level,
                    phishing_risk_level,
                    collection_timestamp
                FROM reconnaissance_results
                WHERE risk_level IN ('critical', 'high')
                ORDER BY attack_surface_score DESC
            ''')
            
            # Attack vectors summary view
            cursor.execute('''
                CREATE VIEW IF NOT EXISTS attack_vectors_summary AS
                SELECT 
                    r.inventory_id,
                    r.input_value,
                    av.vector_type,
                    av.name,
                    av.severity,
                    av.mitre_technique,
                    av.tactic
                FROM reconnaissance_results r
                JOIN attack_vectors av ON r.id = av.result_id
                ORDER BY r.attack_surface_score DESC, av.severity DESC
            ''')
            
            # Threat indicators summary view
            cursor.execute('''
                CREATE VIEW IF NOT EXISTS threat_indicators_summary AS
                SELECT 
                    r.inventory_id,
                    r.input_value,
                    ti.indicator,
                    ti.risk_level,
                    ti.description
                FROM reconnaissance_results r
                JOIN threat_indicators ti ON r.id = ti.result_id
                ORDER BY r.attack_surface_score DESC, ti.risk_level DESC
            ''')
            
            # Vulnerability summary view
            cursor.execute('''
                CREATE VIEW IF NOT EXISTS vulnerability_summary AS
                SELECT 
                    r.inventory_id,
                    r.input_value,
                    r.attack_surface_score,
                    r.risk_level,
                    json_extract(di.vulnerabilities, '$.vulnerability_count') as total_vulnerabilities,
                    json_extract(di.vulnerabilities, '$.critical_count') as critical_vulnerabilities,
                    json_extract(di.vulnerabilities, '$.high_count') as high_vulnerabilities
                FROM reconnaissance_results r
                LEFT JOIN domain_intelligence di ON r.id = di.result_id
                WHERE json_extract(di.vulnerabilities, '$.vulnerability_count') > 0
                ORDER BY json_extract(di.vulnerabilities, '$.critical_count') DESC
            ''')
            
            # Breach analysis summary view
            cursor.execute('''
                CREATE VIEW IF NOT EXISTS breach_analysis_summary AS
                SELECT 
                    r.inventory_id,
                    r.input_value,
                    r.attack_surface_score,
                    r.risk_level,
                    json_extract(df.breach_analysis, '$.breach_count') as breach_count,
                    json_extract(df.breach_analysis, '$.exposed_data') as exposed_data
                FROM reconnaissance_results r
                LEFT JOIN digital_footprint df ON r.id = df.result_id
                WHERE json_extract(df.breach_analysis, '$.breach_count') > 0
                ORDER BY json_extract(df.breach_analysis, '$.breach_count') DESC
            ''')
            
            conn.commit()
            
        finally:
            conn.close()

    def get_database_path(self) -> Optional[str]:
        """Get the path to the created database file."""
        return str(self.database_path) if hasattr(self, 'database_path') else None
