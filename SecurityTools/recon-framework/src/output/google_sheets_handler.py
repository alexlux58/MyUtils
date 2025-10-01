"""
Google Sheets Handler
Handles output to Google Sheets with enhanced columns for red team operations.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

try:
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    # Handle missing dependencies gracefully
    Credentials = None
    Request = None
    InstalledAppFlow = None
    build = None
    HttpError = None


class GoogleSheetsHandler:
    """Handles output to Google Sheets with enhanced security columns."""

    SCOPES = ['https://www.googleapis.com/auth/spreadsheets']
    SHEET_NAME = 'Reconnaissance Results'

    def __init__(self, config: Dict[str, Any]):
        """Initialize the Google Sheets handler."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.service = None
        self.spreadsheet_id = None

    async def save_results(self, results: List[Dict[str, Any]], output_path: str) -> bool:
        """Save results to Google Sheets."""
        try:
            # Initialize Google Sheets service
            if not await self._initialize_service():
                self.logger.error("Failed to initialize Google Sheets service")
                return False

            # Create or get spreadsheet
            spreadsheet_id = await self._create_or_get_spreadsheet()
            if not spreadsheet_id:
                self.logger.error("Failed to create or get spreadsheet")
                return False

            # Prepare data for sheets
            sheet_data = self._prepare_sheet_data(results)
            
            # Write data to sheets
            await self._write_to_sheets(spreadsheet_id, sheet_data)
            
            self.logger.info(f"Results saved to Google Sheets: {spreadsheet_id}")
            return True

        except Exception as e:
            self.logger.error(f"Error saving to Google Sheets: {e}")
            return False

    async def _initialize_service(self) -> bool:
        """Initialize Google Sheets API service."""
        try:
            if not all([Credentials, Request, InstalledAppFlow, build]):
                self.logger.warning("Google Sheets dependencies not available")
                return False

            creds = None
            token_file = self.config.get('google_sheets', {}).get('token_file', 'token.json')
            credentials_file = self.config.get('google_sheets', {}).get('credentials_file', 'credentials.json')

            # Load existing credentials
            try:
                creds = Credentials.from_authorized_user_file(token_file, self.SCOPES)
            except FileNotFoundError:
                self.logger.info("No existing credentials found")

            # If no valid credentials, get new ones
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    try:
                        flow = InstalledAppFlow.from_client_secrets_file(credentials_file, self.SCOPES)
                        creds = flow.run_local_server(port=0)
                    except FileNotFoundError:
                        self.logger.warning("Google Sheets credentials file not found")
                        return False

                # Save credentials for next run
                with open(token_file, 'w') as token:
                    token.write(creds.to_json())

            self.service = build('sheets', 'v4', credentials=creds)
            return True

        except Exception as e:
            self.logger.error(f"Error initializing Google Sheets service: {e}")
            return False

    async def _create_or_get_spreadsheet(self) -> Optional[str]:
        """Create or get existing spreadsheet."""
        try:
            spreadsheet_id = self.config.get('google_sheets', {}).get('spreadsheet_id')
            
            if spreadsheet_id:
                # Verify spreadsheet exists
                try:
                    self.service.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
                    return spreadsheet_id
                except HttpError:
                    self.logger.warning("Configured spreadsheet not found, creating new one")

            # Create new spreadsheet
            spreadsheet_body = {
                'properties': {
                    'title': f'{self.SHEET_NAME} - {datetime.now().strftime("%Y-%m-%d %H:%M")}'
                },
                'sheets': [{
                    'properties': {
                        'title': 'Reconnaissance Results',
                        'gridProperties': {
                            'rowCount': 1000,
                            'columnCount': 20
                        }
                    }
                }]
            }

            spreadsheet = self.service.spreadsheets().create(
                body=spreadsheet_body,
                fields='spreadsheetId'
            ).execute()

            return spreadsheet.get('spreadsheetId')

        except Exception as e:
            self.logger.error(f"Error creating spreadsheet: {e}")
            return None

    def _prepare_sheet_data(self, results: List[Dict[str, Any]]) -> List[List[str]]:
        """Prepare data for Google Sheets with enhanced columns."""
        # Define enhanced column headers
        headers = [
            'Inventory ID',
            'Input Value',
            'Input Type',
            'Sensitivity Level',
            'Authorized Scan',
            'Collection Timestamp',
            'Attack Surface Score',
            'Risk Level',
            'Initial Access Vectors',
            'Password Spray Candidates',
            'Phishing Risk Level',
            'Defensive Recommendations',
            'MITRE ATT&CK Mapping',
            'Priority Actions',
            'Domain Intelligence',
            'IP Intelligence',
            'Digital Footprint',
            'Threat Indicators',
            'Intelligence Summary',
            'Raw Data'
        ]

        # Prepare data rows
        rows = [headers]
        
        for result in results:
            row = self._extract_row_data(result)
            rows.append(row)

        return rows

    def _extract_row_data(self, result: Dict[str, Any]) -> List[str]:
        """Extract row data from a single result."""
        # Basic information
        inventory_id = result.get('inventory_id', '')
        input_value = result.get('input_value', '')
        input_type = result.get('input_type', '')
        sensitivity_level = result.get('sensitivity_level', '')
        authorized_scan = str(result.get('authorized_scan', False))
        timestamp = result.get('timestamp', '')

        # Attack surface analysis
        attack_surface = result.get('attack_surface', {})
        attack_surface_score = str(attack_surface.get('attack_surface_score', 0))
        risk_level = attack_surface.get('risk_level', 'unknown')
        initial_access_vectors = ', '.join(attack_surface.get('initial_access_vectors', []))
        password_spray_candidates = str(len(attack_surface.get('password_spray_candidates', [])))
        phishing_risk_level = attack_surface.get('phishing_risk_level', 'unknown')
        
        # Defensive recommendations
        defensive_recommendations = []
        for rec in attack_surface.get('defensive_recommendations', []):
            if isinstance(rec, dict) and 'category' in rec:
                defensive_recommendations.append(rec['category'])
        defensive_recommendations_str = '; '.join(defensive_recommendations)

        # MITRE ATT&CK mapping
        mitre_mapping = []
        for mapping in attack_surface.get('mitre_attack_mapping', []):
            mitre_mapping.append(f"{mapping.get('technique_name', '')} ({mapping.get('mitre_technique', '')})")
        mitre_mapping_str = '; '.join(mitre_mapping)

        # Priority actions
        priority_actions = []
        for action in attack_surface.get('priority_actions', []):
            priority_actions.append(action.get('action', ''))
        priority_actions_str = '; '.join(priority_actions)

        # Intelligence data summaries
        domain_intelligence = self._summarize_domain_intelligence(result.get('correlated_data', {}).get('domain_intelligence', {}))
        ip_intelligence = self._summarize_ip_intelligence(result.get('correlated_data', {}).get('ip_intelligence', {}))
        digital_footprint = self._summarize_digital_footprint(result.get('correlated_data', {}).get('digital_footprint', {}))

        # Threat indicators
        threat_indicators = []
        for indicator in result.get('correlated_data', {}).get('threat_indicators', []):
            threat_indicators.append(f"{indicator.get('indicator', '')} ({indicator.get('risk_level', '')})")
        threat_indicators_str = '; '.join(threat_indicators)

        # Intelligence summary
        intelligence_summary = result.get('correlated_data', {}).get('intelligence_summary', {})
        summary_text = intelligence_summary.get('executive_summary', 'No summary available')

        # Raw data (JSON string)
        raw_data = json.dumps(result, default=str, indent=2)

        return [
            inventory_id,
            input_value,
            input_type,
            sensitivity_level,
            authorized_scan,
            timestamp,
            attack_surface_score,
            risk_level,
            initial_access_vectors,
            password_spray_candidates,
            phishing_risk_level,
            defensive_recommendations_str,
            mitre_mapping_str,
            priority_actions_str,
            domain_intelligence,
            ip_intelligence,
            digital_footprint,
            threat_indicators_str,
            summary_text,
            raw_data
        ]

    def _summarize_domain_intelligence(self, domain_data: Dict[str, Any]) -> str:
        """Summarize domain intelligence data."""
        if not domain_data:
            return "No domain intelligence data"
        
        summary_parts = []
        
        # DNS records
        dns_records = domain_data.get('dns_records', {})
        if dns_records:
            record_count = sum(len(records) for records in dns_records.values())
            summary_parts.append(f"DNS Records: {record_count}")
        
        # Security headers
        security_headers = domain_data.get('security_headers', {})
        if security_headers:
            missing_headers = security_headers.get('missing_headers', [])
            if missing_headers:
                summary_parts.append(f"Missing Headers: {len(missing_headers)}")
            else:
                summary_parts.append("Security Headers: Complete")
        
        # Vulnerabilities
        vulnerabilities = domain_data.get('vulnerabilities', {})
        if vulnerabilities:
            vuln_count = vulnerabilities.get('vulnerability_count', 0)
            if vuln_count > 0:
                summary_parts.append(f"Vulnerabilities: {vuln_count}")
        
        # Subdomains
        subdomains = domain_data.get('subdomains', [])
        if subdomains:
            summary_parts.append(f"Subdomains: {len(subdomains)}")
        
        return "; ".join(summary_parts) if summary_parts else "No significant findings"

    def _summarize_ip_intelligence(self, ip_data: Dict[str, Any]) -> str:
        """Summarize IP intelligence data."""
        if not ip_data:
            return "No IP intelligence data"
        
        summary_parts = []
        
        # Geolocation
        geolocation = ip_data.get('geolocation', {})
        if geolocation:
            country = geolocation.get('country', 'Unknown')
            city = geolocation.get('city', 'Unknown')
            summary_parts.append(f"Location: {city}, {country}")
        
        # ASN information
        asn_info = ip_data.get('asn_info', {})
        if asn_info:
            asn_name = asn_info.get('asn_name', 'Unknown')
            summary_parts.append(f"ASN: {asn_name}")
        
        # Reputation
        reputation_scores = ip_data.get('reputation_scores', {})
        if reputation_scores:
            malicious_count = sum(
                score.get('malicious_count', 0) 
                for score in reputation_scores.values()
            )
            if malicious_count > 0:
                summary_parts.append(f"Malicious Indicators: {malicious_count}")
            else:
                summary_parts.append("Reputation: Clean")
        
        return "; ".join(summary_parts) if summary_parts else "No significant findings"

    def _summarize_digital_footprint(self, footprint_data: Dict[str, Any]) -> str:
        """Summarize digital footprint data."""
        if not footprint_data:
            return "No digital footprint data"
        
        summary_parts = []
        
        # Breach analysis
        breach_analysis = footprint_data.get('breach_analysis', {})
        if breach_analysis:
            breach_count = breach_analysis.get('breach_count', 0)
            if breach_count > 0:
                summary_parts.append(f"Data Breaches: {breach_count}")
            else:
                summary_parts.append("Breach Status: Clean")
        
        # Social media presence
        platforms = footprint_data.get('platforms', {})
        if platforms:
            active_platforms = len([p for p in platforms.values() if p.get('exists')])
            summary_parts.append(f"Social Platforms: {active_platforms}")
        
        # Code repositories
        repositories = footprint_data.get('repositories', [])
        if repositories:
            summary_parts.append(f"Code Repositories: {len(repositories)}")
        
        return "; ".join(summary_parts) if summary_parts else "No significant findings"

    async def _write_to_sheets(self, spreadsheet_id: str, data: List[List[str]]) -> bool:
        """Write data to Google Sheets."""
        try:
            # Clear existing data
            range_name = 'Reconnaissance Results!A1:Z1000'
            self.service.spreadsheets().values().clear(
                spreadsheetId=spreadsheet_id,
                range=range_name
            ).execute()

            # Write new data
            body = {
                'values': data
            }
            
            result = self.service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range='Reconnaissance Results!A1',
                valueInputOption='RAW',
                body=body
            ).execute()

            # Format headers
            await self._format_headers(spreadsheet_id)

            self.logger.info(f"Updated {result.get('updatedCells', 0)} cells in Google Sheets")
            return True

        except Exception as e:
            self.logger.error(f"Error writing to Google Sheets: {e}")
            return False

    async def _format_headers(self, spreadsheet_id: str) -> None:
        """Format header row in Google Sheets."""
        try:
            # Format header row (row 1)
            requests = [{
                'repeatCell': {
                    'range': {
                        'sheetId': 0,
                        'startRowIndex': 0,
                        'endRowIndex': 1
                    },
                    'cell': {
                        'userEnteredFormat': {
                            'backgroundColor': {
                                'red': 0.2,
                                'green': 0.4,
                                'blue': 0.8
                            },
                            'textFormat': {
                                'foregroundColor': {
                                    'red': 1.0,
                                    'green': 1.0,
                                    'blue': 1.0
                                },
                                'bold': True
                            }
                        }
                    },
                    'fields': 'userEnteredFormat(backgroundColor,textFormat)'
                }
            }]

            self.service.spreadsheets().batchUpdate(
                spreadsheetId=spreadsheet_id,
                body={'requests': requests}
            ).execute()

        except Exception as e:
            self.logger.warning(f"Error formatting headers: {e}")

    def get_spreadsheet_url(self) -> Optional[str]:
        """Get the URL of the created spreadsheet."""
        if self.spreadsheet_id:
            return f"https://docs.google.com/spreadsheets/d/{self.spreadsheet_id}"
        return None
