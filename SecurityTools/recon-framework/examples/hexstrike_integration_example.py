#!/usr/bin/env python3
"""
HexStrike Integration Example
Demonstrates how to use the reconnaissance framework with HexStrike AI integration.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def main():
    """Main example function demonstrating HexStrike integration."""
    
    # Example 1: Basic Integration Setup
    print("🔧 Setting up HexStrike Integration...")
    
    # Load configuration with HexStrike enabled
    config = {
        'integrations': {
            'hexstrike': {
                'enabled': True,
                'server_url': 'http://localhost:8888',
                'api_key': 'your_hexstrike_api_key_here',
                'timeout': 30,
                'auto_sync': True,
                'workflow_creation': True
            }
        },
        'rate_limits': {
            'default': 1.0,
            'hexstrike': 0.5
        },
        'output': {
            'google_sheets': {
                'enabled': False
            },
            'jsonl': {
                'enabled': True,
                'output_dir': 'results/'
            },
            'sqlite': {
                'enabled': True,
                'db_path': 'results/recon.db'
            }
        }
    }
    
    # Example 2: Initialize Reconnaissance Engine with Integration
    print("🚀 Initializing Reconnaissance Engine...")
    
    try:
        from src.core.recon_engine import ReconEngine
        from src.utils.opsec_validator import OpSecValidator
        
        # Initialize OPSEC validator
        opsec_config = {
            'restricted_domains': ['*.gov', '*.mil'],
            'restricted_ips': ['10.0.0.0/8', '192.168.0.0/16'],
            'sensitive_keywords': ['classified', 'secret']
        }
        opsec_validator = OpSecValidator(opsec_config)
        
        # Initialize reconnaissance engine
        engine = ReconEngine(
            config=config,
            opsec_validator=opsec_validator,
            rate_limit=1.0,
            dry_run=False
        )
        
        print("✅ Reconnaissance Engine initialized successfully")
        
    except Exception as e:
        print(f"❌ Failed to initialize engine: {e}")
        return
    
    # Example 3: Check Integration Status
    print("🔍 Checking Integration Status...")
    
    try:
        status = await engine.get_integration_status()
        print(f"Integration Status: {json.dumps(status, indent=2)}")
        
        # Test integrations
        test_results = await engine.test_integrations()
        print(f"Integration Tests: {json.dumps(test_results, indent=2)}")
        
    except Exception as e:
        print(f"⚠️  Integration check failed: {e}")
    
    # Example 4: Create Sample Inventory
    print("📋 Creating Sample Inventory...")
    
    sample_inventory = [
        {
            'inventory_id': '1',
            'input_value': 'example.com',
            'input_type': 'domain',
            'notes': 'Test domain for integration',
            'sensitivity_level': 'public',
            'authorized_scan': True
        },
        {
            'inventory_id': '2',
            'input_value': '192.168.1.1',
            'input_type': 'ip',
            'notes': 'Test IP for integration',
            'sensitivity_level': 'low',
            'authorized_scan': True
        }
    ]
    
    # Save sample inventory
    inventory_path = Path('sample_inventory.csv')
    with open(inventory_path, 'w') as f:
        f.write('inventory_id,input_value,input_type,notes,sensitivity_level,authorized_scan\n')
        for item in sample_inventory:
            f.write(f"{item['inventory_id']},{item['input_value']},{item['input_type']},{item['notes']},{item['sensitivity_level']},{item['authorized_scan']}\n")
    
    print(f"✅ Sample inventory created: {inventory_path}")
    
    # Example 5: Run Reconnaissance with Integration
    print("🔍 Running Reconnaissance with HexStrike Integration...")
    
    try:
        # Load inventory
        inventory = await engine.load_inventory(inventory_path)
        print(f"📊 Loaded {len(inventory)} targets from inventory")
        
        # Process each target
        results = []
        for target in inventory:
            print(f"🎯 Processing target: {target['input_value']}")
            
            # Run reconnaissance
            result = await engine.tiered_recon(
                target_data=target,
                sensitivity_level=target['sensitivity_level'],
                authorized_scan=target['authorized_scan'],
                dry_run=False
            )
            
            results.append(result)
            print(f"✅ Completed reconnaissance for {target['input_value']}")
        
        # Example 6: Sync with HexStrike
        print("🔄 Syncing Results with HexStrike...")
        
        try:
            sync_result = await engine.sync_with_hexstrike(results)
            print(f"Sync Result: {json.dumps(sync_result, indent=2)}")
            
            # Get HexStrike recommendations
            for result in results:
                target = result['input_value']
                recommendations = await engine.get_hexstrike_recommendations(
                    target, result
                )
                if recommendations:
                    print(f"🎯 HexStrike recommendations for {target}: {len(recommendations)} tools")
                    for rec in recommendations[:3]:  # Show first 3 recommendations
                        print(f"  - {rec.get('tool', 'Unknown')}: {rec.get('reason', 'No reason provided')}")
                
        except Exception as e:
            print(f"⚠️  HexStrike sync failed: {e}")
        
        # Example 7: Create HexStrike Workflow
        print("🛠️  Creating HexStrike Workflow...")
        
        try:
            workflow_result = await engine.execute_hexstrike_workflow(results)
            print(f"Workflow Result: {json.dumps(workflow_result, indent=2)}")
            
        except Exception as e:
            print(f"⚠️  Workflow creation failed: {e}")
        
        # Example 8: Generate Reports
        print("📊 Generating Reports...")
        
        try:
            # Generate executive summary
            summary = engine.generate_executive_summary(results)
            print(f"Executive Summary: {json.dumps(summary, indent=2)}")
            
            # Save results
            output_dir = Path('results')
            output_dir.mkdir(exist_ok=True)
            
            # Save to JSONL
            jsonl_path = output_dir / 'recon_results.jsonl'
            with open(jsonl_path, 'w') as f:
                for result in results:
                    f.write(json.dumps(result) + '\n')
            
            print(f"✅ Results saved to: {jsonl_path}")
            
        except Exception as e:
            print(f"⚠️  Report generation failed: {e}")
    
    except Exception as e:
        print(f"❌ Reconnaissance failed: {e}")
    
    # Example 9: Integration Best Practices
    print("\n📚 Integration Best Practices:")
    print("1. Always test integration before production use")
    print("2. Monitor HexStrike server health and availability")
    print("3. Use appropriate rate limiting for both tools")
    print("4. Implement proper error handling and fallbacks")
    print("5. Log all integration activities for audit purposes")
    print("6. Regularly update integration configurations")
    print("7. Test with different sensitivity levels and authorization states")
    
    # Cleanup
    if inventory_path.exists():
        inventory_path.unlink()
        print(f"🧹 Cleaned up sample inventory: {inventory_path}")


if __name__ == "__main__":
    print("🚀 HexStrike Integration Example")
    print("=" * 50)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Example interrupted by user")
    except Exception as e:
        print(f"\n❌ Example failed: {e}")
    
    print("\n✅ Example completed!")
