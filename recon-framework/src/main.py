#!/usr/bin/env python3
"""
Enhanced Security Reconnaissance & OSINT Automation Framework
Main entry point for the reconnaissance system.
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from src.core.recon_engine import ReconEngine
from src.utils.logger import setup_logging
from src.utils.config_manager import ConfigManager
from src.utils.opsec_validator import OpSecValidator


async def main():
    """Main entry point for the reconnaissance framework."""
    parser = argparse.ArgumentParser(
        description="Enhanced Security Reconnaissance & OSINT Automation Framework"
    )
    parser.add_argument(
        "--inventory", 
        required=True, 
        help="Path to inventory CSV file"
    )
    parser.add_argument(
        "--output", 
        default="./results", 
        help="Output directory for results"
    )
    parser.add_argument(
        "--config", 
        default="./config", 
        help="Configuration directory"
    )
    parser.add_argument(
        "--sensitivity", 
        choices=["public", "low", "med", "high"], 
        default="med",
        help="Default sensitivity level for targets"
    )
    parser.add_argument(
        "--dry-run", 
        action="store_true", 
        help="Perform dry run without making external requests"
    )
    parser.add_argument(
        "--verbose", 
        action="store_true", 
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--rate-limit", 
        type=float, 
        default=1.0,
        help="Rate limit in requests per second"
    )

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)
    logger = logging.getLogger(__name__)

    try:
        # Initialize configuration
        config_manager = ConfigManager(args.config)
        config = config_manager.load_config()

        # Initialize OPSEC validator
        opsec_validator = OpSecValidator(config)

        # Initialize reconnaissance engine
        recon_engine = ReconEngine(
            config=config,
            opsec_validator=opsec_validator,
            rate_limit=args.rate_limit,
            dry_run=args.dry_run
        )

        # Validate inventory file
        inventory_path = Path(args.inventory)
        if not inventory_path.exists():
            logger.error(f"Inventory file not found: {inventory_path}")
            sys.exit(1)

        # Create output directory
        output_path = Path(args.output)
        output_path.mkdir(parents=True, exist_ok=True)

        logger.info("Starting reconnaissance framework...")
        logger.info(f"Inventory: {inventory_path}")
        logger.info(f"Output: {output_path}")
        logger.info(f"Sensitivity: {args.sensitivity}")
        logger.info(f"Dry run: {args.dry_run}")

        # Load and validate inventory
        inventory = await recon_engine.load_inventory(inventory_path)
        logger.info(f"Loaded {len(inventory)} targets from inventory")

        # Perform reconnaissance
        results = await recon_engine.execute_reconnaissance(
            inventory=inventory,
            output_path=output_path,
            default_sensitivity=args.sensitivity
        )

        logger.info(f"Reconnaissance completed. Results saved to: {output_path}")
        logger.info(f"Processed {len(results)} targets successfully")

        # Generate summary report
        await recon_engine.generate_summary_report(results, output_path)

    except KeyboardInterrupt:
        logger.info("Reconnaissance interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
