"""
main.py: Orchestrator for the AndroidServiceFuzzer framework.

This script ties together all modules, parses CLI args, and runs the fuzzing loop.
It supports overriding config values via CLI and logs progress.
"""

import argparse
import logging
import random
from typing import List
from config import ConfigManager
from generator import InputGenerator
from executor import Executor
from monitor import Monitor
from analyzer import Analyzer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AndroidServiceFuzzer Framework - PMS Fuzzer for Android 13")
    parser.add_argument('--config', default='./config/config.yaml', help='Path to config YAML file')
    parser.add_argument('--iterations', type=int, help='Override number of iterations')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help='Set logging level')
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)
    try:
        
        config = ConfigManager(args.config)
        if args.iterations is not None:
            config.update('iterations', args.iterations)
        executor = Executor(config)
        monitor = Monitor(config, executor)
        analyzer = Analyzer(config, monitor)
        generator = InputGenerator(config)
        logger.info("[*] Discovering PMS transactions")
        txs: List[int] = executor.discover_transactions()
        if not txs:
            logger.error("No transactions discovered. Exiting.")
            return
        logger.info(f"[+] {len(txs)} live transactions")
        iterations: int = config.get_int('iterations')
        for i in range(iterations):
            if generator.seed_corpus and random.random() < 0.5:
                seed = random.choice(generator.seed_corpus)
                tx = seed['tx']
                args = generator.mutate(seed)['args']  # mutate returns (tx, args), but tx is same
            else:
                tx = random.choice(txs)
                args = generator.generate_random(tx)

            pkg: str = generator.rand_pkg()
            before_pkg = monitor.snapshot_package(pkg)
            before_global = monitor.snapshot_global_state()
            monitor.clear_logs()
            executor.run_case(tx, args)
            alive = monitor.system_server_alive()
            novelty, logs = monitor.collect_logs()
            after_pkg = monitor.snapshot_package(pkg)
            after_global = monitor.snapshot_global_state()
            score, case = analyzer.analyze_case(
                tx, pkg, args, before_pkg, after_pkg, before_global, after_global, alive, novelty, logs
            )
            
            generator.add_seed({'tx': tx, 'args': args}, score)
            if i % 100 == 0:
                logger.info(f"[+] Completed iteration {i}/{iterations}")

        logger.info("Fuzzing completed")
    except Exception as e:
        logger.critical(f"Fatal error in main loop: {e}", exc_info=True)

if __name__ == "__main__":
    main()