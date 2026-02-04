#!/usr/bin/env node

/**
 * SkillGuard CLI Entry Point
 * Security scanner for AI Agent Skills
 */

import { Command } from 'commander';
import * as path from 'path';
import { scan } from './scanner';
import { showLogo, createSpinner, showReport, showError, showInfo } from './ui';
import { initializeConfig } from './config';

const program = new Command();

program
  .name('skillguard')
  .description(
    '🛡️  Security scanner for AI Agent Skills (Multi-language: JS/TS/Python/Java/Go/Ruby/PHP/C/C++/Rust)',
  )
  .version('1.1.1');

program
  .command('scan <directory>')
  .description('Scan a directory for security vulnerabilities')
  .option('-q, --quiet', 'Suppress the ASCII logo')
  .option('-j, --json', 'Output results as JSON')
  .option('-c, --config <path>', 'Path to custom configuration file')
  .action(
    async (directory: string, options: { quiet?: boolean; json?: boolean; config?: string }) => {
      try {
        // Initialize configuration
        initializeConfig(options.config, directory);

        // Show logo unless quiet mode
        if (!options.quiet && !options.json) {
          showLogo();
        }

        const targetPath = path.resolve(directory);

        // Create spinner
        const spinner = createSpinner(`Scanning ${targetPath}...`);

        if (!options.json) {
          spinner.start();
        }

        // Run the scan
        const result = await scan(targetPath);

        if (options.json) {
          // JSON output mode
          console.log(JSON.stringify(result, null, 2));
        } else {
          spinner.succeed('Scan complete!');

          // Show the report
          showReport(result, targetPath);
        }

        // Exit with appropriate code
        if (result.riskLevel === 'critical' || result.riskLevel === 'high') {
          process.exit(1);
        }
      } catch (error) {
        if (options.json) {
          console.log(JSON.stringify({ error: (error as Error).message }, null, 2));
        } else {
          showError((error as Error).message);
        }
        process.exit(1);
      }
    },
  );

program
  .command('version')
  .description('Show version information')
  .action(() => {
    showLogo();
    showInfo('SkillGuard v1.0.0');
  });

// Parse arguments
program.parse();

// Show help if no command provided
if (!process.argv.slice(2).length) {
  showLogo();
  program.outputHelp();
}
