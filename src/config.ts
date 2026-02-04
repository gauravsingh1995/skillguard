/**
 * SkillGuard Configuration System
 * Allows users to customize risk evaluation and severity levels
 */

import * as fs from 'fs';
import * as path from 'path';
import { RiskSeverity, Language } from './types';

export interface PatternOverride {
  pattern: string;
  severity: RiskSeverity;
  enabled?: boolean;
  description?: string;
}

export interface LanguageConfig {
  enabled?: boolean;
  patternOverrides?: PatternOverride[];
}

export interface RiskThresholds {
  safe: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface SeverityWeights {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface SkillGuardConfig {
  // Risk evaluation settings
  riskThresholds?: Partial<RiskThresholds>;
  severityWeights?: Partial<SeverityWeights>;

  // Language-specific settings
  languages?: {
    [key in Language]?: LanguageConfig;
  };

  // Global pattern overrides (applies to all languages)
  globalPatternOverrides?: PatternOverride[];

  // Scanner settings
  excludePatterns?: string[];
  includePatterns?: string[];
  maxFiles?: number;

  // Dependency scanning
  dependencyScanning?: {
    enabled?: boolean;
    npmAudit?: boolean;
    osvScanning?: boolean;
  };
}

// Default configuration
export const DEFAULT_CONFIG: SkillGuardConfig = {
  riskThresholds: {
    safe: 0,
    low: 1,
    medium: 21,
    high: 51,
    critical: 76,
  },
  severityWeights: {
    critical: 50,
    high: 30,
    medium: 20,
    low: 10,
  },
  languages: {},
  globalPatternOverrides: [],
  excludePatterns: [
    'node_modules',
    'dist',
    'build',
    'target',
    'vendor',
    '__pycache__',
    '.git',
    'venv',
    'env',
  ],
  dependencyScanning: {
    enabled: true,
    npmAudit: true,
    osvScanning: true,
  },
};

/**
 * Configuration loader class
 */
export class ConfigLoader {
  private config: SkillGuardConfig;

  constructor() {
    this.config = { ...DEFAULT_CONFIG };
  }

  /**
   * Load configuration from file
   */
  loadFromFile(configPath: string): SkillGuardConfig {
    try {
      if (!fs.existsSync(configPath)) {
        return this.config;
      }

      const fileContent = fs.readFileSync(configPath, 'utf-8');
      const userConfig = JSON.parse(fileContent);

      this.config = this.mergeConfig(DEFAULT_CONFIG, userConfig);
      return this.config;
    } catch (error) {
      console.warn(`Warning: Could not load config from ${configPath}:`, (error as Error).message);
      return this.config;
    }
  }

  /**
   * Auto-discover and load configuration file
   */
  loadConfig(startDir: string = process.cwd()): SkillGuardConfig {
    const configFiles = [
      '.skillguardrc.json',
      '.skillguardrc',
      'skillguard.config.json',
      'skillguard.config.js',
    ];

    // Look for config file in current directory and parent directories
    let currentDir = startDir;
    const root = path.parse(currentDir).root;

    while (currentDir !== root) {
      for (const configFile of configFiles) {
        const configPath = path.join(currentDir, configFile);
        if (fs.existsSync(configPath)) {
          return this.loadFromFile(configPath);
        }
      }
      currentDir = path.dirname(currentDir);
    }

    return this.config;
  }

  /**
   * Merge user config with default config
   */
  private mergeConfig(
    defaultConfig: SkillGuardConfig,
    userConfig: Partial<SkillGuardConfig>,
  ): SkillGuardConfig {
    return {
      riskThresholds: {
        ...defaultConfig.riskThresholds,
        ...userConfig.riskThresholds,
      },
      severityWeights: {
        ...defaultConfig.severityWeights,
        ...userConfig.severityWeights,
      },
      languages: {
        ...defaultConfig.languages,
        ...userConfig.languages,
      },
      globalPatternOverrides: [
        ...(defaultConfig.globalPatternOverrides || []),
        ...(userConfig.globalPatternOverrides || []),
      ],
      excludePatterns: userConfig.excludePatterns || defaultConfig.excludePatterns,
      includePatterns: userConfig.includePatterns || defaultConfig.includePatterns,
      maxFiles: userConfig.maxFiles || defaultConfig.maxFiles,
      dependencyScanning: {
        ...defaultConfig.dependencyScanning,
        ...userConfig.dependencyScanning,
      },
    };
  }

  /**
   * Get current configuration
   */
  getConfig(): SkillGuardConfig {
    return this.config;
  }

  /**
   * Get severity for a specific pattern
   */
  getPatternSeverity(
    patternName: string,
    defaultSeverity: RiskSeverity,
    language?: Language,
  ): RiskSeverity {
    // Check language-specific overrides first
    if (language && this.config.languages?.[language]?.patternOverrides) {
      const languageOverride = this.config.languages[language].patternOverrides?.find(
        (o) => o.pattern === patternName,
      );
      if (languageOverride) {
        return languageOverride.severity;
      }
    }

    // Check global overrides
    const globalOverride = this.config.globalPatternOverrides?.find(
      (o) => o.pattern === patternName,
    );
    if (globalOverride) {
      return globalOverride.severity;
    }

    return defaultSeverity;
  }

  /**
   * Check if a pattern is enabled
   */
  isPatternEnabled(patternName: string, language?: Language): boolean {
    // Check language-specific overrides first
    if (language && this.config.languages?.[language]?.patternOverrides) {
      const languageOverride = this.config.languages[language].patternOverrides?.find(
        (o) => o.pattern === patternName,
      );
      if (languageOverride && languageOverride.enabled !== undefined) {
        return languageOverride.enabled;
      }
    }

    // Check global overrides
    const globalOverride = this.config.globalPatternOverrides?.find(
      (o) => o.pattern === patternName,
    );
    if (globalOverride && globalOverride.enabled !== undefined) {
      return globalOverride.enabled;
    }

    return true; // Enabled by default
  }

  /**
   * Check if a language is enabled
   */
  isLanguageEnabled(language: Language): boolean {
    return this.config.languages?.[language]?.enabled !== false;
  }

  /**
   * Get severity weight
   */
  getSeverityWeight(severity: RiskSeverity): number {
    return (
      this.config.severityWeights?.[severity] ?? DEFAULT_CONFIG.severityWeights![severity] ?? 10
    );
  }

  /**
   * Get risk level based on score
   */
  getRiskLevel(score: number): 'safe' | 'low' | 'medium' | 'high' | 'critical' {
    const thresholds = this.config.riskThresholds!;

    if (score >= thresholds.critical!) return 'critical';
    if (score >= thresholds.high!) return 'high';
    if (score >= thresholds.medium!) return 'medium';
    if (score >= thresholds.low!) return 'low';
    return 'safe';
  }
}

// Singleton instance
let configLoader: ConfigLoader | null = null;

/**
 * Get or create the config loader instance
 */
export function getConfigLoader(reload: boolean = false): ConfigLoader {
  if (!configLoader || reload) {
    configLoader = new ConfigLoader();
  }
  return configLoader;
}

/**
 * Initialize configuration with optional path
 */
export function initializeConfig(configPath?: string, startDir?: string): SkillGuardConfig {
  const loader = getConfigLoader(true);

  if (configPath) {
    return loader.loadFromFile(configPath);
  }

  return loader.loadConfig(startDir);
}
