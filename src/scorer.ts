/**
 * SkillGuard Risk Scorer
 * Calculates overall risk score based on findings
 */

import { Finding, DependencyFinding, ScanResult } from './types';
import { getConfigLoader } from './config';

/**
 * Risk score weights by category (used when config not available)
 */
const DEFAULT_CATEGORY_WEIGHTS: Record<string, number> = {
  'Shell Execution': 50,
  'Code Injection': 50,
  'File System Write': 30,
  'File System Delete': 30,
  'File System Permissions': 25,
  'Network Access': 20,
  'Environment Access': 10,
  'Buffer Overflow': 50,
  'Memory Management': 30,
  Deserialization: 30,
  'Unsafe Operations': 40,
  Reflection: 30,
  'Dynamic Method Call': 30,
};

/**
 * Calculate risk score from findings
 * Score ranges from 0 (safe) to 100 (critical)
 */
export function calculateRiskScore(
  codeFindings: Finding[],
  dependencyFindings: DependencyFinding[],
): number {
  let score = 0;
  const configLoader = getConfigLoader();

  // Score code findings
  for (const finding of codeFindings) {
    // Get severity weight from config
    const severityWeight = configLoader.getSeverityWeight(finding.severity);

    // Use category weight if available, otherwise use severity weight
    const categoryWeight = DEFAULT_CATEGORY_WEIGHTS[finding.category];

    // Take the higher of the two weights
    score += Math.max(categoryWeight || 0, severityWeight);
  }

  // Score dependency findings
  for (const finding of dependencyFindings) {
    // Use configurable severity weights for dependencies too
    score += configLoader.getSeverityWeight(finding.severity);
  }

  // Cap the score at 100
  return Math.min(score, 100);
}

/**
 * Determine risk level from score using configurable thresholds
 */
export function getRiskLevel(score: number): ScanResult['riskLevel'] {
  const configLoader = getConfigLoader();
  return configLoader.getRiskLevel(score);
}

/**
 * Get risk statistics for reporting
 */
export function getRiskStats(
  codeFindings: Finding[],
  dependencyFindings: DependencyFinding[],
): {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
} {
  const counts = {
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
  };

  for (const finding of codeFindings) {
    switch (finding.severity) {
      case 'critical':
        counts.criticalCount++;
        break;
      case 'high':
        counts.highCount++;
        break;
      case 'medium':
        counts.mediumCount++;
        break;
      case 'low':
        counts.lowCount++;
        break;
    }
  }

  for (const finding of dependencyFindings) {
    switch (finding.severity) {
      case 'critical':
        counts.criticalCount++;
        break;
      case 'high':
        counts.highCount++;
        break;
      case 'medium':
        counts.mediumCount++;
        break;
      case 'low':
        counts.lowCount++;
        break;
    }
  }

  return counts;
}
