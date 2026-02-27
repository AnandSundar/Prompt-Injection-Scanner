export interface ScanRequest {
    prompt: string;
}

export interface PatternMatch {
    pattern: string;
    description: string;
    confidence: number;
    position?: {
        start: number;
        end: number;
    };
}

export interface ScanResponse {
    id: string;
    prompt: string;
    verdict: Verdict;
    score: number;
    patternMatches: PatternMatch[];
    recommendations: string[];
    timestamp: string;
}

export type Verdict = "safe" | "danger" | "warning" | "unknown";

export interface HistoryItem {
    id: string;
    prompt: string;
    verdict: Verdict;
    score: number;
    timestamp: Date;
    patternMatches?: PatternMatch[];
    recommendations?: string[];
}

export interface Pattern {
    id: string;
    name: string;
    description: string;
    risk: "high" | "medium" | "low";
    example: string;
    regex?: string;
}
