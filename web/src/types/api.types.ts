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

export interface RegexScore {
    risk_score: number;
    risk_level: string;
    matched_categories: string[];
    should_escalate_to_llm: boolean;
}

export interface LLMResult {
    verdict: string;
    confidence: number;
    payload_type: string;
    reasoning: string;
}

// Actual API response from backend
export interface ScanResponse {
    prompt_preview: string;
    regex_score: RegexScore;
    llm_result: LLMResult | null;
    final_verdict: string;
    scan_duration_ms: number;
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
