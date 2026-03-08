import { useCallback } from "react";
import { useStore } from "@/store/useStore";
import { useHistoryStore } from "@/store/useHistoryStore";
import { api } from "@/lib/api";
import { ScanRequest } from "@/types/api.types";

export function useScanner() {
    const {
        isScanning,
        scanStage,
        currentPrompt,
        lastResult,
        setIsScanning,
        setScanStage,
        setCurrentPrompt,
        setLastResult,
    } = useStore();

    // Use history store for persisting scan history
    const addScan = useHistoryStore((state) => state.addScan);

    const scan = useCallback(async (prompt: string) => {
        if (!prompt.trim()) return;

        console.log("[DEBUG] scan() called with prompt:", prompt);

        setCurrentPrompt(prompt);
        setIsScanning(true);
        setScanStage("analyzing");
        setLastResult(null);

        try {
            setScanStage("regex");

            const request: ScanRequest = { prompt };
            const response = await api.scan(request);

            setScanStage("llm");

            // Simulate delay for scoring
            await new Promise((resolve) => setTimeout(resolve, 500));

            setScanStage("complete");
            setLastResult(response);

            // Add to history - use the correct store that HistoryPage reads from
            // Map API response fields to what the history store expects
            // Backend returns: prompt_preview, final_verdict, regex_score, llm_result
            addScan({
                prompt: response.prompt_preview,
                verdict: response.final_verdict as "safe" | "warning" | "danger" | "unknown",
                score: Math.round((response.regex_score?.risk_score || 0) * 100),
                patternMatches: response.regex_score?.matched_categories?.map((cat: string) => ({
                    category: cat,
                    description: `Detected ${cat} pattern`,
                    matched_text: prompt,
                    severity: (response.regex_score?.risk_score || 0) > 0.7 ? "high" : (response.regex_score?.risk_score || 0) > 0.4 ? "medium" : "low"
                })),
                llmAnalysis: response.llm_result ? {
                    verdict: response.llm_result.verdict || response.final_verdict,
                    confidence: response.llm_result.confidence || 0,
                    payload_type: response.llm_result.payload_type || "unknown",
                    reasoning: response.llm_result.reasoning || ""
                } : undefined
            });

        } catch (error) {
            console.error("[DEBUG] Scan failed:", error);
            setScanStage("idle");
        } finally {
            setIsScanning(false);
        }
    }, [
        setCurrentPrompt,
        setIsScanning,
        setScanStage,
        setLastResult,
        addScan,
    ]);

    const reset = useCallback(() => {
        setCurrentPrompt("");
        setLastResult(null);
        setScanStage("idle");
    }, [setCurrentPrompt, setLastResult, setScanStage]);

    return {
        isScanning,
        scanStage,
        currentPrompt,
        lastResult,
        scan,
        reset,
    };
}
