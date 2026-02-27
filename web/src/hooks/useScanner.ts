import { useCallback } from "react";
import { useStore } from "@/store/useStore";
import { api } from "@/lib/api";
import { ScanRequest, HistoryItem } from "@/types/api.types";

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
        addToHistory,
    } = useStore();

    const scan = useCallback(async (prompt: string) => {
        if (!prompt.trim()) return;

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

            // Add to history
            const historyItem: HistoryItem = {
                id: response.id,
                prompt: response.prompt,
                verdict: response.verdict,
                score: response.score,
                timestamp: new Date(response.timestamp),
                patternMatches: response.patternMatches,
                recommendations: response.recommendations,
            };
            addToHistory(historyItem);

        } catch (error) {
            console.error("Scan failed:", error);
            setScanStage("idle");
        } finally {
            setIsScanning(false);
        }
    }, [
        setCurrentPrompt,
        setIsScanning,
        setScanStage,
        setLastResult,
        addToHistory,
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
