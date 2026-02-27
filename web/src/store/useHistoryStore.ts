import { create } from "zustand";
import { persist } from "zustand/middleware";
import { formatDistanceToNow } from "date-fns";

export type Verdict = "safe" | "warning" | "danger" | "unknown";

export interface ScanRecord {
    id: string;
    prompt: string;
    verdict: Verdict;
    score: number;
    timestamp: number;
    patternMatches?: {
        category: string;
        description: string;
        matched_text: string;
        severity: string;
    }[];
    llmAnalysis?: {
        verdict: string;
        confidence: number;
        payload_type: string;
        reasoning: string;
    };
}

interface HistoryState {
    scans: ScanRecord[];
    addScan: (scan: Omit<ScanRecord, "id" | "timestamp">) => void;
    removeScan: (id: string) => void;
    clearAll: () => void;
    getScanById: (id: string) => ScanRecord | undefined;
}

export const useHistoryStore = create<HistoryState>()(
    persist(
        (set, get) => ({
            scans: [],

            addScan: (scan) => {
                const newScan: ScanRecord = {
                    ...scan,
                    id: crypto.randomUUID(),
                    timestamp: Date.now(),
                };
                set((state) => ({
                    scans: [newScan, ...state.scans].slice(0, 100), // Keep last 100
                }));
            },

            removeScan: (id) => {
                set((state) => ({
                    scans: state.scans.filter((scan) => scan.id !== id),
                }));
            },

            clearAll: () => {
                set({ scans: [] });
            },

            getScanById: (id) => {
                return get().scans.find((scan) => scan.id === id);
            },
        }),
        {
            name: "pisc-history-storage",
        }
    )
);

// Helper to format timestamp
export function formatTimestamp(timestamp: number): string {
    return formatDistanceToNow(new Date(timestamp), { addSuffix: true });
}
