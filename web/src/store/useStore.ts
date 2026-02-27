import { create } from "zustand";
import { persist } from "zustand/middleware";
import { HistoryItem, ScanResponse } from "@/types/api.types";
import { ScanStage } from "@/components/scanner/StageProgress";

interface ScannerState {
    // Scan state
    isScanning: boolean;
    scanStage: ScanStage;
    currentPrompt: string;
    lastResult: ScanResponse | null;

    // History
    history: HistoryItem[];

    // Actions
    setIsScanning: (isScanning: boolean) => void;
    setScanStage: (stage: ScanStage) => void;
    setCurrentPrompt: (prompt: string) => void;
    setLastResult: (result: ScanResponse | null) => void;
    addToHistory: (item: HistoryItem) => void;
    removeFromHistory: (id: string) => void;
    clearHistory: () => void;
    getHistoryItemById: (id: string) => HistoryItem | undefined;
}

export const useStore = create<ScannerState>()(
    persist(
        (set, get) => ({
            // Initial state
            isScanning: false,
            scanStage: "idle",
            currentPrompt: "",
            lastResult: null,
            history: [],

            // Actions
            setIsScanning: (isScanning) => set({ isScanning }),
            setScanStage: (scanStage) => set({ scanStage }),
            setCurrentPrompt: (currentPrompt) => set({ currentPrompt }),
            setLastResult: (lastResult) => set({ lastResult }),

            addToHistory: (item) =>
                set((state) => ({
                    history: [item, ...state.history].slice(0, 100), // Keep last 100
                })),

            removeFromHistory: (id) =>
                set((state) => ({
                    history: state.history.filter((item) => item.id !== id),
                })),

            clearHistory: () => set({ history: [] }),

            getHistoryItemById: (id) => {
                return get().history.find((item) => item.id === id);
            },
        }),
        {
            name: "prompt-scanner-storage",
            partialize: (state) => ({ history: state.history }),
        }
    )
);
