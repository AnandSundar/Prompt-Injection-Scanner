import { useState } from "react";
import { Shield } from "lucide-react";
import { motion } from "framer-motion";
import * as Switch from "@radix-ui/react-switch";
import { PageWrapper } from "@/components/layout/PageWrapper";
import { PromptInput } from "@/components/scanner/PromptInput";
import { ScanButton, TrustBadges } from "@/components/scanner/ScanButton";
import { ResultCard } from "@/components/scanner/ResultCard";
import { StageProgress } from "@/components/scanner/StageProgress";
import { Verdict } from "@/components/scanner/VerdictBadge";
import { cn } from "@/lib/utils";

// Simulated result type (will be replaced with actual API response)
interface ScanResult {
  verdict: Verdict;
  score: number;
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
  recommendations: string[];
}

export function ScannerPage() {
  const [prompt, setPrompt] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [forceLLM, setForceLLM] = useState(false);
  const [stage, setStage] = useState<"idle" | "analyzing" | "reading" | "regex" | "llm" | "complete">("idle");
  const [result, setResult] = useState<ScanResult | null>(null);

  const handleScan = async () => {
    if (!prompt.trim()) return;

    setIsLoading(true);
    setResult(null);
    setStage("analyzing");

    // Simulated scan - replace with actual API/WebSocket call
    setTimeout(() => {
      setStage("regex");
      setTimeout(() => {
        setStage(forceLLM ? "llm" : "complete");
        setTimeout(() => {
          // Determine verdict based on forceLLM (simulated)
          const isSuspicious = prompt.toLowerCase().includes("ignore") || 
                              prompt.toLowerCase().includes("forget") ||
                              prompt.toLowerCase().includes("disregard");
          
          setResult({
            verdict: isSuspicious ? "warning" : "safe",
            score: isSuspicious ? 0.65 : 0.15,
            patternMatches: isSuspicious ? [
              { category: "INSTRUCTION_OVERRIDE", description: "Attempts to ignore previous instructions", matched_text: "ignore all previous instructions", severity: "high" },
            ] : [],
            llmAnalysis: forceLLM ? {
              verdict: isSuspicious ? "INJECTION" : "BENIGN",
              confidence: isSuspicious ? 0.87 : 0.95,
              payload_type: "instruction override",
              reasoning: "This prompt attempts to override system instructions.",
            } : undefined,
            recommendations: isSuspicious ? [
              "Review the prompt for potential instruction override attempts",
              "Consider rejecting prompts that attempt to override system instructions",
            ] : [],
          });
          setStage("complete");
          setIsLoading(false);
        }, forceLLM ? 1000 : 500);
      }, 500);
    }, 500);
  };

  return (
    <PageWrapper>
      <div className="w-full max-w-[720px] mx-auto">
        {/* Hero Header */}
        <div className="text-center mb-10">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="relative inline-flex mb-6"
          >
            {/* Animated gradient background */}
            <div className="absolute inset-0 bg-gradient-to-r from-violet-600 via-indigo-500 to-violet-600 rounded-2xl blur-xl opacity-30 animate-pulse" />
            <div className="relative p-4 bg-zinc-900/80 rounded-2xl border border-zinc-800">
              <Shield className="w-16 h-16 text-violet-400" />
            </div>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="text-4xl md:text-5xl font-bold mb-4"
          >
            <span className="bg-gradient-to-r from-violet-400 via-indigo-400 to-violet-400 bg-clip-text text-transparent">
              Prompt Injection Scanner
            </span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="text-lg text-zinc-400 max-w-lg mx-auto"
          >
            Paste any AI prompt below. We'll tell you if it's trying to hijack an AI system.
          </motion.p>
        </div>

        {/* Main Scanner Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.3 }}
          className="bg-zinc-900/50 border border-zinc-800 rounded-2xl p-6 space-y-6"
        >
          {/* Prompt Input */}
          <PromptInput
            value={prompt}
            onChange={setPrompt}
            maxLength={4000}
          />

          {/* Deep Scan Toggle */}
          <div className="flex items-center justify-between py-3 px-4 bg-zinc-800/30 rounded-lg border border-zinc-700/50">
            <div className="flex items-center gap-3">
              <span className="text-sm font-medium text-zinc-300">
                Deep Scan (uses AI)
              </span>
              <div className="group relative">
                <div className="w-4 h-4 text-zinc-500 cursor-help">ℹ</div>
                <div className="absolute bottom-full left-0 mb-2 w-64 p-3 bg-zinc-800 border border-zinc-700 rounded-lg text-xs text-zinc-300 opacity-0 group-hover:opacity-100 transition-opacity z-10">
                  By default we use pattern matching only. Enable this to also run the prompt through an AI classifier for higher accuracy.
                </div>
              </div>
            </div>
            <Switch.Root
              checked={forceLLM}
              onCheckedChange={setForceLLM}
              className={cn(
                "w-11 h-6 rounded-full transition-colors",
                "data-[state=checked]:bg-violet-600 data-[state=unchecked]:bg-zinc-700",
                "focus:outline-none focus:ring-2 focus:ring-violet-500 focus:ring-offset-2 focus:ring-offset-zinc-900"
              )}
            >
              <Switch.Thumb className={cn(
                "block w-5 h-5 bg-white rounded-full transition-transform",
                "data-[state=checked]:translate-x-5 data-[state=unchecked]:translate-x-0.5"
              )} />
            </Switch.Root>
          </div>

          {/* Scan Button */}
          <ScanButton
            onClick={handleScan}
            isLoading={isLoading}
            disabled={!prompt.trim()}
          />

          {/* Stage Progress */}
          {isLoading && <StageProgress stage={stage} />}

          {/* Result Card */}
          {result && !isLoading && (
            <ResultCard
              verdict={result.verdict}
              score={result.score}
              patternMatches={result.patternMatches}
              llmAnalysis={result.llmAnalysis}
            />
          )}
        </motion.div>

        {/* Trust Badges */}
        <TrustBadges />
      </div>
    </PageWrapper>
  );
}
