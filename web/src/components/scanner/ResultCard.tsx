import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { CheckCircle, AlertTriangle, Shield, Copy, Save, RotateCcw, ChevronDown, ChevronUp, CircleDashed } from "lucide-react";
import { cn } from "@/lib/utils";

// Types
export type Verdict = "safe" | "warning" | "danger" | "unknown";

interface PatternMatch {
  category: string;
  description: string;
  matched_text: string;
  severity: string;
}

interface LLMAnalysis {
  verdict: string;
  confidence: number;
  payload_type: string;
  reasoning: string;
}

interface ResultCardProps {
  verdict: Verdict;
  score: number;
  patternMatches?: PatternMatch[];
  llmAnalysis?: LLMAnalysis;
  onScanAnother?: () => void;
  onSaveToHistory?: () => void;
}

// Verdict config
const verdictConfig = {
  safe: {
    label: "SAFE",
    gradient: "from-green-500/20 to-emerald-500/20",
    border: "border-green-500/30",
    icon: CheckCircle,
    iconBg: "bg-green-500",
    title: "This prompt looks safe",
    description: "No goal-hijacking payloads were found.",
    color: "text-green-400",
    ariaLabel: "Safe. This prompt looks safe.",
  },
  warning: {
    label: "SUSPICIOUS",
    gradient: "from-amber-500/20 to-orange-500/20",
    border: "border-amber-500/30",
    icon: AlertTriangle,
    iconBg: "bg-amber-500",
    title: "This prompt has suspicious patterns",
    description: "Some patterns suggest an attempt to manipulate AI behavior.",
    color: "text-amber-400",
    ariaLabel: "Warning. This prompt has suspicious patterns.",
  },
  danger: {
    label: "INJECTION",
    gradient: "from-red-500/20 to-rose-500/20",
    border: "border-red-500/30",
    icon: Shield,
    iconBg: "bg-red-500",
    title: "Prompt injection detected",
    description: "This prompt is actively trying to override AI instructions.",
    color: "text-red-400",
    ariaLabel: "Danger. Prompt injection detected.",
  },
  unknown: {
    label: "UNKNOWN",
    gradient: "from-zinc-500/20 to-gray-500/20",
    border: "border-zinc-500/30",
    icon: CircleDashed,
    iconBg: "bg-zinc-500",
    title: "Analysis inconclusive",
    description: "Unable to determine if this prompt is safe.",
    color: "text-zinc-400",
    ariaLabel: "Unknown. Analysis inconclusive.",
  },
};

// Risk level labels
const getRiskLabel = (score: number): string => {
  if (score < 30) return "LOW RISK";
  if (score < 60) return "MODERATE RISK";
  return "HIGH RISK";
};

// Category badge colors
const categoryColors: Record<string, string> = {
  INSTRUCTION_OVERRIDE: "bg-red-500/20 text-red-400 border-red-500/30",
  ROLE_HIJACK: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  GOAL_REDIRECT: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  DATA_EXFIL: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  ENCODING_TRICKS: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  DELIMITER_INJECTION: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  CONTEXT_OVERFLOW: "bg-pink-500/20 text-pink-400 border-pink-500/30",
};

function RiskMeter({ score }: { score: number }) {
  const normalizedScore = Math.min(Math.max(score, 0), 100);
  
  return (
    <div className="space-y-2">
      <div className="flex justify-between text-sm">
        <span className="text-zinc-400">Risk Score</span>
        <span className="font-mono">{normalizedScore} / 100</span>
      </div>
      
      {/* Meter bar */}
      <div className="h-3 bg-zinc-800 rounded-full overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${normalizedScore}%` }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className={cn(
            "h-full rounded-full",
            score < 30 && "bg-gradient-to-r from-green-400 to-green-500",
            score >= 30 && score < 60 && "bg-gradient-to-r from-amber-400 to-orange-500",
            score >= 60 && "bg-gradient-to-r from-red-400 to-red-600"
          )}
        />
      </div>
      
      <p className={cn(
        "text-xs font-medium",
        score < 30 && "text-green-400",
        score >= 30 && score < 60 && "text-amber-400",
        score >= 60 && "text-red-400"
      )}>
        {getRiskLabel(score)}
      </p>
    </div>
  );
}

function PatternMatchesSection({ matches }: { matches?: PatternMatch[] }) {
  const [isOpen, setIsOpen] = useState(false);
  
  if (!matches || matches.length === 0) return null;

  return (
    <div className="border border-zinc-700/50 rounded-lg overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        className="w-full flex items-center justify-between p-4 bg-zinc-800/30 hover:bg-zinc-800/50 transition-colors focus:outline-none focus:ring-2 focus:ring-violet-500"
      >
        <span className="text-sm text-zinc-300">
          Show details ({matches.length} pattern{matches.length > 1 ? "s" : ""} matched)
        </span>
        {isOpen ? (
          <ChevronUp className="w-4 h-4 text-zinc-500" aria-hidden="true" />
        ) : (
          <ChevronDown className="w-4 h-4 text-zinc-500" aria-hidden="true" />
        )}
      </button>
      
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="p-4 space-y-3 bg-zinc-900/50">
              {matches.map((match, index) => (
                <div
                  key={index}
                  className="p-3 bg-zinc-800/50 rounded-lg border border-zinc-700/50"
                >
                  <div className="flex items-center gap-2 mb-2">
                    <span className={cn(
                      "px-2 py-0.5 text-xs rounded-full border",
                      categoryColors[match.category] || "bg-zinc-500/20 text-zinc-400 border-zinc-500/30"
                    )}>
                      {match.category.replace(/_/g, " ")}
                    </span>
                  </div>
                  <p className="text-sm text-zinc-300 mb-2">{match.description}</p>
                  <code className="text-xs bg-zinc-900 px-2 py-1 rounded text-violet-300 block truncate">
                    "{match.matched_text}"
                  </code>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function LLMAnalysisSection({ analysis }: { analysis?: LLMAnalysis }) {
  if (!analysis) return null;

  const confidencePercent = Math.round(analysis.confidence * 100);

  return (
    <div className="space-y-4 p-4 bg-violet-500/5 border border-violet-500/20 rounded-lg">
      <h4 className="text-sm font-medium text-violet-300">AI Analysis</h4>
      
      <div className="flex items-center gap-4">
        {/* Confidence ring */}
        <div className="relative w-16 h-16">
          <svg className="w-16 h-16 transform -rotate-90" aria-hidden="true">
            <circle
              cx="32"
              cy="32"
              r="28"
              stroke="currentColor"
              strokeWidth="4"
              fill="none"
              className="text-zinc-700"
            />
            <motion.circle
              cx="32"
              cy="32"
              r="28"
              stroke="currentColor"
              strokeWidth="4"
              fill="none"
              className="text-violet-500"
              strokeLinecap="round"
              initial={{ strokeDasharray: 176, strokeDashoffset: 176 }}
              animate={{ strokeDashoffset: 176 - (176 * confidencePercent) / 100 }}
              transition={{ duration: 0.8, ease: "easeOut" }}
            />
          </svg>
          <span className="absolute inset-0 flex items-center justify-center text-sm font-bold text-violet-300" aria-label={`Confidence: ${confidencePercent}%`}>
            {confidencePercent}%
          </span>
        </div>
        
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 text-xs bg-violet-500/20 text-violet-300 rounded-full border border-violet-500/30">
              {analysis.payload_type.replace(/_/g, " ")}
            </span>
          </div>
          <p className="text-sm text-zinc-300 italic">"{analysis.reasoning}"</p>
        </div>
      </div>
    </div>
  );
}

export function ResultCard({
  verdict: verdictKey,
  score,
  patternMatches,
  llmAnalysis,
  onScanAnother,
  onSaveToHistory,
}: ResultCardProps) {
  const config = verdictConfig[verdictKey] || verdictConfig.unknown;
  const Icon = config.icon;
  const normalizedScore = Math.round(score * 100);
  const [copied, setCopied] = useState(false);
  const [announceMessage, setAnnounceMessage] = useState("");

  // Announce verdict to screen readers
  useEffect(() => {
    setAnnounceMessage(`${config.ariaLabel} Risk score ${normalizedScore} out of 100.`);
    const timer = setTimeout(() => setAnnounceMessage(""), 3000);
    return () => clearTimeout(timer);
  }, [config.ariaLabel, normalizedScore]);

  const handleCopyReport = async () => {
    const report = `
Prompt Injection Scan Report
=============================
Verdict: ${config.label}
Risk Score: ${normalizedScore} / 100
${patternMatches && patternMatches.length > 0 ? `\nPattern Matches: ${patternMatches.length}` : ""}
${llmAnalysis ? `\nAI Analysis: ${llmAnalysis.verdict} (${Math.round(llmAnalysis.confidence * 100)}% confidence)` : ""}

${config.description}
    `.trim();

    try {
      await navigator.clipboard.writeText(report);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  return (
    <>
      {/* Screen reader announcement */}
      <div 
        role="status" 
        aria-live="polite" 
        aria-atomic="true" 
        className="sr-only"
      >
        {announceMessage}
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: "easeOut" }}
        className="space-y-4"
      >
        {/* Verdict Hero */}
        <div className={cn(
          "relative overflow-hidden rounded-xl p-6",
          "bg-gradient-to-br border",
          config.gradient,
          config.border
        )}>
          {/* Animated background pattern */}
          <div className="absolute inset-0 opacity-10" aria-hidden="true">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_0%,var(--tw-gradient-stops))] from-white/20 via-transparent to-transparent" />
          </div>
          
          <div className="relative flex items-start gap-4">
            <div className={cn("p-3 rounded-xl", config.iconBg)}>
              <Icon className="w-8 h-8 text-white" aria-hidden="true" />
            </div>
            
            <div className="flex-1">
              <h3 className={cn("text-xl font-bold mb-1", config.color)}>
                {config.title}
              </h3>
              <p className="text-zinc-300">{config.description}</p>
            </div>
          </div>
        </div>

        {/* Risk Score Meter */}
        <RiskMeter score={normalizedScore} />

        {/* Pattern Matches */}
        <PatternMatchesSection matches={patternMatches} />

        {/* LLM Analysis */}
        <LLMAnalysisSection analysis={llmAnalysis} />

        {/* Action Buttons */}
        <div className="flex flex-wrap gap-3 pt-2">
          <button
            onClick={onScanAnother}
            className="flex items-center gap-2 px-4 py-2.5 min-h-[44px] bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-lg transition-colors text-sm focus:outline-none focus:ring-2 focus:ring-violet-500"
            aria-label="Scan another prompt"
          >
            <RotateCcw className="w-4 h-4" aria-hidden="true" />
            <span>Scan Another</span>
          </button>
          
          <button
            onClick={handleCopyReport}
            className={cn(
              "flex items-center gap-2 px-4 py-2.5 min-h-[44px] rounded-lg transition-colors text-sm focus:outline-none focus:ring-2 focus:ring-violet-500",
              copied 
                ? "bg-green-600/20 text-green-400 border border-green-500/30" 
                : "bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
            )}
            aria-label={copied ? "Report copied to clipboard" : "Copy scan report to clipboard"}
          >
            {copied ? (
              <CheckCircle className="w-4 h-4" aria-hidden="true" />
            ) : (
              <Copy className="w-4 h-4" aria-hidden="true" />
            )}
            <span>{copied ? "Copied!" : "Copy Report"}</span>
          </button>
          
          {onSaveToHistory && (
            <button
              onClick={onSaveToHistory}
              className="flex items-center gap-2 px-4 py-2.5 min-h-[44px] bg-violet-600 hover:bg-violet-500 text-white rounded-lg transition-colors text-sm focus:outline-none focus:ring-2 focus:ring-violet-400"
              aria-label="Save result to history"
            >
              <Save className="w-4 h-4" aria-hidden="true" />
              <span>Save to History</span>
            </button>
          )}
        </div>

        {/* Footer note */}
        <p className="text-xs text-zinc-500 text-center pt-2">
          Results are not stored on our servers. Analysis runs locally + via your API key.
        </p>
      </motion.div>
    </>
  );
}
