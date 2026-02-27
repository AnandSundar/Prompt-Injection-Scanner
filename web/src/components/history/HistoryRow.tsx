import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronDown, ChevronUp, Trash2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { ScanRecord, formatTimestamp, useHistoryStore } from "@/store/useHistoryStore";
import { ResultCard, Verdict } from "@/components/scanner/ResultCard";

interface HistoryRowProps {
  scan: ScanRecord;
}

function MiniRiskMeter({ score }: { score: number }) {
  const normalizedScore = Math.min(Math.max(score, 0), 100);
  
  return (
    <div className="w-20 h-2 bg-zinc-700 rounded-full overflow-hidden">
      <div
        className={cn(
          "h-full rounded-full",
          normalizedScore < 30 && "bg-green-500",
          normalizedScore >= 30 && normalizedScore < 60 && "bg-amber-500",
          normalizedScore >= 60 && "bg-red-500"
        )}
        style={{ width: `${normalizedScore}%` }}
      />
    </div>
  );
}

function VerdictPill({ verdict }: { verdict: string }) {
  const config = {
    safe: { label: "SAFE", bg: "bg-green-500/20", text: "text-green-400", border: "border-green-500/30" },
    warning: { label: "SUSPICIOUS", bg: "bg-amber-500/20", text: "text-amber-400", border: "border-amber-500/30" },
    danger: { label: "MALICIOUS", bg: "bg-red-500/20", text: "text-red-400", border: "border-red-500/30" },
    unknown: { label: "UNKNOWN", bg: "bg-zinc-500/20", text: "text-zinc-400", border: "border-zinc-500/30" },
  };
  
  const c = config[verdict as keyof typeof config] || config.unknown;
  
  return (
    <span className={cn("px-2 py-0.5 text-xs font-medium rounded-full border", c.bg, c.text, c.border)}>
      {c.label}
    </span>
  );
}

export function HistoryRow({ scan }: HistoryRowProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const removeScan = useHistoryStore((state) => state.removeScan);
  
  const promptPreview = scan.prompt.length > 100 
    ? scan.prompt.slice(0, 100) + "..." 
    : scan.prompt;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-zinc-900/50 border border-zinc-800 rounded-xl overflow-hidden"
    >
      {/* Card Header - always visible */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-4 flex items-center gap-4 hover:bg-zinc-800/30 transition-colors text-left"
      >
        {/* Verdict Badge */}
        <VerdictPill verdict={scan.verdict} />
        
        {/* Prompt Preview */}
        <div className="flex-1 min-w-0">
          <p className="text-sm text-zinc-300 truncate">{promptPreview}</p>
          <p className="text-xs text-zinc-500">{formatTimestamp(scan.timestamp)}</p>
        </div>
        
        {/* Risk Score */}
        <MiniRiskMeter score={scan.score * 100} />
        
        {/* Expand Icon */}
        <div className="text-zinc-500">
          {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </div>
      </button>
      
      {/* Expanded Content */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 pt-2 border-t border-zinc-800/50 space-y-4">
              {/* Full Prompt */}
              <div>
                <h4 className="text-xs font-medium text-zinc-500 uppercase mb-2">Full Prompt</h4>
                <pre className="text-sm text-zinc-300 bg-zinc-800/50 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap font-mono">
                  {scan.prompt}
                </pre>
              </div>
              
              {/* Result Card */}
              <ResultCard
                verdict={scan.verdict as Verdict}
                score={scan.score}
                patternMatches={scan.patternMatches}
                llmAnalysis={scan.llmAnalysis}
              />
              
              {/* Delete Button */}
              <div className="flex justify-end">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    removeScan(scan.id);
                  }}
                  className="flex items-center gap-2 px-3 py-2 text-xs text-zinc-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                  Delete
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
