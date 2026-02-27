import { motion, AnimatePresence } from "framer-motion";
import { CheckCircle, Circle, Loader2, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

// Extended stage type for WebSocket events
export type ScanStage = 
  | "idle" 
  | "analyzing"
  | "reading" 
  | "regex" 
  | "llm" 
  | "complete";

export interface StepData {
  summary?: string;
  data?: unknown;
}

interface StageProgressProps {
  stage: ScanStage;
  stepData?: Record<string, StepData>;
}

// Vertical stepper configuration
const steps = [
  { 
    key: "reading", 
    label: "Reading your prompt",
    description: "Analyzing input text",
  },
  { 
    key: "regex", 
    label: "Pattern matching", 
    description: "Checking against known injection patterns",
  },
  { 
    key: "llm", 
    label: "AI Classification", 
    description: "Running through LLM analysis",
    requiresLLM: true,
  },
  { 
    key: "complete", 
    label: "Generating verdict", 
    description: "Compiling final results",
  },
];

interface StepIndicatorProps {
  status: "pending" | "running" | "done";
  stepNumber: number;
  label: string;
  description?: string;
  summary?: string;
}

function StepIndicator({ status, stepNumber, label, description, summary }: StepIndicatorProps) {
  // Use stepNumber to display small badge for pending steps
  const showBadge = status === "pending";

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      className="flex gap-4 py-3"
    >
      {/* Step indicator */}
      <div className="flex flex-col items-center">
        {status === "running" ? (
          <div className="relative">
            <Loader2 className="w-6 h-6 text-violet-500 animate-spin" />
            <motion.div
              className="absolute inset-0 rounded-full border-2 border-violet-500/30"
              animate={{ scale: [1, 1.5, 1], opacity: [0.5, 0, 0.5] }}
              transition={{ duration: 1.5, repeat: Infinity }}
            />
          </div>
        ) : status === "done" ? (
          <CheckCircle className="w-6 h-6 text-green-500" />
        ) : (
          <div className="relative">
            <Circle className="w-6 h-6 text-zinc-600" />
            {showBadge && (
              <span className="absolute -top-1 -right-1 w-4 h-4 text-[10px] bg-zinc-700 rounded-full flex items-center justify-center text-zinc-400">
                {stepNumber}
              </span>
            )}
          </div>
        )}
        
        {/* Connecting line */}
        {status !== "done" && (
          <div className="w-0.5 h-8 bg-zinc-700 mt-1" />
        )}
      </div>

      {/* Step content */}
      <div className="flex-1 pb-4">
        <div className="flex items-center gap-2">
          <span className={cn(
            "text-sm font-medium",
            status === "pending" && "text-zinc-500",
            status === "running" && "text-violet-400",
            status === "done" && "text-zinc-300",
          )}>
            {label}
          </span>
          
          {status === "running" && (
            <motion.span
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-xs text-violet-400/80"
            >
              Checking...
            </motion.span>
          )}
        </div>

        {/* Description or summary */}
        <AnimatePresence mode="wait">
          {summary ? (
            <motion.p
              key="summary"
              initial={{ opacity: 0, y: -5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 5 }}
              className="text-sm text-green-400 mt-1"
            >
              {summary}
            </motion.p>
          ) : description && status === "running" ? (
            <motion.p
              key="desc"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-xs text-zinc-500 mt-0.5"
            >
              {description}
            </motion.p>
          ) : null}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}

export function StageProgress({ stage, stepData = {} }: StageProgressProps) {
  // Determine which step is currently active
  const getStepStatus = (stepKey: string): "pending" | "running" | "done" => {
    const stepIndex = steps.findIndex(s => s.key === stepKey);
    const currentIndex = steps.findIndex(s => s.key === stage);
    
    if (stepIndex < currentIndex) return "done";
    if (stepIndex === currentIndex) return "running";
    return "pending";
  };

  // Check if we should show escalation warning (between regex and llm, if score is high)
  const showEscalationWarning = stage === "llm" && stepData["regex"]?.summary?.includes("suspicious");

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6"
    >
      {/* Escalation warning banner */}
      <AnimatePresence>
        {showEscalationWarning && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="mb-4 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg flex items-center gap-2"
          >
            <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0" />
            <span className="text-sm text-amber-200">
              Suspicious patterns detected — running deeper AI analysis...
            </span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Vertical stepper */}
      <div className="space-y-0">
        {steps.map((step, index) => {
          // Skip LLM step if not needed
          if (step.requiresLLM && stage !== "llm" && stage !== "complete") {
            return null;
          }

          const status = getStepStatus(step.key);
          const stepDataItem = stepData[step.key];

          return (
            <StepIndicator
              key={step.key}
              status={status}
              stepNumber={index + 1}
              label={step.label}
              description={step.description}
              summary={status === "done" ? stepDataItem?.summary : undefined}
            />
          );
        })}
      </div>

      {/* Running animation dots */}
      {stage !== "complete" && stage !== "idle" && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex justify-center gap-1 mt-2"
        >
          {[0, 1, 2].map((i) => (
            <motion.div
              key={i}
              className="w-1.5 h-1.5 rounded-full bg-violet-500"
              animate={{ y: [0, -4, 0] }}
              transition={{
                duration: 0.6,
                repeat: Infinity,
                delay: i * 0.15,
              }}
            />
          ))}
        </motion.div>
      )}
    </motion.div>
  );
}

// Helper to get summary text from step data
export function getStepSummary(stage: string, data?: unknown): string | undefined {
  if (!data) return undefined;

  switch (stage) {
    case "regex": {
      const regexData = data as { matches_found?: number; risk_score?: number };
      if (regexData?.matches_found) {
        return `Found ${regexData.matches_found} suspicious pattern${regexData.matches_found > 1 ? "s" : ""}`;
      }
      if (regexData?.risk_score && regexData.risk_score > 0.3) {
        return "Suspicious patterns detected";
      }
      return "No suspicious patterns found";
    }
    case "llm": {
      const llmData = data as { verdict?: string; confidence?: number };
      if (llmData?.verdict) {
        const confidence = llmData.confidence ? ` (${Math.round(llmData.confidence * 100)}% confidence)` : "";
        return `AI classified as: ${llmData.verdict}${confidence}`;
      }
      return "AI analysis complete";
    }
    case "complete":
      return "Verdict generated";
    default:
      return undefined;
  }
}
