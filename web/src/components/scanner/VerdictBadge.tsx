import { Badge } from "@/components/ui/badge";
import { AlertTriangle, CheckCircle, XCircle, Info } from "lucide-react";
import { motion } from "framer-motion";

export type Verdict = "safe" | "danger" | "warning" | "unknown";

interface VerdictBadgeProps {
  verdict: Verdict;
}

const verdictConfig = {
  safe: {
    label: "Safe",
    variant: "success" as const,
    icon: CheckCircle,
  },
  danger: {
    label: "Danger",
    variant: "danger" as const,
    icon: XCircle,
  },
  warning: {
    label: "Warning",
    variant: "warning" as const,
    icon: AlertTriangle,
  },
  unknown: {
    label: "Unknown",
    variant: "secondary" as const,
    icon: Info,
  },
};

export function VerdictBadge({ verdict }: VerdictBadgeProps) {
  const config = verdictConfig[verdict];
  const Icon = config.icon;

  return (
    <motion.div
      initial={{ scale: 0, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{
        type: "spring",
        stiffness: 500,
        damping: 25,
        delay: 0.1
      }}
    >
      <Badge 
        variant={config.variant} 
        className="gap-1"
        role="status"
        aria-label={`Verdict: ${config.label}`}
      >
        <Icon className="h-3 w-3" aria-hidden="true" />
        <span>{config.label}</span>
      </Badge>
    </motion.div>
  );
}
