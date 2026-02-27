import { useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Scan, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface ScanButtonProps {
  onClick: () => void;
  isLoading?: boolean;
  disabled?: boolean;
}

interface Ripple {
  id: number;
  x: number;
  y: number;
}

export function ScanButton({ onClick, isLoading, disabled }: ScanButtonProps) {
  const [ripples, setRipples] = useState<Ripple[]>([]);

  const handleClick = useCallback((e: React.MouseEvent<HTMLButtonElement>) => {
    if (disabled || isLoading) return;
    
    const button = e.currentTarget;
    const rect = button.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    
    const newRipple: Ripple = { id: Date.now(), x, y };
    setRipples((prev) => [...prev, newRipple]);
    
    // Remove ripple after animation
    setTimeout(() => {
      setRipples((prev) => prev.filter((r) => r.id !== newRipple.id));
    }, 600);
    
    onClick();
  }, [disabled, isLoading, onClick]);

  return (
    <Button
      onClick={handleClick}
      disabled={disabled || isLoading}
      className={cn(
        "relative w-full h-14 text-lg font-semibold overflow-hidden",
        "bg-gradient-to-r from-violet-600 to-indigo-600",
        "hover:from-violet-500 hover:to-indigo-500",
        "text-white shadow-lg",
        "transition-all duration-300 ease-out",
        "hover:shadow-violet-500/25 hover:shadow-xl",
        "active:scale-[0.98]",
        "disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:shadow-lg",
        !disabled && !isLoading && "hover:scale-[1.01]"
      )}
      aria-label={isLoading ? "Analyzing prompt" : "Scan this prompt for injection"}
    >
      {/* Ripple effects */}
      {ripples.map((ripple) => (
        <span
          key={ripple.id}
          className="absolute bg-white/30 rounded-full animate-ripple pointer-events-none"
          style={{
            left: ripple.x - 50,
            top: ripple.y - 50,
            width: 100,
            height: 100,
          }}
        />
      ))}
      
      {isLoading ? (
        <div className="flex items-center gap-2">
          <Loader2 className="w-5 h-5 animate-spin" aria-hidden="true" />
          <span>Analyzing...</span>
        </div>
      ) : (
        <div className="flex items-center gap-2">
          <Scan className="w-5 h-5" aria-hidden="true" />
          <span>Scan This Prompt</span>
        </div>
      )}
    </Button>
  );
}

// Trust badges component
export function TrustBadges() {
  const badges = [
    { icon: <span className="text-lg" aria-hidden="true">⚡</span>, text: "Results in under 2s" },
    { icon: <span className="text-lg" aria-hidden="true">🔒</span>, text: "Nothing stored permanently" },
    { icon: <span className="text-lg" aria-hidden="true">🧠</span>, text: "Dual-layer analysis" },
  ];

  return (
    <div className="flex flex-wrap justify-center gap-6 mt-8 pt-6" role="list" aria-label="Trust badges">
      {badges.map((badge, index) => (
        <div
          key={index}
          className="flex items-center gap-2 text-sm text-zinc-500"
          role="listitem"
        >
          {badge.icon}
          <span>{badge.text}</span>
        </div>
      ))}
    </div>
  );
}
