import { useState, useEffect, useMemo, memo } from "react";
import { PageWrapper } from "@/components/layout/PageWrapper";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ChevronDown, ChevronUp, Search, Beaker } from "lucide-react";
import { PatternCardSkeleton } from "@/components/ui/skeleton";

interface PatternEntry {
  id: string;
  category: string;
  pattern: string;
  severity: string;
  description: string;
}

// Filter Tab Component
const FilterTab = memo(({ 
  label, 
  count, 
  active, 
  onClick 
}: { 
  label: string;
  count: number;
  active: boolean;
  onClick: () => void;
}) => {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors min-h-[44px] ${
        active
          ? "bg-violet-600 text-white"
          : "bg-zinc-800 text-zinc-400 hover:bg-zinc-700 hover:text-zinc-200"
      }`}
      aria-pressed={active}
    >
      {label} ({count})
    </button>
  );
});
FilterTab.displayName = "FilterTab";

// Pattern Card Component - memoized for performance
const PatternCard = memo(function PatternCard({ pattern }: { pattern: PatternEntry }) {
  const [showRegex, setShowRegex] = useState(false);

  const severityStyles = {
    high: "bg-red-500/20 text-red-400 border-red-500/30",
    medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    low: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  };

  const severityKey = pattern.severity.toLowerCase() as "high" | "medium" | "low";

  return (
    <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-5 hover:border-zinc-700 transition-colors">
      <div className="flex items-start justify-between gap-4 mb-3">
        <div className="flex-1">
          <h3 className="font-semibold text-zinc-100 mb-1">{pattern.category}</h3>
          <p className="text-sm text-zinc-400">{pattern.description}</p>
        </div>
        <span className={`px-2.5 py-1 rounded-full text-xs font-medium border ${severityStyles[severityKey] || severityStyles.low}`}>
          {pattern.severity}
        </span>
      </div>
      
      <button
        onClick={() => setShowRegex(!showRegex)}
        className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-violet-400 transition-colors min-h-[44px]"
        aria-expanded={showRegex}
      >
        {showRegex ? (
          <>
            <ChevronUp className="w-3.5 h-3.5" aria-hidden="true" />
            Hide pattern
          </>
        ) : (
          <>
            <ChevronDown className="w-3.5 h-3.5" aria-hidden="true" />
            Show pattern
          </>
        )}
      </button>

      {showRegex && (
        <div className="mt-3 p-3 bg-zinc-950 rounded-lg border border-zinc-800">
          <code className="text-xs font-mono text-violet-300 break-all">
            {pattern.pattern}
          </code>
        </div>
      )}
    </div>
  );
});
PatternCard.displayName = "PatternCard";

// Empty State Component
const EmptyState = memo(function EmptyState({ searchQuery }: { searchQuery: string }) {
  return (
    <div className="text-center py-16">
      <div className="w-16 h-16 bg-zinc-800 rounded-full flex items-center justify-center mx-auto mb-4">
        <Search className="w-8 h-8 text-zinc-500" aria-hidden="true" />
      </div>
      <h3 className="text-lg font-medium text-zinc-300 mb-2">No patterns found</h3>
      <p className="text-zinc-500">
        No patterns match "{searchQuery}". Try a different search term.
      </p>
    </div>
  );
});
EmptyState.displayName = "EmptyState";

export function PatternsPage() {
  const [patterns, setPatterns] = useState<PatternEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"all" | "high" | "medium" | "low">("all");

  useEffect(() => {
    fetch("http://localhost:8000/patterns")
      .then((res) => res.json())
      .then((data) => {
        setPatterns(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Failed to fetch patterns:", err);
        setLoading(false);
      });
  }, []);

  // Calculate counts for each severity
  const counts = useMemo(() => {
    return {
      all: patterns.length,
      high: patterns.filter((p) => p.severity.toLowerCase() === "high").length,
      medium: patterns.filter((p) => p.severity.toLowerCase() === "medium").length,
      low: patterns.filter((p) => p.severity.toLowerCase() === "low").length,
    };
  }, [patterns]);

  // Filter patterns based on search and severity
  const filteredPatterns = useMemo(() => {
    return patterns.filter((pattern) => {
      // Severity filter
      if (severityFilter !== "all" && pattern.severity.toLowerCase() !== severityFilter) {
        return false;
      }

      // Search filter
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return (
          pattern.category.toLowerCase().includes(query) ||
          pattern.description.toLowerCase().includes(query) ||
          pattern.id.toLowerCase().includes(query)
        );
      }

      return true;
    });
  }, [patterns, searchQuery, severityFilter]);

  // Loading state with skeleton
  if (loading) {
    return (
      <PageWrapper title="Detection Pattern Library" description="Loading patterns...">
        {/* Callout Box Skeleton */}
        <div className="bg-violet-900/20 border border-violet-500/30 rounded-xl p-4 mb-6">
          <div className="flex gap-3">
            <Beaker className="w-5 h-5 text-violet-400 flex-shrink-0 mt-0.5" />
            <p className="text-sm text-zinc-300">
              🔬 These patterns are checked instantly on every scan.
            </p>
          </div>
        </div>

        {/* Header Skeleton */}
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold text-zinc-100">
            Detection Pattern Library
            <Badge variant="secondary" className="ml-3 bg-zinc-800 text-zinc-300">
              ... patterns
            </Badge>
          </h1>
        </div>

        {/* Search and Filters Skeleton */}
        <div className="flex flex-col md:flex-row gap-4 mb-8">
          <div className="relative flex-1">
            <Input
              placeholder="Search by category, description, or ID..."
              className="pl-10 bg-zinc-900 border-zinc-800"
              disabled
            />
          </div>
          <div className="flex gap-2">
            {["All", "High", "Medium", "Low"].map((label) => (
              <div key={label} className="px-4 py-2 rounded-lg text-sm font-medium bg-zinc-800 h-10 w-16" />
            ))}
          </div>
        </div>

        {/* Skeleton Cards */}
        <div className="grid gap-4 md:grid-cols-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <PatternCardSkeleton key={i} />
          ))}
        </div>
      </PageWrapper>
    );
  }

  return (
    <PageWrapper
      title="Detection Pattern Library"
      description="Common prompt injection patterns we detect"
    >
      {/* Callout Box */}
      <div className="bg-violet-900/20 border border-violet-500/30 rounded-xl p-4 mb-6">
        <div className="flex gap-3">
          <Beaker className="w-5 h-5 text-violet-400 flex-shrink-0 mt-0.5" aria-hidden="true" />
          <p className="text-sm text-zinc-300">
            🔬 These patterns are checked instantly on every scan. If a match is found, 
            the risk score increases. High-severity matches may trigger an AI review.
          </p>
        </div>
      </div>

      {/* Header with count badge */}
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-zinc-100">
          Detection Pattern Library
          <Badge variant="secondary" className="ml-3 bg-zinc-800 text-zinc-300">
            {patterns.length} patterns
          </Badge>
        </h1>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col md:flex-row gap-4 mb-8">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" aria-hidden="true" />
          <Input
            placeholder="Search by category, description, or ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10 bg-zinc-900 border-zinc-800"
            aria-label="Search patterns"
          />
        </div>
        
        <div className="flex gap-2" role="group" aria-label="Filter by severity">
          <FilterTab
            label="All"
            count={counts.all}
            active={severityFilter === "all"}
            onClick={() => setSeverityFilter("all")}
          />
          <FilterTab
            label="High"
            count={counts.high}
            active={severityFilter === "high"}
            onClick={() => setSeverityFilter("high")}
          />
          <FilterTab
            label="Medium"
            count={counts.medium}
            active={severityFilter === "medium"}
            onClick={() => setSeverityFilter("medium")}
          />
          <FilterTab
            label="Low"
            count={counts.low}
            active={severityFilter === "low"}
            onClick={() => setSeverityFilter("low")}
          />
        </div>
      </div>

      {/* Pattern Cards Grid */}
      {filteredPatterns.length > 0 ? (
        <div className="grid gap-4 md:grid-cols-2" role="list" aria-label="Detection patterns">
          {filteredPatterns.map((pattern) => (
            <PatternCard key={pattern.id} pattern={pattern} />
          ))}
        </div>
      ) : (
        <EmptyState searchQuery={searchQuery} />
      )}
    </PageWrapper>
  );
}
