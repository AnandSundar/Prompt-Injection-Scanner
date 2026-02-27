import { useState, useMemo, useEffect, useCallback } from "react";
import { Search } from "lucide-react";
import { useHistoryStore } from "@/store/useHistoryStore";
import { HistoryRow } from "./HistoryRow";
import { Input } from "@/components/ui/input";
import { HistoryRowSkeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

type FilterPill = "all" | "safe" | "warning" | "danger";

const filterPills: { key: FilterPill; label: string }[] = [
  { key: "all", label: "All" },
  { key: "safe", label: "Safe" },
  { key: "warning", label: "Suspicious" },
  { key: "danger", label: "Malicious" },
];

// Debounce hook
function useDebounce<T>(value: T, delay: number): T {
  const [debouncedValue, setDebouncedValue] = useState<T>(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
}

export function HistoryTable() {
  const scans = useHistoryStore((state) => state.scans);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeFilter, setActiveFilter] = useState<FilterPill>("all");
  const [isLoading, setIsLoading] = useState(true);

  // Debounce search input (300ms)
  const debouncedSearch = useDebounce(searchQuery, 300);

  // Simulate loading state
  useEffect(() => {
    // Show skeleton briefly on mount
    const timer = setTimeout(() => setIsLoading(false), 500);
    return () => clearTimeout(timer);
  }, []);

  const filteredScans = useMemo(() => {
    return scans.filter((scan) => {
      // Search filter (use debounced value)
      const matchesSearch = debouncedSearch === "" || 
        scan.prompt.toLowerCase().includes(debouncedSearch.toLowerCase());
      
      // Verdict filter
      const matchesFilter = activeFilter === "all" || scan.verdict === activeFilter;
      
      return matchesSearch && matchesFilter;
    });
  }, [scans, debouncedSearch, activeFilter]);

  const handleSearchChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
  }, []);

  return (
    <div className="space-y-6">
      {/* Search and Filter Bar */}
      <div className="flex flex-col sm:flex-row gap-4">
        {/* Search Input */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" aria-hidden="true" />
          <Input
            type="text"
            placeholder="Search prompts..."
            value={searchQuery}
            onChange={handleSearchChange}
            className="pl-10 bg-zinc-900 border-zinc-800"
            aria-label="Search scan history"
          />
        </div>
        
        {/* Filter Pills */}
        <div className="flex gap-2" role="group" aria-label="Filter by verdict">
          {filterPills.map((pill) => (
            <button
              key={pill.key}
              onClick={() => setActiveFilter(pill.key)}
              className={cn(
                "px-3 py-1.5 text-sm rounded-full transition-colors min-h-[44px]",
                activeFilter === pill.key
                  ? "bg-violet-600 text-white"
                  : "bg-zinc-800 text-zinc-400 hover:bg-zinc-700"
              )}
              aria-pressed={activeFilter === pill.key}
            >
              {pill.label}
            </button>
          ))}
        </div>
      </div>

      {/* Results count */}
      <p className="text-sm text-zinc-500" aria-live="polite">
        {isLoading ? "Loading..." : `Showing ${filteredScans.length} of ${scans.length} scans`}
      </p>

      {/* History List */}
      <div className="space-y-3" role="list" aria-label="Scan history">
        {isLoading ? (
          // Skeleton loaders while loading
          Array.from({ length: 3 }).map((_, i) => (
            <HistoryRowSkeleton key={i} />
          ))
        ) : filteredScans.length > 0 ? (
          filteredScans.map((scan) => (
            <HistoryRow key={scan.id} scan={scan} />
          ))
        ) : (
          <p className="text-center py-8 text-zinc-500">
            No scans match your search.
          </p>
        )}
      </div>
    </div>
  );
}
