import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { SearchX, Trash2, AlertTriangle } from "lucide-react";
import { PageWrapper } from "@/components/layout/PageWrapper";
import { HistoryTable } from "@/components/history/HistoryTable";
import { Button } from "@/components/ui/button";
import { useHistoryStore } from "@/store/useHistoryStore";

export function HistoryPage() {
  const navigate = useNavigate();
  const scans = useHistoryStore((state) => state.scans);
  const clearAll = useHistoryStore((state) => state.clearAll);
  const [showConfirmClear, setShowConfirmClear] = useState(false);

  const handleClearAll = () => {
    clearAll();
    setShowConfirmClear(false);
  };

  if (scans.length === 0) {
    return (
      <PageWrapper>
        <div className="flex flex-col items-center justify-center min-h-[60vh] text-center">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="mb-6 p-8 bg-zinc-900/50 rounded-full"
          >
            <SearchX className="w-16 h-16 text-zinc-600" />
          </motion.div>
          
          <motion.h2
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-xl font-semibold text-zinc-300 mb-2"
          >
            No scans yet
          </motion.h2>
          
          <motion.p
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="text-zinc-500 mb-6 max-w-md"
          >
            Head back to the scanner to get started with your first prompt analysis.
          </motion.p>
          
          <motion.button
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            onClick={() => navigate("/")}
            className="px-6 py-3 bg-violet-600 hover:bg-violet-500 text-white rounded-lg font-medium transition-colors"
          >
            Start Scanning →
          </motion.button>
        </div>
      </PageWrapper>
    );
  }

  return (
    <PageWrapper>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">
            Your Scan History 
            <span className="text-zinc-500 font-normal ml-2">
              ({scans.length} scan{scans.length !== 1 ? "s" : ""})
            </span>
          </h1>
        </div>

        {/* History Table with Filters */}
        <HistoryTable />

        {/* Clear All Button */}
        <div className="flex justify-end pt-4 border-t border-zinc-800">
          {showConfirmClear ? (
            <div className="flex items-center gap-3">
              <span className="text-sm text-zinc-400 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-500" />
                This cannot be undone
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowConfirmClear(false)}
              >
                Cancel
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={handleClearAll}
              >
                <Trash2 className="w-4 h-4 mr-2" />
                Confirm Clear
              </Button>
            </div>
          ) : (
            <button
              onClick={() => setShowConfirmClear(true)}
              className="flex items-center gap-2 px-4 py-2 text-sm text-zinc-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
            >
              <Trash2 className="w-4 h-4" />
              Clear All History
            </button>
          )}
        </div>
      </div>
    </PageWrapper>
  );
}
