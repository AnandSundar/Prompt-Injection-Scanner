import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, Key, Check, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

const STORAGE_KEY = "pisc_api_key";

interface ApiKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function ApiKeyModal({ isOpen, onClose }: ApiKeyModalProps) {
  const [apiKey, setApiKey] = useState("");
  const [status, setStatus] = useState<"idle" | "saved" | "error">("idle");

  useEffect(() => {
    if (isOpen) {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        setApiKey(saved);
      }
    }
  }, [isOpen]);

  const handleSave = () => {
    if (apiKey.trim()) {
      localStorage.setItem(STORAGE_KEY, apiKey.trim());
      setStatus("saved");
      setTimeout(() => {
        onClose();
        setStatus("idle");
      }, 1000);
    }
  };

  const handleClear = () => {
    localStorage.removeItem(STORAGE_KEY);
    setApiKey("");
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
        onClick={onClose}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          className="w-full max-w-md bg-zinc-900 border border-zinc-800 rounded-2xl p-6"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-blue-600/20 rounded-xl flex items-center justify-center">
                <Key className="w-5 h-5 text-blue-400" />
              </div>
              <h2 className="text-lg font-semibold text-zinc-100">
                API Key Settings
              </h2>
            </div>
            <button
              onClick={onClose}
              className="text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <p className="text-sm text-zinc-400 mb-4">
            Enter your OpenAI API key to enable AI-powered analysis. 
            Your key is stored locally and never sent to our servers.
          </p>

          <Input
            type="password"
            placeholder="sk-..."
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            className="bg-zinc-800 border-zinc-700 mb-4"
          />

          <div className="flex gap-3">
            <Button
              variant="outline"
              onClick={handleClear}
              className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
            >
              Clear
            </Button>
            <Button
              onClick={handleSave}
              className="flex-1 bg-violet-600 hover:bg-violet-500"
              disabled={!apiKey.trim()}
            >
              {status === "saved" ? (
                <>
                  <Check className="w-4 h-4 mr-2" />
                  Saved!
                </>
              ) : (
                "Save Key"
              )}
            </Button>
          </div>

          {status === "error" && (
            <p className="text-red-400 text-sm mt-3 flex items-center gap-2">
              <AlertCircle className="w-4 h-4" />
              Failed to save. Please try again.
            </p>
          )}
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}

// Hook to check API key status
export function useApiKey() {
  const [hasApiKey, setHasApiKey] = useState(false);

  useEffect(() => {
    const key = localStorage.getItem(STORAGE_KEY);
    setHasApiKey(!!key);
  }, []);

  const getApiKey = () => {
    return localStorage.getItem(STORAGE_KEY);
  };

  return { hasApiKey, getApiKey };
}
