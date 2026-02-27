import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldX, ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";

export function NotFoundPage() {
  const navigate = useNavigate();

  return (
    <div className="min-h-[80vh] flex items-center justify-center px-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center max-w-md"
      >
        {/* Illustration */}
        <motion.div
          initial={{ scale: 0.8 }}
          animate={{ scale: 1 }}
          transition={{ delay: 0.2, type: "spring" }}
          className="w-32 h-32 bg-zinc-800/50 rounded-full flex items-center justify-center mx-auto mb-8"
        >
          <ShieldX className="w-16 h-16 text-zinc-500" />
        </motion.div>

        <h1 className="text-4xl font-bold text-zinc-100 mb-4">
          This page doesn't exist
        </h1>
        <p className="text-zinc-400 mb-8">
          The page you're looking for has been moved or doesn't exist. 
          Let's get you back on track.
        </p>

        <Button
          onClick={() => navigate("/")}
          className="bg-violet-600 hover:bg-violet-500"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Scanner
        </Button>
      </motion.div>
    </div>
  );
}
