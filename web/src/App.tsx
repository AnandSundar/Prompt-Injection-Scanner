import { useState, useEffect, lazy, Suspense } from "react";
import { Routes, Route, useLocation } from "react-router-dom";
import { AnimatePresence } from "framer-motion";
import { Navbar } from "@/components/layout/Navbar";
import { OnboardingModal, useOnboarding } from "@/components/layout/OnboardingModal";
import { ScannerPage } from "@/pages/ScannerPage";
import { HistoryPage } from "@/pages/HistoryPage";
import { NotFoundPage } from "@/pages/NotFoundPage";

// Lazy load heavier pages
const HowItWorksPage = lazy(() => import("@/pages/HowItWorksPage").then(module => ({ default: module.HowItWorksPage })));
const PatternsPage = lazy(() => import("@/pages/PatternsPage").then(module => ({ default: module.PatternsPage })));

// Loading fallback
function PageLoader() {
  return (
    <div className="flex items-center justify-center min-h-[50vh]">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-violet-500" />
    </div>
  );
}

function AnimatedRoutes() {
  const location = useLocation();

  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route path="/" element={<ScannerPage />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route 
          path="/how-it-works" 
          element={
            <Suspense fallback={<PageLoader />}>
              <HowItWorksPage />
            </Suspense>
          } 
        />
        <Route 
          path="/patterns" 
          element={
            <Suspense fallback={<PageLoader />}>
              <PatternsPage />
            </Suspense>
          } 
        />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </AnimatePresence>
  );
}

function App() {
  const { needsOnboarding, isLoaded, completeOnboarding } = useOnboarding();
  const [showOnboarding, setShowOnboarding] = useState(false);

  useEffect(() => {
    if (isLoaded && needsOnboarding) {
      setShowOnboarding(true);
    }
  }, [isLoaded, needsOnboarding]);

  const handleOnboardingClose = () => {
    setShowOnboarding(false);
    completeOnboarding();
  };

  if (!isLoaded) {
    return null;
  }

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <main>
        <AnimatedRoutes />
      </main>
      
      <OnboardingModal
        isOpen={showOnboarding}
        onClose={handleOnboardingClose}
      />
    </div>
  );
}

export default App;
