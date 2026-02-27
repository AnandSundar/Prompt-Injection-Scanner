import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { 
  Clipboard, 
  Brain, 
  ChevronDown, 
  ChevronUp,
  FileWarning,
  Users,
  ArrowRight,
  Code2,
  Target,
  Database,
  Keyboard,
  Layers
} from "lucide-react";
import { PageWrapper } from "@/components/layout/PageWrapper";
import { Button } from "@/components/ui/button";

// FAQ Accordion Item
function FAQItem({ question, answer }: { question: string; answer: string }) {
  const [isOpen, setIsOpen] = useState(false);
  
  return (
    <div className="border-b border-zinc-800">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between py-4 text-left"
      >
        <span className="font-medium text-zinc-200">{question}</span>
        {isOpen ? (
          <ChevronUp className="w-5 h-5 text-zinc-500" />
        ) : (
          <ChevronDown className="w-5 h-5 text-zinc-500" />
        )}
      </button>
      <motion.div
        initial={false}
        animate={{ height: isOpen ? "auto" : 0, opacity: isOpen ? 1 : 0 }}
        transition={{ duration: 0.2 }}
        className="overflow-hidden"
      >
        <p className="pb-4 text-zinc-400 leading-relaxed">{answer}</p>
      </motion.div>
    </div>
  );
}

// Attack Type Card
function AttackCard({ 
  icon: Icon, 
  name, 
  description,
  color 
}: { 
  icon: React.ElementType;
  name: string;
  description: string;
  color: string;
}) {
  return (
    <motion.div
      whileHover={{ y: -4 }}
      className="p-5 bg-zinc-900/50 border border-zinc-800 rounded-xl hover:border-zinc-700 transition-colors"
    >
      <div className={`w-10 h-10 rounded-lg ${color} flex items-center justify-center mb-3`}>
        <Icon className="w-5 h-5 text-white" />
      </div>
      <h3 className="font-semibold text-zinc-200 mb-2">{name}</h3>
      <p className="text-sm text-zinc-400">{description}</p>
    </motion.div>
  );
}

// Pipeline Step
function PipelineStep({ 
  step, 
  title, 
  description, 
  icon: Icon, 
  color,
  isLast = false 
}: { 
  step: number;
  title: string;
  description: string;
  icon: React.ElementType;
  color: string;
  isLast?: boolean;
}) {
  return (
    <div className="flex items-start gap-4">
      <div className="flex flex-col items-center">
        <div className={`w-14 h-14 rounded-2xl ${color} flex items-center justify-center shadow-lg`}>
          <Icon className="w-7 h-7 text-white" />
        </div>
        {!isLast && (
          <div className="w-0.5 h-16 bg-gradient-to-b from-violet-500 to-blue-500 mt-2" />
        )}
      </div>
      <div className="flex-1 pb-8">
        <span className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Step {step}</span>
        <h3 className="text-lg font-semibold text-zinc-100 mt-1">{title}</h3>
        <p className="text-zinc-400 mt-2">{description}</p>
      </div>
    </div>
  );
}

export function HowItWorksPage() {
  const navigate = useNavigate();
  
  const attackTypes = [
    {
      icon: FileWarning,
      name: "Instruction Override",
      description: "Attempts to make AI ignore its original instructions.",
      color: "bg-red-500",
    },
    {
      icon: Users,
      name: "Role Hijacking",
      description: "Tricks AI into pretending to be someone else.",
      color: "bg-orange-500",
    },
    {
      icon: Target,
      name: "Goal Redirect",
      description: "Changes the AI's original task to something else.",
      color: "bg-amber-500",
    },
    {
      icon: Database,
      name: "Data Exfiltration",
      description: "Tries to extract private system information.",
      color: "bg-purple-500",
    },
    {
      icon: Keyboard,
      name: "Encoding Tricks",
      description: "Hides malicious text using special encoding.",
      color: "bg-blue-500",
    },
    {
      icon: Layers,
      name: "Delimiter Injection",
      description: "Uses special markers to confuse the AI.",
      color: "bg-cyan-500",
    },
  ];

  const faqs = [
    {
      question: "What is prompt injection?",
      answer: "Prompt injection is a technique where someone tries to manipulate an AI system by crafting malicious input that overrides or bypasses the AI's original instructions. It's like tricking a helpful assistant into doing something it shouldn't.",
    },
    {
      question: "Why is it dangerous?",
      answer: "Attackers can use prompt injection to make AI systems reveal private information, ignore safety guidelines, generate harmful content, or perform actions they weren't designed to do. This poses risks to both AI providers and users.",
    },
    {
      question: "Who should use this tool?",
      answer: "Anyone building or using AI-powered applications — developers, product managers, and even end-users who want to verify prompts before sending them to an AI system.",
    },
    {
      question: "Is my data private?",
      answer: "Yes. We don't store your prompts on our servers. The analysis runs entirely in your browser, and if you use the optional AI classification, your prompt is only sent to OpenAI's API — not stored anywhere.",
    },
  ];

  return (
    <PageWrapper>
      <div className="max-w-4xl mx-auto">
        {/* Hero */}
        <div className="text-center mb-16">
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-4xl md:text-5xl font-bold mb-4"
          >
            How the Scanner Works
          </motion.h1>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="text-xl text-zinc-400 max-w-2xl mx-auto"
          >
            We use two layers of analysis to detect prompt injection — no security expertise required.
          </motion.p>
        </div>

        {/* Pipeline - Desktop horizontal, Mobile vertical */}
        <div className="mb-20">
          {/* Desktop: Horizontal flow */}
          <div className="hidden md:flex justify-between items-start gap-8">
            <PipelineStep
              step={1}
              title="You paste a prompt"
              description="Any text you'd send to an AI chatbot."
              icon={Clipboard}
              color="bg-violet-500"
            />
            <PipelineStep
              step={2}
              title="Pattern Matching"
              description="We instantly check for 30+ known attack patterns — things like 'ignore all instructions' or role-hijacking phrases."
              icon={Code2}
              color="bg-blue-500"
            />
            <PipelineStep
              step={3}
              title="AI Classification"
              description="An AI model reviews the prompt for subtle manipulations that patterns might miss."
              icon={Brain}
              color="bg-indigo-500"
              isLast
            />
          </div>

          {/* Mobile: Vertical flow */}
          <div className="md:hidden space-y-2">
            <PipelineStep
              step={1}
              title="You paste a prompt"
              description="Any text you'd send to an AI chatbot."
              icon={Clipboard}
              color="bg-violet-500"
            />
            <PipelineStep
              step={2}
              title="Pattern Matching"
              description="We instantly check for 30+ known attack patterns."
              icon={Code2}
              color="bg-blue-500"
            />
            <PipelineStep
              step={3}
              title="AI Classification"
              description="An AI model reviews the prompt for subtle manipulations."
              icon={Brain}
              color="bg-indigo-500"
              isLast
            />
          </div>
        </div>

        {/* What is Prompt Injection? FAQ */}
        <div className="mb-20">
          <h2 className="text-2xl font-bold mb-6">What is Prompt Injection?</h2>
          <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-6">
            {faqs.map((faq, index) => (
              <FAQItem key={index} question={faq.question} answer={faq.answer} />
            ))}
          </div>
        </div>

        {/* Types of Attacks */}
        <div className="mb-20">
          <h2 className="text-2xl font-bold mb-6">Types of Attacks We Detect</h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
            {attackTypes.map((attack, index) => (
              <AttackCard
                key={index}
                icon={attack.icon}
                name={attack.name}
                description={attack.description}
                color={attack.color}
              />
            ))}
          </div>
        </div>

        {/* CTA Banner */}
        <div className="bg-gradient-to-r from-violet-600/20 to-indigo-600/20 border border-violet-500/30 rounded-2xl p-8 text-center">
          <h2 className="text-2xl font-bold mb-4">Ready to scan a prompt?</h2>
          <p className="text-zinc-400 mb-6">
            Paste any AI prompt and we'll check if it's safe in seconds.
          </p>
          <Button
            onClick={() => navigate("/")}
            className="bg-violet-600 hover:bg-violet-500 text-white px-8 py-3 text-lg"
          >
            Start Scanning
            <ArrowRight className="ml-2 w-5 h-5" />
          </Button>
        </div>
      </div>
    </PageWrapper>
  );
}
