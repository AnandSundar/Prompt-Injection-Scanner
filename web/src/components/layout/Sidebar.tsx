import { Link, useLocation } from "react-router-dom";
import { cn } from "@/lib/utils";
import { Shield, History, BookOpen, HelpCircle } from "lucide-react";

interface SidebarProps {
  className?: string;
}

const navItems = [
  { path: "/", label: "Scanner", icon: Shield },
  { path: "/history", label: "History", icon: History },
  { path: "/how-it-works", label: "How It Works", icon: HelpCircle },
  { path: "/patterns", label: "Patterns", icon: BookOpen },
];

export function Sidebar({ className }: SidebarProps) {
  const location = useLocation();

  return (
    <aside className={cn("w-64 border-r bg-card", className)}>
      <div className="flex h-16 items-center border-b px-4">
        <Link to="/" className="flex items-center space-x-2">
          <Shield className="h-6 w-6 text-primary" />
          <span className="text-lg font-bold">Prompt Scanner</span>
        </Link>
      </div>
      
      <nav className="space-y-1 p-2">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path;
          const Icon = item.icon;
          
          return (
            <Link
              key={item.path}
              to={item.path}
              className={cn(
                "flex items-center space-x-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground"
              )}
            >
              <Icon className="h-4 w-4" />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
