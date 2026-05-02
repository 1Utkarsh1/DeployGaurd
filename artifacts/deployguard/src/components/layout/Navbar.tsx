import { ShieldCheck } from "lucide-react";
import { Link } from "wouter";

export function Navbar() {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-border/40 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container mx-auto flex h-14 max-w-screen-xl items-center">
        <Link href="/" className="mr-6 flex items-center space-x-2">
          <ShieldCheck className="h-6 w-6 text-primary" />
          <span className="font-bold sm:inline-block">DeployGuard</span>
        </Link>
        <nav className="flex flex-1 items-center justify-between space-x-2 md:justify-end">
          <div className="flex-1 text-sm text-muted-foreground hidden md:block">
            Launch-readiness checklist & security scanner
          </div>
        </nav>
      </div>
    </header>
  );
}
