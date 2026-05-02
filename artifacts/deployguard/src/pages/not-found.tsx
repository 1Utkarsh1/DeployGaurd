import { ShieldAlert } from "lucide-react";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center">
      <div className="text-center space-y-6 px-4">
        <ShieldAlert className="h-16 w-16 text-muted-foreground mx-auto" />
        <div className="space-y-2">
          <h1 className="text-4xl font-bold tracking-tight">404</h1>
          <p className="text-xl text-muted-foreground">Page not found</p>
        </div>
        <Button asChild variant="outline">
          <Link href="/">Back to scanner</Link>
        </Button>
      </div>
    </div>
  );
}
