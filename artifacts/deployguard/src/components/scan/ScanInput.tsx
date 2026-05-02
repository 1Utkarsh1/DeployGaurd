import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { Globe, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";

const formSchema = z.object({
  url: z.preprocess(
    (val) => {
      if (typeof val !== "string") return val;
      const trimmed = val.trim();
      if (!trimmed) return trimmed;
      if (/^https?:\/\//i.test(trimmed)) return trimmed;
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return trimmed;
      return `https://${trimmed}`;
    },
    z.string().min(1, "Please enter a URL").url("Please enter a valid URL (e.g. github.com)")
  ),
});

type FormValues = z.infer<typeof formSchema>;

interface ScanInputProps {
  onScan: (url: string) => void;
  isScanning: boolean;
  scanKey?: number;
}

export function ScanInput({ onScan, isScanning, scanKey }: ScanInputProps) {
  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: { url: "" },
  });

  useEffect(() => {
    if (scanKey) form.reset({ url: "" });
  }, [scanKey, form]);

  function onSubmit(values: FormValues) {
    onScan(values.url);
  }

  return (
    <div className="w-full max-w-2xl mx-auto space-y-4 text-center">
      <div className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tighter sm:text-4xl md:text-5xl">
          Is your app ready to ship?
        </h1>
        <p className="mx-auto max-w-[600px] text-muted-foreground md:text-xl">
          Run a comprehensive security, SEO, and performance check before you go live.
        </p>
      </div>

      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="mt-8 flex flex-col sm:flex-row gap-3">
          <FormField
            control={form.control}
            name="url"
            render={({ field }) => (
              <FormItem className="flex-1">
                <FormControl>
                  <div className="relative">
                    <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                    <Input
                      placeholder="https://your-staging-url.com"
                      className="pl-10 h-12 text-lg bg-card"
                      disabled={isScanning}
                      {...field}
                    />
                  </div>
                </FormControl>
                <FormMessage className="text-left" />
              </FormItem>
            )}
          />
          <Button type="submit" size="lg" disabled={isScanning} className="h-12 px-8">
            {isScanning ? (
              <>
                <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                Scanning
              </>
            ) : (
              "Scan URL"
            )}
          </Button>
        </form>
      </Form>
    </div>
  );
}
