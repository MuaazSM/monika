import { cn } from "@/lib/utils";

export function Mono({ className, ...props }: React.HTMLAttributes<HTMLSpanElement>) {
  return <span className={cn("mono", className)} {...props} />;
}
