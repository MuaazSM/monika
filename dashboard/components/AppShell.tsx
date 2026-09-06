"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, CircleDot, Gauge, LayoutDashboard, Settings, Shield, SlidersHorizontal } from "lucide-react";
import { useEffect, useState } from "react";
import { usingFixtures } from "@/lib/api";

const navigation = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/incidents", label: "Incidents", icon: Shield },
  { href: "/endpoints", label: "Endpoints", icon: Gauge },
  { href: "/simulator", label: "Simulator", icon: SlidersHorizontal },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [clock, setClock] = useState("");

  useEffect(() => {
    const update = () => setClock(new Intl.DateTimeFormat("en", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false, timeZone: "UTC" }).format());
    update();
    const timer = window.setInterval(update, 1000);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <aside className="fixed inset-y-0 left-0 hidden w-64 border-r border-zinc-800/80 bg-zinc-950 lg:block">
        <div className="flex h-20 items-center gap-3 border-b border-zinc-800/80 px-7">
          <div className="flex size-8 items-center justify-center rounded-md bg-indigo-400 text-zinc-950"><Activity size={17} /></div>
          <div><p className="text-sm font-semibold tracking-wide">MONIKA</p><p className="mono text-[10px] text-zinc-500">CONTROL PLANE</p></div>
        </div>
        <nav className="space-y-1 p-4" aria-label="Primary navigation">
          {navigation.map(({ href, label, icon: Icon }) => {
            const active = href === "/" ? pathname === href : pathname.startsWith(href);
            return <Link key={href} href={href} className={`nav-link ${active ? "nav-link-active" : ""}`}><Icon size={16} />{label}</Link>;
          })}
        </nav>
        <div className="absolute bottom-6 left-4 right-4 border-t border-zinc-800 pt-4 text-xs text-zinc-500"><p className="mono">ENGINE v0.1.0</p><p className="mt-1">{usingFixtures ? "Fixture environment" : "Live environment"}</p></div>
      </aside>
      <div className="lg:pl-64">
        <header className="flex h-20 items-center justify-between border-b border-zinc-800/80 px-6 sm:px-8">
          <div className="flex items-center gap-2 text-sm text-zinc-400"><CircleDot size={14} className="text-emerald-400" /><span>PROTECTED</span></div>
          <time className="mono text-xs text-zinc-500" dateTime={clock}>{clock || "--:--:--"} UTC</time>
        </header>
        <main className="mx-auto max-w-[1600px] p-6 sm:p-8">{children}</main>
      </div>
    </div>
  );
}
