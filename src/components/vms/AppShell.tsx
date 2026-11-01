import { useState, type ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import {
  LayoutDashboard, Siren, BarChart3, Cctv, BrainCircuit, ShieldAlert, Network, Vault, ScrollText,
  Menu, Bell, Search, ShieldCheck, PanelLeftClose, PanelLeftOpen,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { StatusDot } from "./ui";

const nav = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/incidents", label: "Live Incidents", icon: Siren },
  { to: "/analytics", label: "Analytics", icon: BarChart3 },
  { to: "/cameras", label: "Camera Management", icon: Cctv },
  { to: "/ai-analysis", label: "AI Video Analysis", icon: BrainCircuit },
  { to: "/cyber", label: "Cybersecurity Monitor", icon: ShieldAlert },
  { to: "/correlation", label: "Threat Correlation", icon: Network },
  { to: "/evidence", label: "Evidence Vault", icon: Vault },
  { to: "/audit", label: "Audit Logs", icon: ScrollText },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  const path = useRouterState({ select: (s) => s.location.pathname });
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const current = nav.find((n) => n.to === path);

  return (
    <div className="flex min-h-screen w-full">
      {mobileOpen && <div className="fixed inset-0 z-30 bg-background/70 lg:hidden" onClick={() => setMobileOpen(false)} />}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex flex-col border-r border-sidebar-border bg-sidebar transition-all lg:sticky lg:top-0 lg:h-screen",
          collapsed ? "w-16" : "w-64",
          mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0",
        )}
      >
        <div className="flex h-16 items-center gap-2 border-b border-sidebar-border px-4">
          <span className="glow-primary flex size-8 shrink-0 items-center justify-center rounded-md bg-primary text-primary-foreground">
            <ShieldCheck className="size-4" />
          </span>
          {!collapsed && (
            <div className="leading-tight">
              <p className="text-sm font-semibold">Secure VMS</p>
              <p className="text-[10px] uppercase tracking-widest text-cyan">Cyber-Physical SOC</p>
            </div>
          )}
        </div>
        <nav className="flex-1 space-y-0.5 overflow-y-auto p-2">
          {nav.map((n) => {
            const active = path === n.to;
            return (
              <Link
                key={n.to} to={n.to} onClick={() => setMobileOpen(false)} title={n.label}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm text-sidebar-foreground transition-colors hover:bg-sidebar-accent",
                  active && "bg-sidebar-accent text-sidebar-accent-foreground shadow-[inset_2px_0_0_var(--primary)]",
                )}
              >
                <n.icon className={cn("size-4 shrink-0", active && "text-primary")} />
                {!collapsed && <span className="truncate">{n.label}</span>}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-sidebar-border p-3">
          <button onClick={() => setCollapsed((c) => !c)} className="hidden w-full items-center gap-2 rounded-md px-2 py-1.5 text-xs text-muted-foreground hover:bg-sidebar-accent lg:flex">
            {collapsed ? <PanelLeftOpen className="size-4" /> : <><PanelLeftClose className="size-4" /> Collapse</>}
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b bg-background/85 px-4 backdrop-blur lg:px-6">
          <button className="rounded-md p-2 hover:bg-accent lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open menu">
            <Menu className="size-5" />
          </button>
          <p className="hidden text-sm text-muted-foreground md:block">
            Command Center <span className="mx-1">/</span> <span className="text-foreground">{current?.label ?? "Page"}</span>
          </p>
          <div className="ml-auto flex items-center gap-3">
            <div className="hidden items-center gap-2 rounded-md border bg-panel px-3 py-1.5 sm:flex">
              <Search className="size-4 text-muted-foreground" />
              <input placeholder="Search incidents, cameras, IPs…" className="w-56 bg-transparent text-sm outline-none placeholder:text-muted-foreground" />
            </div>
            <span className="hidden items-center gap-2 rounded-md border border-success/30 bg-success/10 px-2.5 py-1 text-xs text-success md:flex">
              <StatusDot tone="success" /> All systems nominal
            </span>
            <button className="relative rounded-md p-2 hover:bg-accent" aria-label="Notifications">
              <Bell className="size-5" />
              <span className="absolute right-1.5 top-1.5 size-2 rounded-full bg-critical" />
            </button>
            <span className="flex size-8 items-center justify-center rounded-full bg-accent text-xs font-semibold">JM</span>
          </div>
        </header>
        <main className="flex-1 p-4 lg:p-6">{children}</main>
      </div>
    </div>
  );
}
