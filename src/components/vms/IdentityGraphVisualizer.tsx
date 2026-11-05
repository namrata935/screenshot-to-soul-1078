import { useState, useMemo } from "react";
import {
  User,
  Laptop,
  Globe,
  Camera,
  Search,
  Filter,
  ShieldAlert,
  Info,
  RefreshCw,
  ExternalLink,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  type GraphResponse,
  type GraphNode,
  type GraphEdge,
} from "@/lib/cyber-api";

interface IdentityGraphVisualizerProps {
  graph: GraphResponse;
  isLoading?: boolean;
  onRefresh?: () => void;
  onFilterAlertsByEntity?: (entityType: string, entityId: string) => void;
}

export function IdentityGraphVisualizer({
  graph,
  isLoading = false,
  onRefresh,
  onFilterAlertsByEntity,
}: IdentityGraphVisualizerProps) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>("ip:185.220.101.4");
  const [filterType, setFilterType] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Map nodes and edges
  const { nodes, edges } = graph;

  // Filter nodes according to search and type
  const matchingNodeIds = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    return new Set(
      nodes
        .filter((n) => {
          if (filterType !== "all" && n.type !== filterType) return false;
          if (q && !n.label.toLowerCase().includes(q) && !n.entity_id.toLowerCase().includes(q)) {
            return false;
          }
          return true;
        })
        .map((n) => n.id)
    );
  }, [nodes, filterType, searchQuery]);

  // Determine Blast Radius for selected node (neighbors)
  const { blastNodeIds, blastEdgeIndices } = useMemo(() => {
    if (!selectedNodeId) {
      return { blastNodeIds: new Set<string>(), blastEdgeIndices: new Set<number>() };
    }
    const bNodes = new Set<string>([selectedNodeId]);
    const bEdges = new Set<number>();

    // 1-hop
    edges.forEach((e, idx) => {
      if (e.source === selectedNodeId) {
        bNodes.add(e.target);
        bEdges.add(idx);
      } else if (e.target === selectedNodeId) {
        bNodes.add(e.source);
        bEdges.add(idx);
      }
    });

    // 2-hop expansion for blast radius
    edges.forEach((e, idx) => {
      if (bNodes.has(e.source) || bNodes.has(e.target)) {
        bNodes.add(e.source);
        bNodes.add(e.target);
        bEdges.add(idx);
      }
    });

    return { blastNodeIds: bNodes, blastEdgeIndices: bEdges };
  }, [selectedNodeId, edges]);

  // Selected Node Details
  const selectedNode = useMemo(() => {
    return nodes.find((n) => n.id === selectedNodeId) || null;
  }, [nodes, selectedNodeId]);

  // Connected entities for selected node
  const connectedRelations = useMemo(() => {
    if (!selectedNodeId) return [];
    const rels: Array<{ target: GraphNode; relation: string; weight: number }> = [];

    edges.forEach((e) => {
      if (e.source === selectedNodeId) {
        const targetNode = nodes.find((n) => n.id === e.target);
        if (targetNode) rels.push({ target: targetNode, relation: e.relation, weight: e.weight });
      } else if (e.target === selectedNodeId) {
        const sourceNode = nodes.find((n) => n.id === e.source);
        if (sourceNode) rels.push({ target: sourceNode, relation: e.relation, weight: e.weight });
      }
    });
    return rels;
  }, [selectedNodeId, edges, nodes]);

  // SVG Node Layout Coordinates (Multi-Tier Column Layout)
  // Column 1: Users (x = 100)
  // Column 2: Devices (x = 320)
  // Column 3: IPs (x = 540)
  // Column 4: Cameras (x = 760)
  const nodePositions = useMemo(() => {
    const coords: Record<string, { x: number; y: number }> = {};
    const tiers: Record<string, GraphNode[]> = {
      user: [],
      device: [],
      ip: [],
      camera: [],
    };

    nodes.forEach((n) => {
      if (tiers[n.type]) {
        tiers[n.type].push(n);
      } else {
        tiers.user.push(n);
      }
    });

    const xMap = { user: 80, device: 290, ip: 520, camera: 750 };
    const height = 480;

    Object.entries(tiers).forEach(([type, typeNodes]) => {
      const x = xMap[type as keyof typeof xMap] || 80;
      const count = typeNodes.length;
      typeNodes.forEach((node, i) => {
        const y = count === 1 ? height / 2 : 60 + (i / Math.max(count - 1, 1)) * (height - 120);
        coords[node.id] = { x, y };
      });
    });

    return coords;
  }, [nodes]);

  const getNodeColor = (type: string, isAlert = false) => {
    if (isAlert) return "stroke-critical fill-critical/20 text-critical";
    switch (type) {
      case "user":
        return "stroke-cyan fill-cyan/15 text-cyan";
      case "device":
        return "stroke-purple-400 fill-purple-400/15 text-purple-400";
      case "ip":
        return "stroke-amber-400 fill-amber-400/15 text-amber-400";
      case "camera":
        return "stroke-emerald-400 fill-emerald-400/15 text-emerald-400";
      default:
        return "stroke-primary fill-primary/15 text-primary";
    }
  };

  const getNodeIcon = (type: string) => {
    switch (type) {
      case "user":
        return User;
      case "device":
        return Laptop;
      case "ip":
        return Globe;
      case "camera":
        return Camera;
      default:
        return Info;
    }
  };

  return (
    <div className="space-y-4">
      {/* Controls & Search */}
      <div className="flex flex-col gap-3 rounded-lg border border-border/70 bg-card p-3 md:flex-row md:items-center md:justify-between">
        <div className="flex flex-wrap items-center gap-2">
          {/* Entity Type Filter Tabs */}
          <div className="inline-flex rounded-md border border-border/80 bg-background/50 p-0.5 text-xs">
            {(["all", "user", "device", "ip", "camera"] as const).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setFilterType(t)}
                className={cn(
                  "rounded px-2.5 py-1 font-medium capitalize transition-colors",
                  filterType === t
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                {t === "all" ? "All Entities" : `${t}s`}
              </button>
            ))}
          </div>

          {selectedNodeId && (
            <button
              type="button"
              onClick={() => setSelectedNodeId(null)}
              className="rounded-md border border-border bg-background px-2.5 py-1 text-xs text-muted-foreground hover:bg-muted hover:text-foreground"
            >
              Clear Blast Radius
            </button>
          )}
        </div>

        <div className="flex items-center gap-2">
          <div className="relative flex-1 md:w-64">
            <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search user, device, IP, camera..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-md border border-border bg-background py-1 pl-8 pr-3 text-xs text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none"
            />
          </div>
          {onRefresh && (
            <button
              type="button"
              onClick={onRefresh}
              disabled={isLoading}
              title="Refresh graph"
              className="inline-flex size-7 items-center justify-center rounded-md border border-border bg-background text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-50"
            >
              <RefreshCw className={cn("size-3.5", isLoading && "animate-spin text-primary")} />
            </button>
          )}
        </div>
      </div>

      {/* Main Graph Area + Inspector Drawer */}
      <div className="grid gap-4 lg:grid-cols-4">
        {/* SVG Interactive Canvas */}
        <div className="relative rounded-lg border border-border bg-terminal/70 p-4 lg:col-span-3 overflow-hidden">
          {/* Legend Header */}
          <div className="mb-2 flex flex-wrap items-center justify-between gap-3 border-b border-border/50 pb-2 text-[11px]">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1.5 text-cyan">
                <span className="size-2 rounded-full bg-cyan" /> Users (Identity)
              </span>
              <span className="flex items-center gap-1.5 text-purple-400">
                <span className="size-2 rounded-full bg-purple-400" /> Devices
              </span>
              <span className="flex items-center gap-1.5 text-amber-400">
                <span className="size-2 rounded-full bg-amber-400" /> IP Addresses
              </span>
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="size-2 rounded-full bg-emerald-400" /> Cameras
              </span>
            </div>
            <div className="font-mono text-[10px] text-muted-foreground">
              Click node to calculate forensic blast radius
            </div>
          </div>

          <svg
            viewBox="0 0 840 480"
            className="w-full h-auto select-none"
            style={{ maxHeight: "520px" }}
          >
            <defs>
              <marker
                id="arrow"
                viewBox="0 0 10 10"
                refX="18"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(148, 163, 184, 0.4)" />
              </marker>
              <marker
                id="arrow-active"
                viewBox="0 0 10 10"
                refX="18"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#06b6d4" />
              </marker>
            </defs>

            {/* Edge Lines */}
            {edges.map((e, idx) => {
              const p1 = nodePositions[e.source];
              const p2 = nodePositions[e.target];
              if (!p1 || !p2) return null;

              const isBlastEdge = blastEdgeIndices.has(idx);
              const isDimmed = selectedNodeId && !isBlastEdge;

              // Bezier curve
              const dx = (p2.x - p1.x) / 2;
              const pathD = `M ${p1.x} ${p1.y} C ${p1.x + dx} ${p1.y}, ${p2.x - dx} ${p2.y}, ${p2.x} ${p2.y}`;

              return (
                <g key={`edge-${idx}`}>
                  <path
                    d={pathD}
                    fill="none"
                    stroke={isBlastEdge ? "#06b6d4" : "rgba(148, 163, 184, 0.25)"}
                    strokeWidth={isBlastEdge ? 2 : 1}
                    strokeDasharray={e.relation === "ACCESSED_CAMERA" ? "4 3" : undefined}
                    opacity={isDimmed ? 0.12 : 0.8}
                    className="transition-all duration-300"
                  />
                  {/* Subtle Relationship Label on mid-point if blast edge */}
                  {isBlastEdge && (
                    <text
                      x={(p1.x + p2.x) / 2}
                      y={(p1.y + p2.y) / 2 - 4}
                      fill="#06b6d4"
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                      className="select-none pointer-events-none"
                    >
                      {e.relation}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Nodes */}
            {nodes.map((node) => {
              const pos = nodePositions[node.id];
              if (!pos) return null;

              const isSelected = selectedNodeId === node.id;
              const isInBlast = blastNodeIds.has(node.id);
              const isDimmed = selectedNodeId && !isInBlast;
              const isSearchMatch = matchingNodeIds.has(node.id);
              const isAlert = node.metadata?.compromised || node.metadata?.threat_level === "critical" || node.metadata?.alert;

              const Icon = getNodeIcon(node.type);

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  onClick={() => setSelectedNodeId(isSelected ? null : node.id)}
                  className="cursor-pointer transition-transform duration-200 hover:scale-110"
                  opacity={isDimmed ? (isSearchMatch ? 0.3 : 0.15) : 1}
                >
                  {/* Glow circle if selected */}
                  {isSelected && (
                    <circle
                      r="22"
                      className="animate-ping fill-cyan/20 stroke-cyan/60 stroke-2"
                    />
                  )}

                  {/* Node Circle */}
                  <circle
                    r={isSelected ? "17" : "14"}
                    className={cn(
                      "transition-all duration-200 stroke-2",
                      getNodeColor(node.type, Boolean(isAlert)),
                      isSelected && "stroke-cyan fill-cyan/30 stroke-[2.5px]"
                    )}
                  />

                  {/* Icon centered in node */}
                  <foreignObject
                    x={isSelected ? -10 : -8}
                    y={isSelected ? -10 : -8}
                    width={isSelected ? 20 : 16}
                    height={isSelected ? 20 : 16}
                    className="pointer-events-none"
                  >
                    <Icon className={cn("size-full", isAlert ? "text-critical" : "text-foreground")} />
                  </foreignObject>

                  {/* Node Label */}
                  <text
                    y={isSelected ? "27" : "24"}
                    textAnchor="middle"
                    fill="currentColor"
                    fontSize={isSelected ? "11" : "10"}
                    fontWeight={isSelected ? "600" : "500"}
                    fontFamily="monospace"
                    className="select-none text-foreground/90 pointer-events-none"
                  >
                    {node.label.length > 18 ? `${node.label.slice(0, 16)}…` : node.label}
                  </text>

                  {/* Event count badge */}
                  <text
                    y={isSelected ? "37" : "34"}
                    textAnchor="middle"
                    fill="var(--muted-foreground)"
                    fontSize="8"
                    fontFamily="monospace"
                    className="select-none pointer-events-none"
                  >
                    {node.event_count} events
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Node Inspector / Blast Radius Card */}
        <div className="flex flex-col rounded-lg border border-border bg-card p-4">
          <div className="mb-3 flex items-center justify-between border-b border-border/70 pb-2">
            <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              <Zap className="size-3.5 text-cyan" />
              Forensic Inspector
            </h3>
            {selectedNode && (
              <span className="rounded bg-primary/20 px-1.5 py-0.5 font-mono text-[10px] text-cyan capitalize">
                {selectedNode.type}
              </span>
            )}
          </div>

          {selectedNode ? (
            <div className="space-y-4 text-xs">
              <div>
                <p className="font-mono text-sm font-semibold text-foreground">{selectedNode.label}</p>
                <p className="font-mono text-[11px] text-muted-foreground">ID: {selectedNode.entity_id}</p>
              </div>

              {selectedNode.metadata && Object.keys(selectedNode.metadata).length > 0 && (
                <div className="rounded border border-critical/30 bg-critical/10 p-2 text-critical">
                  <p className="font-medium text-[11px] uppercase tracking-wider">Security Flag</p>
                  <p className="text-[11px]">{JSON.stringify(selectedNode.metadata)}</p>
                </div>
              )}

              <div className="grid grid-cols-2 gap-2 rounded border border-border/60 bg-muted/20 p-2 font-mono text-[11px]">
                <div>
                  <span className="text-muted-foreground block text-[10px]">TOTAL EVENTS</span>
                  <span className="font-bold text-foreground">{selectedNode.event_count}</span>
                </div>
                <div>
                  <span className="text-muted-foreground block text-[10px]">BLAST RADIUS</span>
                  <span className="font-bold text-cyan">{blastNodeIds.size - 1} entities</span>
                </div>
              </div>

              {/* Connected Relationships */}
              <div>
                <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Connected Entities ({connectedRelations.length})
                </p>
                <div className="max-h-48 space-y-1.5 overflow-y-auto pr-1">
                  {connectedRelations.map((rel, i) => (
                    <div
                      key={i}
                      onClick={() => setSelectedNodeId(rel.target.id)}
                      className="group flex cursor-pointer items-center justify-between rounded border border-border/50 bg-background/50 p-1.5 transition-colors hover:border-cyan hover:bg-muted/40"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-[10px] text-cyan">[{rel.relation}]</span>
                        <span className="font-mono text-[11px] font-medium text-foreground">
                          {rel.target.label}
                        </span>
                      </div>
                      <span className="font-mono text-[10px] text-muted-foreground">
                        w: {rel.weight}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Action Button: Filter Alerts */}
              {onFilterAlertsByEntity && (
                <button
                  type="button"
                  onClick={() => onFilterAlertsByEntity(selectedNode.type, selectedNode.entity_id)}
                  className="w-full flex items-center justify-center gap-1.5 rounded-md border border-cyan/40 bg-cyan/10 py-1.5 text-xs font-semibold text-cyan transition-colors hover:bg-cyan hover:text-black"
                >
                  <Filter className="size-3" />
                  Filter Alerts For This {selectedNode.type}
                </button>
              )}
            </div>
          ) : (
            <div className="my-auto py-12 text-center text-muted-foreground">
              <Info className="mx-auto mb-2 size-6 opacity-40 text-cyan" />
              <p className="text-xs font-medium text-foreground">No Entity Selected</p>
              <p className="text-[11px] text-muted-foreground">
                Click any User, Device, IP, or Camera in the graph to visualize its forensic blast radius.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

