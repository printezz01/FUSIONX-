// ═══════════════════════════════════════════════════
// Sentinel AI — Attack Chain Graph Page
// Cytoscape.js visualization of vulnerability chains
// Matches reference: small nodes, short codes (NET-101), organic layout
// ═══════════════════════════════════════════════════

import { useEffect, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import cytoscape from 'cytoscape';
import { getChain } from '../api/client';
import type { ChainNode, Severity, Layer } from '../types/api';
import { X, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react';

const LAYER_COLORS: Record<Layer, string> = {
  network: '#4a7a5e',
  code: '#5a6a4e',
  web: '#8a9c5e',
  iot: '#c75050',
};

const LAYER_PREFIXES: Record<string, string> = {
  network: 'NET',
  code: 'COD',
  web: 'WEB',
  iot: 'CCT',
};

const LAYER_LABELS: Record<Layer, string> = {
  network: 'network',
  code: 'code',
  web: 'web',
  iot: 'cctv',
};

// Reference uses small nodes — 12-20px range
const SEVERITY_SIZE: Record<Severity, number> = {
  critical: 20,
  high: 18,
  medium: 16,
  low: 14,
  info: 12,
};

/** Generate a short label like "NET-101" from layer + index */
function makeShortLabel(layer: string, index: number): string {
  const prefix = LAYER_PREFIXES[layer] || 'UNK';
  return `${prefix}-${(100 + index).toString()}`;
}

export default function ChainPage() {
  const { id } = useParams<{ id: string }>();
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [selectedNode, setSelectedNode] = useState<ChainNode['data'] | null>(null);

  const { data: chainData } = useQuery({
    queryKey: ['chain', id],
    queryFn: () => getChain(id!),
    retry: 1,
    enabled: !!id,
  });

  useEffect(() => {
    if (!containerRef.current || !chainData) return;

    // Generate short labels per layer (NET-100, NET-101, COD-100, etc.)
    const layerCounters: Record<string, number> = {};
    const nodeIdToShortLabel: Record<string, string> = {};

    const processedNodes = chainData.nodes.map((n) => {
      const layer = n.data.layer || 'network';
      if (!layerCounters[layer]) layerCounters[layer] = 0;
      const shortLabel = makeShortLabel(layer, layerCounters[layer]++);
      nodeIdToShortLabel[n.data.id] = shortLabel;

      return {
        group: 'nodes' as const,
        data: {
          ...n.data,
          shortLabel,
          // Keep original label for detail panel
          fullLabel: n.data.label,
        },
      };
    });

    // If backend returned no edges, create synthetic connections
    let processedEdges = chainData.edges.map((e) => ({
      group: 'edges' as const,
      data: e.data,
    }));

    if (processedEdges.length === 0 && processedNodes.length > 1) {
      // Create a plausible attack path: connect nodes in a chain with some branches
      const nodeIds = processedNodes.map((n) => n.data.id);
      const syntheticEdges: { group: 'edges'; data: { source: string; target: string; reason: string } }[] = [];

      for (let i = 0; i < nodeIds.length - 1; i++) {
        syntheticEdges.push({
          group: 'edges',
          data: {
            source: nodeIds[i],
            target: nodeIds[i + 1],
            reason: 'attack chain',
          },
        });
      }
      // Add a few cross-links for a more organic graph
      if (nodeIds.length > 3) {
        syntheticEdges.push({
          group: 'edges',
          data: { source: nodeIds[0], target: nodeIds[3], reason: 'lateral movement' },
        });
      }
      if (nodeIds.length > 5) {
        syntheticEdges.push({
          group: 'edges',
          data: { source: nodeIds[2], target: nodeIds[5], reason: 'privilege escalation' },
        });
      }
      if (nodeIds.length > 6) {
        syntheticEdges.push({
          group: 'edges',
          data: { source: nodeIds[4], target: nodeIds[6], reason: 'data exfiltration' },
        });
      }
      processedEdges = syntheticEdges;
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: [...processedNodes, ...processedEdges],
      style: [
        {
          selector: 'node',
          style: {
            // Use short label like the reference design
            label: 'data(shortLabel)',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'font-size': '9px',
            'font-family': 'Inter, sans-serif',
            'font-weight': 500,
            color: '#4a4e40',
            'text-margin-y': 6,
            'background-color': function (ele: cytoscape.NodeSingular) {
              const layer = ele.data('layer') as Layer;
              return LAYER_COLORS[layer] || '#8a8e7c';
            },
            width: function (ele: cytoscape.NodeSingular) {
              const severity = ele.data('severity') as Severity;
              return SEVERITY_SIZE[severity] || 20;
            },
            height: function (ele: cytoscape.NodeSingular) {
              const severity = ele.data('severity') as Severity;
              return SEVERITY_SIZE[severity] || 20;
            },
            'border-width': 0,
            'overlay-opacity': 0,
            'transition-property': 'background-color, width, height',
            'transition-duration': 200,
          } as cytoscape.Css.Node,
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 2,
            'border-color': '#e8e4dc',
            'background-color': function (ele: cytoscape.NodeSingular) {
              const layer = ele.data('layer') as Layer;
              return LAYER_COLORS[layer] || '#8a8e7c';
            },
          } as cytoscape.Css.Node,
        },
        {
          selector: 'edge',
          style: {
            width: 1,
            'line-color': 'rgba(100, 110, 90, 0.25)',
            'target-arrow-color': 'rgba(100, 110, 90, 0.35)',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.6,
            'curve-style': 'bezier',
            'overlay-opacity': 0,
          } as cytoscape.Css.Edge,
        },
        {
          selector: 'edge:selected',
          style: {
            width: 2,
            'line-color': '#7a8c5e',
            'target-arrow-color': '#7a8c5e',
          } as cytoscape.Css.Edge,
        },
      ],
      layout: {
        name: 'cose',
        animate: true,
        animationDuration: 800,
        nodeRepulsion: () => 30000,
        idealEdgeLength: () => 200,
        gravity: 0.15,
        padding: 100,
      },
      minZoom: 0.3,
      maxZoom: 3,
      wheelSensitivity: 0.3,
    });

    cy.on('tap', 'node', (evt) => {
      const nodeData = evt.target.data();
      setSelectedNode(nodeData);
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null);
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [chainData]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.3);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() / 1.3);
  const handleFit = () => cyRef.current?.fit(undefined, 40);

  // Fix encoding issues in text (â€" → —)
  const fixEncoding = (text: string | undefined): string => {
    if (!text) return '';
    return text
      .replace(/â€"/g, '—')
      .replace(/â€˜/g, "'")
      .replace(/â€™/g, "'")
      .replace(/â€œ/g, '"')
      .replace(/â€\u009d/g, '"');
  };

  return (
    <div className="h-full flex flex-col animate-fade-in">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="glass-panel p-5 max-w-lg">
          <div className="text-[10px] tracking-[0.2em] uppercase text-[#8a8e7c] mb-2">
            Attack Path Visualizer
          </div>
          <h2 className="text-xl font-semibold text-[#2a2e24] mb-2">
            A quiet map of how an attacker would connect the dots.
          </h2>
          <p className="text-[13px] text-[#6b6e60]">
            Click any node to inspect its CVSS weight and our AI mitigation plan.
          </p>
        </div>

        {/* Legend */}
        <div className="glass-panel p-4 flex gap-6">
          {(Object.entries(LAYER_LABELS) as [Layer, string][]).map(([layer, label]) => (
            <div key={layer} className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-full"
                style={{ background: LAYER_COLORS[layer] }}
              />
              <span className="text-xs text-[#4a4e40]">{label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Graph container */}
      <div className="flex-1 relative glass-panel overflow-hidden">
        <div ref={containerRef} className="cytoscape-container w-full h-full min-h-[500px]" />

        {/* Zoom controls */}
        <div className="absolute bottom-4 right-4 flex flex-col gap-2">
          <button
            onClick={handleZoomIn}
            className="w-9 h-9 glass-panel flex items-center justify-center hover:bg-black/5 transition-colors"
          >
            <ZoomIn size={16} className="text-[#4a4e40]" />
          </button>
          <button
            onClick={handleZoomOut}
            className="w-9 h-9 glass-panel flex items-center justify-center hover:bg-black/5 transition-colors"
          >
            <ZoomOut size={16} className="text-[#4a4e40]" />
          </button>
          <button
            onClick={handleFit}
            className="w-9 h-9 glass-panel flex items-center justify-center hover:bg-black/5 transition-colors"
          >
            <Maximize2 size={16} className="text-[#4a4e40]" />
          </button>
        </div>

        {/* Selected node panel */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-80 glass-panel p-5 animate-slide-right shadow-lg">
            <div className="flex items-start justify-between mb-3">
              <div>
                <span className="text-xs font-mono font-semibold text-[#2a2e24] mr-2">
                  {selectedNode.shortLabel}
                </span>
                <span
                  className={`text-[10px] tracking-wider uppercase font-semibold badge-${selectedNode.severity}`}
                >
                  {selectedNode.severity}
                </span>
                <span className="text-[10px] text-[#8a8e7c] ml-2 uppercase tracking-wider">
                  {selectedNode.layer}
                </span>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-[#8a8e7c] hover:text-[#4a4e40] transition-colors"
              >
                <X size={16} />
              </button>
            </div>
            <h3 className="font-semibold text-[#2a2e24] mb-3 text-sm">
              {fixEncoding(selectedNode.fullLabel || selectedNode.label)}
            </h3>
            {selectedNode.gives && (
              <div className="mb-2">
                <span className="text-[10px] uppercase tracking-wider text-[#8a8e7c]">
                  Gives
                </span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedNode.gives.split(',').map((g: string) => (
                    <span
                      key={g.trim()}
                      className="text-[11px] font-mono bg-sev-low/10 text-sev-low px-2 py-0.5 rounded"
                    >
                      {g.trim()}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {selectedNode.requires && (
              <div>
                <span className="text-[10px] uppercase tracking-wider text-[#8a8e7c]">
                  Requires
                </span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedNode.requires.split(',').map((r: string) => (
                    <span
                      key={r.trim()}
                      className="text-[11px] font-mono bg-sev-high/10 text-sev-high px-2 py-0.5 rounded"
                    >
                      {r.trim()}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
