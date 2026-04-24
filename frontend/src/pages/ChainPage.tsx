// ═══════════════════════════════════════════════════
// Sentinel AI — Attack Chain Graph Page
// Cytoscape.js visualization of vulnerability chains
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

const LAYER_LABELS: Record<Layer, string> = {
  network: 'network',
  code: 'code',
  web: 'web',
  iot: 'cctv',
};

const SEVERITY_SIZE: Record<Severity, number> = {
  critical: 50,
  high: 42,
  medium: 36,
  low: 30,
  info: 26,
};

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

    const cy = cytoscape({
      container: containerRef.current,
      elements: [
        ...chainData.nodes.map((n) => ({
          group: 'nodes' as const,
          data: {
            ...n.data,
            label: n.data.label,
          },
        })),
        ...chainData.edges.map((e) => ({
          group: 'edges' as const,
          data: e.data,
        })),
      ],
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'font-size': '10px',
            'font-family': 'Inter, sans-serif',
            color: '#4a4e40',
            'text-margin-y': 8,
            'text-wrap': 'wrap',
            'text-max-width': '100px',
            'background-color': function (ele: cytoscape.NodeSingular) {
              const layer = ele.data('layer') as Layer;
              return LAYER_COLORS[layer] || '#8a8e7c';
            },
            width: function (ele: cytoscape.NodeSingular) {
              const severity = ele.data('severity') as Severity;
              return SEVERITY_SIZE[severity] || 30;
            },
            height: function (ele: cytoscape.NodeSingular) {
              const severity = ele.data('severity') as Severity;
              return SEVERITY_SIZE[severity] || 30;
            },
            'border-width': 2,
            'border-color': 'rgba(255,255,255,0.2)',
            'overlay-opacity': 0,
            'transition-property': 'background-color, width, height',
            'transition-duration': 200,
          } as cytoscape.Css.Node,
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 3,
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
            width: 1.5,
            'line-color': 'rgba(100, 110, 90, 0.3)',
            'target-arrow-color': 'rgba(100, 110, 90, 0.5)',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.8,
            'curve-style': 'bezier',
            'overlay-opacity': 0,
          } as cytoscape.Css.Edge,
        },
        {
          selector: 'edge:selected',
          style: {
            width: 2.5,
            'line-color': '#7a8c5e',
            'target-arrow-color': '#7a8c5e',
          } as cytoscape.Css.Edge,
        },
      ],
      layout: {
        name: 'cose',
        animate: true,
        animationDuration: 800,
        nodeRepulsion: () => 8000,
        idealEdgeLength: () => 120,
        gravity: 0.5,
        padding: 60,
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
            <h3 className="font-semibold text-[#2a2e24] mb-3">{selectedNode.label}</h3>
            {selectedNode.gives && (
              <div className="mb-2">
                <span className="text-[10px] uppercase tracking-wider text-[#8a8e7c]">
                  Gives
                </span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedNode.gives.split(',').map((g) => (
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
                  {selectedNode.requires.split(',').map((r) => (
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
