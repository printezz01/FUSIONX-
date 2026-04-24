// ═══════════════════════════════════════════════════
// Sentinel AI — Main App Entry Point
// React Router + TanStack Query + Toast setup
// ═══════════════════════════════════════════════════

import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'react-hot-toast';
import { lazy, Suspense } from 'react';

import AppLayout from './components/AppLayout';
import HomePage from './pages/HomePage';
import LiveScanPage from './pages/LiveScanPage';
import DashboardPage from './pages/DashboardPage';
import ChatPage from './pages/ChatPage';

// Lazy-load Cytoscape route for performance
const ChainPage = lazy(() => import('./pages/ChainPage'));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 5000,
    },
  },
});

function ChainPageWrapper() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center h-64">
          <div className="text-[#8a8e7c] text-sm">Loading attack chain visualizer...</div>
        </div>
      }
    >
      <ChainPage />
    </Suspense>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<AppLayout />}>
            <Route path="/" element={<HomePage />} />
            <Route path="/scan/:id/live" element={<LiveScanPage />} />
            <Route path="/scan/:id/dashboard" element={<DashboardPage />} />
            <Route path="/scan/:id/chain" element={<ChainPageWrapper />} />
            <Route path="/scan/:id/chat" element={<ChatPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#232820',
            color: '#e8e4dc',
            borderRadius: '12px',
            fontSize: '13px',
            fontFamily: 'Inter, sans-serif',
            border: '1px solid #3a4234',
          },
          success: {
            iconTheme: {
              primary: '#7a9c5e',
              secondary: '#e8e4dc',
            },
          },
          error: {
            iconTheme: {
              primary: '#c75050',
              secondary: '#e8e4dc',
            },
          },
        }}
      />
    </QueryClientProvider>
  );
}
