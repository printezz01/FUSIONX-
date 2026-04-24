# Sentinel AI — Frontend

React 18 + Vite + TypeScript + Tailwind CSS frontend for the Sentinel AI security intelligence platform.

## Setup

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

The app starts at `http://localhost:5173/`.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_BASE_URL` | `http://localhost:8000` | Backend API URL |
| `VITE_USE_MOCKS` | `false` | Set to `true` to use static mock data |

## Stack

- **React 18** with Vite
- **TypeScript** (strict mode)
- **Tailwind CSS** (v4 with `@tailwindcss/vite`)
- **React Router** for navigation
- **TanStack Query** for API calls and polling
- **Cytoscape.js** for attack chain graph
- **Recharts** for severity charts
- **lucide-react** for icons
- **react-hot-toast** for notifications

## Mock Mode

Set `VITE_USE_MOCKS=true` in `.env` to run the frontend without a backend. All API calls return realistic fixture data including:
- 20 findings across network, code, web, and IoT layers
- Attack chain with 14 nodes and 15 edges
- Risk score of 18/100
- OWASP Top 10 mapping
- RAG-powered chat responses

## Screens

| Route | Screen |
|-------|--------|
| `/` | Scan input (home) |
| `/scan/:id/live` | Real-time scan feed |
| `/scan/:id/dashboard` | Full dashboard |
| `/scan/:id/chain` | Attack chain graph |
| `/scan/:id/chat` | AI chat about findings |

## Demo Rehearsal Checklist

1. Start the backend: `uvicorn app.main:app --reload`
2. Start the frontend: `cd frontend && npm run dev`
3. Open `http://localhost:5173/`
4. Click "github.com/OWASP/PyGoat" quick chip or type `https://github.com/OWASP/PyGoat`
5. Click **Scan**
6. Watch the live terminal log fill with findings (~42s)
7. Click **View Dashboard** when complete
8. Browse the severity breakdown, findings table, and OWASP mapping
9. Navigate to **Attack Paths** and click nodes to inspect the chain
10. Navigate to **Chat** and try "What is the most dangerous issue?"
11. Click **Download PDF** in the top bar
