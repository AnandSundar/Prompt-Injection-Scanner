# Prompt Injection Scanner (PISC) - Web Frontend

A modern, responsive web application for scanning prompts for potential prompt injection attacks.

## Features

- **Instant Pattern Scanning** - Detects 30+ known attack patterns
- **AI-Powered Analysis** - Optional OpenAI-powered deep scanning
- **Real-time Progress** - WebSocket-based streaming results
- **Scan History** - Local history with search and filtering
- **Educational Content** - Learn about prompt injection attacks

## Prerequisites

- Node.js 18+
- npm or yarn
- Running backend API (see `/api`)

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create a `.env` file (optional):
   ```bash
   VITE_API_URL=http://localhost:8000
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```

4. Open http://localhost:5173 in your browser

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_API_URL` | Backend API URL | `http://localhost:8000` |

## Building for Production

```bash
npm run build
```

The built files will be in the `dist` folder.

## Tech Stack

- **React 18** with TypeScript
- **Vite** for fast builds
- **Tailwind CSS v4** for styling
- **Framer Motion** for animations
- **Radix UI** for accessible components
- **Zustand** for state management

## Project Structure

```
web/
├── src/
│   ├── components/      # Reusable UI components
│   │   ├── layout/      # Navbar, PageWrapper, etc.
│   │   ├── scanner/     # Scanner-related components
│   │   ├── history/     # History components
│   │   └── ui/         # Base UI components
│   ├── pages/           # Route pages
│   ├── hooks/          # Custom React hooks
│   ├── lib/            # Utilities
│   ├── store/          # Zustand stores
│   └── types/          # TypeScript types
├── public/             # Static assets
└── index.html          # Entry HTML
```

## API Integration

The frontend communicates with the backend API at `/api`:

- `POST /scan` - Submit a prompt for scanning
- `GET /patterns` - Get all detection patterns
- `GET /health` - Health check

For WebSocket streaming, connect to `/ws/scan`.

## License

MIT
