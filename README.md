# PISC - Prompt Injection Scanner

<img width="1024" height="1536" alt="image" src="https://github.com/user-attachments/assets/f69eac05-5f83-4328-b97c-541c954b2f74" />


A comprehensive security tool for detecting and classifying prompt injection vulnerabilities in LLM applications. PISC combines regex pattern matching with AI-powered classification to identify malicious prompts before they reach your language models.

![Version](https://img.shields.io/badge/version-0.1.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [CLI](#cli)
  - [API Server](#api-server)
  - [Web Interface](#web-interface)
- [Scanning Pipeline](#scanning-pipeline)
- [Detection Patterns](#detection-patterns)
- [Environment Variables](#environment-variables)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

PISC (Prompt Injection Scanner) is a turnkey security solution that helps you protect your LLM-powered applications from prompt injection attacks. It uses a multi-stage detection pipeline:

1. **Regex Pattern Detection** - Matches against 30+ known attack patterns
2. **Risk Scoring** - Calculates a weighted risk score based on pattern severity
3. **LLM Classification** - Uses OpenAI for deep semantic analysis (when needed)
4. **Final Verdict** - Combines results for a definitive security decision

---

## Architecture

### System Architecture Flowchart

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PISC Architecture                                  │
└─────────────────────────────────────────────────────────────────────────────┘

                                    ┌──────────────┐
                                    │    User      │
                                    └──────┬───────┘
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    │                      │                      │
                    ▼                      ▼                      ▼
           ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
           │     CLI      │       │  REST API    │       │  Web UI      │
           │  (Python)    │       │  (FastAPI)   │       │  (React)     │
           └──────┬───────┘       └──────┬───────┘       └──────┬───────┘
                  │                      │                      │
                  └──────────────────────┼──────────────────────┘
                                           │
                                           ▼
                                 ┌─────────────────┐
                                 │   Core Engine   │
                                 └────────┬────────┘
                                          │
         ┌────────────────────────────────┼────────────────────────────────┐
         │                                │                                │
         ▼                                ▼                                ▼
┌─────────────────┐            ┌─────────────────┐            ┌─────────────────┐
│   Patterns      │            │     Scorer      │            │    LLM          │
│   Detector      │            │   (Risk Calc)   │            │  Classifier     │
│                 │            │                 │            │  (OpenAI)       │
│ - 30+ patterns │            │ - Weighted      │            │                 │
│ - Categories:  │            │   scoring       │            │ - Semantic      │
│   - Jailbreak  │            │ - Risk levels   │            │   analysis      │
│   - Injection  │            │ - Threshold     │            │ - Confidence    │
│   - Context    │            │   detection     │            │ - Payload type  │
│   - Roleplay   │            │                 │            │                 │
└────────┬────────┘            └────────┬────────┘            └────────┬────────┘
         │                               │                               │
         └───────────────────────────────┼───────────────────────────────┘
                                         │
                                         ▼
                                 ┌─────────────────┐
                                 │    Verdict      │
                                 │   Generator     │
                                 └────────┬────────┘
                                          │
                                          ▼
                                 ┌─────────────────┐
                                 │  BENIGN         │
                                 │  SUSPICIOUS     │
                                 │  INJECTION      │
                                 └─────────────────┘
```

### Scanning Pipeline Flowchart

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Scanning Pipeline Detail                             │
└─────────────────────────────────────────────────────────────────────────────┘

    ┌──────────┐
    │  Input   │
    │  Prompt  │
    └────┬─────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Stage 1: Regex Pattern Detection                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  • Run 30+ regex patterns against input                              │   │
│  │  • Match patterns: Jailbreak, Injection, Context, Roleplay        │   │
│  │  • Return: List[PatternMatch]                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Stage 2: Risk Scoring                                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  • Calculate weighted score from matches                            │   │
│  │  • Weights: low=0.1, medium=0.25, high=0.5, critical=0.75          │   │
│  │  • Determine risk level: SAFE (<0.3), SUSPICIOUS (<0.6), MALICIOUS │   │
│  │  • Check escalation threshold (0.3)                                 │   │
│  │  • Return: ScanScore                                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
         │
         ▼
    ┌─────────────┐
    │ Escalate    │──────── No ────────┐
    │ to LLM?     │                     │
    └──────┬──────┘                     │
         Yes│                           │
           │                             │
           ▼                             ▼
┌─────────────────────────────────┐  ┌─────────────────────────────────────────┐
│  Stage 3: LLM Classification    │  │  Stage 4: Derive Final Verdict         │
│  ┌───────────────────────────┐  │  │  ┌───────────────────────────────────┐  │
│  │  • Send to OpenAI API     │  │  │  │  • Use regex risk_level mapping   │  │
│  │  • Provide context from  │  │  │  │    - SAFE → BENIGN                 │  │
│  │    regex matches         │  │  │  │    - SUSPICIOUS → SUSPICIOUS       │  │
│  │  • Get semantic analysis │  │  │  │    - MALICIOUS → INJECTION        │  │
│  │  • Return: verdict,       │  │  │  └───────────────────────────────────┘  │
│  │    confidence, payload   │  │  │                                         │
│  │    type, reasoning       │  │  │                                         │
│  └───────────────────────────┘  │  │                                         │
└─────────────────────────────────┘  │                                         │
                                     │                                         │
                                     └─────────────────┬───────────────────────┘
                                                       │
                                                       ▼
                                          ┌─────────────────────┐
                                          │    Final Result     │
                                          │  ┌───────────────┐  │
                                          │  │ ScanResult    │  │
                                          │  │ - verdict     │  │
                                          │  │ - confidence  │  │
                                          │  │ - matches     │  │
                                          │  │ - duration    │  │
                                          │  └───────────────┘  │
                                          └─────────────────────┘
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Regex Pattern Detection** | 30+ built-in patterns for detecting common injection techniques |
| **Multi-Category Analysis** | Categories: Jailbreak, Direct Injection, Context Manipulation, Roleplay |
| **Risk Scoring** | Weighted scoring with severity levels (low, medium, high, critical) |
| **AI-Powered Classification** | OpenAI-powered semantic analysis for complex cases |
| **Real-time Streaming** | WebSocket support for live progress updates |
| **Multiple Interfaces** | CLI, REST API, and Web UI included |
| **Scan History** | Persistent local history with search and filtering (Web UI) |
| **Pattern Management** | List and inspect all detection patterns |
| **Security Hardening** | OWASP Top 10 security controls implementation |
| **Input Validation** | Comprehensive input validation and sanitization (A03: Injection Prevention) |
| **SSRF Prevention** | Server-side request forgery protection (A10: SSRF Prevention) |
| **Secure Logging** | Tamper-evident security logging (A08: Data Integrity) |
| **Security Auditing** | Comprehensive security audit system (A09: Logging & Monitoring) |
| **Verification Script** | Automated security controls verification tool |

---

## Quick Start

### Running Both Frontend and Backend

This project has two main components:
- **Backend**: Python FastAPI server (port 8000)
- **Frontend**: React web application (port 5173)

You need to run both to use the full web interface.

#### Step 1: Set Up Environment

```bash
# Navigate to project directory
cd pisc

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -e .
```

#### Step 2: Configure API Key

Create a `.env` file in the project root:

```bash
# .env file
OPENAI_API_KEY=sk-your-openai-api-key
```

Get your API key from [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys)

#### Step 3: Start Backend (API Server)

**Terminal 1:**

```bash
# Run the API server
python -m api.main
```

The API will start at `http://localhost:8000`

#### Step 4: Start Frontend (Web UI)

**Terminal 2:**

```bash
# Navigate to web directory
cd web

# Install dependencies (first time only)
npm install

# Start development server
npm run dev
```

The web app will start at `http://localhost:5173`

#### Step 5: Open in Browser

Navigate to `http://localhost:5173` - you can now:
- Scan prompts using the web interface
- View scan history
- Browse detection patterns
- Learn about prompt injection attacks

---

### Alternative: CLI Only (No Web UI)

If you only need the CLI, you can run scans without starting the web interface:

```bash
# Activate virtual environment
source venv/bin/activate

# Set API key
export OPENAI_API_KEY="sk-your-key"

# Run a scan
pisc scan "Ignore all previous instructions"
```

---

## Installation

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | Required for core scanner |
| Node.js | 18+ | Required for web interface |
| OpenAI API Key | - | Required for LLM classification |

### Python Package Installation

```bash
# Install in development mode
pip install -e .

# Or install production dependencies
pip install -r requirements.txt
```

### Web Interface Installation

```bash
cd web
npm install
```

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Required for LLM classification
OPENAI_API_KEY=sk-your-openai-api-key

# Optional: Override default model
PISC_MODEL=gpt-4o-mini

# Optional: API configuration
PISC_API_HOST=0.0.0.0
PISC_API_PORT=8000
```

### Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | Yes | - | OpenAI API key from [platform.openai.com](https://platform.openai.com/api-keys) |
| `PISC_MODEL` | No | `gpt-4o-mini` | OpenAI model to use for classification |
| `PISC_API_HOST` | No | `0.0.0.0` | API server host |
| `PISC_API_PORT` | No | `8000` | API server port |
| `PISC_API_URL` | No | `http://localhost:8000` | Web UI backend URL |

---

## Usage

### CLI

The PISC CLI provides commands for scanning prompts, listing patterns, and more.

#### Scan a Single Prompt

```bash
pisc scan "Your prompt here"
```

**Example Output:**
```
╭───────────────────────────────────────╮
│  INJECTION                           │
╰───────────────────────────────────────╯

Regex Matches
═══════════════════════════════════════════════════════════
 Category          Severity    Match
═══════════════════════════════════════════════════════════
 Context           high        "Ignore all previous"
   Manipulation

LLM Classification
═══════════════════════════════════════════════════════════
 Verdict          INJECTION
 Confidence       ████████░░ 80%
 Payload Type     Context Override
 Reasoning        The prompt attempts to override system...
═══════════════════════════════════════════════════════════

Scan completed in 1,234.56ms
```

#### Force LLM Classification

```bash
pisc scan "Your prompt here" --force-llm
```

#### Scan a File of Prompts

```bash
pisc scan-file prompts.txt
```

#### List All Detection Patterns

```bash
pisc patterns
```

#### Security Verification

Run the automated security controls verification:

```bash
python security_verification.py
```

This will test all OWASP Top 10 security controls and provide a comprehensive security report.

#### JSON Output

```bash
pisc scan "Your prompt" --output json
```

#### CLI Options

| Option | Short | Description |
|--------|-------|--------------|
| `--force-llm` | `-f` | Force LLM classification regardless of risk score |
| `--output` | `-o` | Output format: `text` or `json` |
| `--model` | `-m` | Override the model to use |
| `--concurrency` | `-c` | Number of concurrent scans (for file scanning) |

---

### API Server

Start the FastAPI server:

```bash
# Using Python directly
python -m api.main

# Or with uvicorn
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

#### API Endpoints Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan` | Scan a single prompt |
| `GET` | `/patterns` | Get all detection patterns |
| `GET` | `/health` | Health check |
| `WS` | `/ws/scan` | WebSocket for streaming scans |

#### Example: Using the API

```bash
# Scan via REST API
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Ignore all previous instructions", "force_llm": false}'

# Get patterns
curl http://localhost:8000/patterns

# Health check
curl http://localhost:8000/health
```

#### Example: WebSocket Streaming

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/scan');

ws.onopen = () => {
  ws.send(JSON.stringify({
    prompt: 'Ignore all previous instructions',
    force_llm: false
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data);
  // { stage: 'regex', status: 'running' }
  // { stage: 'regex', status: 'done', data: {...} }
  // { stage: 'llm', status: 'running' }
  // { stage: 'llm', status: 'done', data: {...} }
  // { stage: 'complete', status: 'done', data: {...} }
};
```

---

### Web Interface

Start the development server:

```bash
cd web
npm run dev
```

Open http://localhost:5173 in your browser.

#### Web Features

- **Scanner Page** - Submit prompts and view results
- **History Page** - View past scans with filtering
- **Patterns Page** - Browse all detection patterns
- **How It Works** - Educational content about prompt injection

---

## Scanning Pipeline

### Stage 1: Regex Pattern Detection

PISC scans the input against 30+ regex patterns organized into categories:

| Category | Description | Example Patterns |
|----------|-------------|------------------|
| **Jailbreak** | Attempts to bypass AI safety measures | "DAN mode", "Developer mode" |
| **Direct Injection** | Direct commands to override behavior | "Ignore previous instructions" |
| **Context Manipulation** | Attempts to modify system context | "You are now [different persona]" |
| **Roleplay** | Unauthorized role assignment | "Pretend you are a human" |

### Stage 2: Risk Scoring

The risk scorer calculates a weighted score:

```
Risk Score = Σ(severity_weight for each matched category)
```

**Severity Weights:**
- Low: 0.1
- Medium: 0.25
- High: 0.5
- Critical: 0.75

**Risk Levels:**
- SAFE: score ≤ 0.29
- SUSPICIOUS: score ≤ 0.59
- MALICIOUS: score > 0.59

### Stage 3: LLM Classification

If the risk score exceeds 0.3 (or `--force-llm` is used), the prompt is sent to OpenAI for semantic analysis.

**LLM Result includes:**
- `verdict`: BENIGN, SUSPICIOUS, INJECTION, MALICIOUS
- `confidence`: 0.0-1.0
- `payload_type`: Type of injection attempt
- `reasoning`: Explanation of the classification

### Stage 4: Final Verdict

| Source | Risk Level | Verdict |
|--------|------------|---------|
| Regex only | SAFE | BENIGN |
| Regex only | SUSPICIOUS | SUSPICIOUS |
| Regex only | MALICIOUS | INJECTION |
| LLM available | Any | LLM verdict |

---

## Detection Patterns

PISC includes 30+ detection patterns. View them all:

```bash
pisc patterns
```

Or via API:

```bash
curl http://localhost:8000/patterns
```

### Pattern Categories

1. **Jailbreak Attempts** - Bypass AI safety measures
2. **Direct Instruction Override** - Ignore system prompts
3. **Context Manipulation** - Modify conversation context
4. **Roleplay Exploitation** - Unauthorized persona adoption
5. **Token Manipulation** - Encoding/fragmentation attempts
6. **Multi-turn Planning** - Multi-stage attack sequences

---
Homepage
<img width="1547" height="902" alt="image" src="https://github.com/user-attachments/assets/c37f9046-2665-464c-a536-e8bfb007ab47" />

Prompt scanner flagging the suspicious HIGH RISK prompt

<img width="1553" height="902" alt="image" src="https://github.com/user-attachments/assets/a9f89a4b-7a41-42fd-8a3d-73e3d1cabc3b" />

Example of LOW RISK prompt

<img width="1575" height="907" alt="image" src="https://github.com/user-attachments/assets/f83832db-3faa-4887-bdb6-06c170eb83bc" />

How It Works page to learn how the scanner works

<img width="1592" height="908" alt="image" src="https://github.com/user-attachments/assets/62b68435-bb7d-420e-a88b-86e2cbc79b5d" />

Patterns page show the 40+ common hacker patterns and when AI review is used

<img width="1587" height="911" alt="image" src="https://github.com/user-attachments/assets/d127d63b-6865-4828-8c13-4995a7a1450c" />

Add your openAI key here for AI based review

<img width="1392" height="851" alt="image" src="https://github.com/user-attachments/assets/1e0f2777-1386-4175-b3a2-6557c85c1ba6" />


---

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

```bash
# Run tests
pytest

# Lint
ruff check .
```

---

## License

MIT License - see LICENSE file for details.

---

## Project Structure

```
pisc/
├── __init__.py                # Package init
├── cli.py                     # CLI entry point
├── scanner.py                 # Core scanner orchestration
├── scorer.py                  # Risk scoring logic
├── patterns.py                # Regex pattern definitions
├── llm_classifier.py          # OpenAI classification
├── security_verification.py   # Security controls verification
├── test_security_modules.py   # Tests for security modules
├── test_validation.py         # Tests for input validation
├── SECURITY.md                # Security documentation
├── requirements.txt           # Python dependencies
├── api/
│   ├── main.py                # FastAPI server
│   ├── run.py                 # API runner
│   ├── security_audit.py      # Security audit logging
│   ├── security_logging.py    # Secure logging module
│   ├── security_ssrf.py       # SSRF prevention
│   └── security_validation.py # Input validation
├── plans/
│   └── OWASP_SECURITY_HARDENING_PLAN.md # Security plan
├── web/                       # React web interface
│   ├── src/
│   │   ├── components/   # UI components
│   │   ├── pages/        # Route pages
│   │   ├── hooks/        # React hooks
│   │   └── store/        # State management
│   └── package.json
└── .env                  # Environment configuration
```

---

**⚠️ Disclaimer**: This tool is for defensive security purposes only. Always follow responsible disclosure practices and obtain proper authorization before scanning any system.
