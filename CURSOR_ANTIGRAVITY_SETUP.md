# Cursor & Antigravity Setup Guide

This document explains everything you need to run, develop, and test **AI-SPAMSHIELD** inside **Cursor IDE** and with **Google Antigravity Agent**.

---

## ⚡ Cursor IDE Quick Reference

### Features Configured Out of the Box:
1. **`.cursorrules`**: Automatically informs Cursor's agent about the fullstack architecture (Vite, React 19, Express, Tailwind v4, `@google/genai`).
2. **`.cursor/rules/*.mdc`**:
   - `fullstack.mdc`: Guides file placement, API routing, and state handling.
   - `antigravity.mdc`: Antigravity Agent execution protocols.
   - `security.mdc`: Cybersecurity scoring, false-positive mitigation, and heuristics.
3. **`.vscode/launch.json`**:
   - Ready-to-use launch target: `Run AI-SPAMSHIELD (Cursor / Node)`
   - Attach debugger with breakpoints in `server.ts` or `src/threatIntelligence.ts`.

### Starting in Cursor:
```bash
# 1. Open Cursor terminal
Ctrl + ` (or Cmd + ` on Mac)

# 2. Install packages
npm install

# 3. Launch
npm run dev
```

---

## 🪐 Google Antigravity Agent Reference

### Agent Identification:
- **Agent Name**: `antigravity-preview-09-2026`
- **Interactions API**: `@google/genai` v2.4+
- **Environment**: Linux container, Node 22 runtime, Port 3000

### Files Recognized by Antigravity:
- `antigravity.config.json`
- `.agent/config.json`

### Key Endpoints for Agent Health & Testing:
- `GET /api/health` -> Server uptime, Gemini status, and channel readiness.
- `GET /api/stats` -> Detection statistics and threats blocked.
- `POST /api/analyze/sms` -> Automated SMS threat classification.
- `POST /api/analyze/email` -> Automated Email phishing classification.
- `POST /api/analyze/url` -> Automated URL threat inspection.
- `POST /api/agent/chat` -> Autonomous cybersecurity dialogue.
- `GET /api/export/zip` -> 1-click project code archive download.
