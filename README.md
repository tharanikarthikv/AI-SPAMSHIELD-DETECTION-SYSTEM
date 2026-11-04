# 🛡️ AI-SPAMSHIELD

> Multi-Channel Cybersecurity Detection Suite, Phishing Forensic Scanner & Autonomous Threat Agent.

Built with **React 19**, **Vite 8**, **Tailwind CSS v4**, **TypeScript**, **Express**, and **Google Gemini GenAI SDK (`@google/genai`)**.

---

## 🚀 Running in Cursor IDE

This repository is fully configured for **[Cursor IDE](https://cursor.com)** with pre-installed `.cursorrules`, modular `.cursor/rules/*.mdc`, and `.vscode/launch.json`.

### 1. Open the Project in Cursor
```bash
# If cloned or unzipped:
cursor .
```
*(Or open Cursor, click **File -> Open Folder**, and select this directory).*

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Add your Google Gemini API key inside `.env`:
```env
GEMINI_API_KEY="your-gemini-api-key-here"
PORT=3000
```
*(Note: The app also operates with robust offline heuristic engines if no API key is provided!)*

### 3. Install Dependencies & Launch
```bash
npm install
npm run dev
```

The app will start at:
👉 **`http://localhost:3000`**

### 4. Gmail OAuth setup (local Windows + deployed website)
The Gmail connection uses Firebase Authentication with Google sign-in and the read-only `gmail.readonly` scope. Complete these one-time settings in the cloud consoles:

1. In **Firebase Console → Authentication → Sign-in method**, enable **Google** and choose a support email.
2. In **Firebase Console → Authentication → Settings → Authorized domains**, add `localhost` for local testing and the exact hostname of each deployed website (including staging, if used).
3. In **Google Cloud Console**, select the same project as Firebase and enable the **Gmail API**. Check the OAuth consent screen audience/status; if it is in Testing, add the Google accounts that will test it. Public production use of Gmail scopes may require Google's verification.
4. Keep `authDomain` set to the Firebase project's auth domain. Firebase manages its OAuth handler at `https://<authDomain>/__/auth/handler`; don't substitute the website URL. Use HTTPS for the deployed site.
5. Retry sign-in in a normal browser tab. OAuth errors now include a targeted explanation and the Firebase error code where available.

**Windows:** run commands in PowerShell from the project folder. `npm run dev` defaults to port 3000; to use another port, run `$env:PORT=8080` before launching.

**Deployment:** use a Node host that runs the Express server, set `NODE_ENV=production`, `PORT` (usually injected by the host), and `GEMINI_API_KEY` in its environment settings, and deploy the built `dist` folder with the server. The frontend and `/api/*` endpoints are designed to share one origin; static-only hosting requires a separately deployed/proxied API.

### 5. 1-Click Debugging in Cursor
Press `F5` or navigate to **Run and Debug** (`Ctrl+Shift+D` / `Cmd+Shift+D`) and select **"Run AI-SPAMSHIELD (Cursor / Node)"**.

---

## 🤖 Running with Google Antigravity Agent

AI-SPAMSHIELD is pre-configured for the **Google Antigravity Agent** (`antigravity-preview-09-2026`) and autonomous code sandboxes.

### Included Agent Configurations:
- `antigravity.config.json`: Project manifest, entry point (`tsx server.ts`), ports, and permissions.
- `.agent/config.json`: Agent sandbox execution lifecycle rules and safety constraints.
- `.cursor/rules/antigravity.mdc`: Coding and execution instructions for the agent.

### Starting in an Antigravity Sandbox:
```bash
npm install
npm run dev
```
Healthcheck endpoint:
```bash
curl http://localhost:3000/api/health
```

---

## 📦 Project Architecture

```
ai-spamshield/
├── .cursorrules               # Cursor IDE AI prompt instructions & tech stack specs
├── .cursor/rules/             # MDC rules (antigravity, fullstack, security)
├── .vscode/                   # Cursor / VS Code launch and task configs
├── antigravity.config.json    # Google Antigravity Agent configuration
├── .agent/config.json         # Autonomous agent execution spec
├── server.ts                  # Express backend & Vite middleware integration
├── src/
│   ├── App.tsx                # Main application UI container
│   ├── components/            # Views: SMS, Email, URL, Ad, AutoScanner, AI Mode
│   ├── services/
│   │   ├── agentService.ts    # Autonomous Cybersecurity Agent
│   │   ├── guardianService.ts # Guardian Risk & Action Interceptor
│   │   └── permissionService.ts# OS & App Permission Matrix
│   ├── threatIntelligence.ts  # Shannon Entropy & Forensic Analysis
│   ├── autoScanner.ts         # Automated background simulated traffic scanner
│   └── documentScanner.ts     # Document and payload inspector
└── package.json
```

## 🛠️ Available Scripts
- `npm run dev`: Starts the unified Express API + Vite dev server on port 3000.
- `npm run build`: Bundles the React application for production.
- `npm run lint`: Runs TypeScript compiler check (`tsc --noEmit`).
- `npm start`: Runs the production server (`node server.ts`).
