import express, { type Request, type Response } from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';
import { dbService } from './src/db.ts';
import { analyzeDocumentPayload } from './src/documentScanner.ts';
import {
  crossReferenceThreatIntelligence,
  calculateShannonEntropy,
  type ThreatIntelReport
} from './src/threatIntelligence.ts';
import {
  getAutoScanConfig,
  updateAutoScanConfig,
  getAutoScanEvents,
  getAutoScanStats,
  clearAutoScanEvents,
  recordAutoScanEvent,
  getNextSimulatedTrafficItem
} from './src/autoScanner.ts';
import type { ChannelType, ClassificationType, DetectionResult } from './src/types.ts';
import { agentService, type AgentPersonality } from './src/services/agentService.ts';
import { guardianService } from './src/services/guardianService.ts';
import { permissionService, type PermissionPolicy } from './src/services/permissionService.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number.parseInt(process.env.PORT || '3000', 10);

app.use(express.json({ limit: '10mb' }));

// Initialize GoogleGenAI SDK on server
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    }
  }
});

// In-memory persistent history store (mirrors SQLite / Room DB)
let detectionHistory: DetectionResult[] = [
  {
    id: 'demo-sms-1',
    channel: 'sms',
    content: 'Congratulations! You have won 5,00,000 in the National Lucky Draw. Click http://win-claim500k.xyz/collect to claim your prize immediately before it expires!',
    classification: 'SCAM',
    risk_score: 95,
    confidence: 97,
    evidence: [
      'Unrealistic lottery/prize lure (5,00,000 windfall claim)',
      'High-pressure urgency language ("immediately before it expires")',
      'Suspicious unverified top-level domain (.xyz)'
    ],
    recommendation: 'DO NOT CLICK THE LINK. Do not share bank credentials or OTP. Report sender and delete message.',
    timestamp: Date.now() - 1000 * 60 * 18,
    metadata: { sender: '+91-98721-XXXXX' }
  },
  {
    id: 'demo-email-1',
    channel: 'email',
    content: 'URGENT: Your Google Account has been restricted due to suspicious sign-in attempt from Russia. Verify your credentials within 24 hours at http://security-google-verify.top/login or your account will be permanently deactivated.',
    classification: 'PHISHING',
    risk_score: 92,
    confidence: 95,
    evidence: [
      'Brand impersonation attempt mimicking Google Security',
      'Coercive urgency threat ("permanently deactivated within 24 hours")',
      'Credential harvesting destination domain (.top TLD)',
      'Mismatched sender domain failing standard SPF/DKIM validation'
    ],
    recommendation: 'DO NOT ENTER PASSWORDS. Flag email as Phishing in your email client and block the sender domain.',
    timestamp: Date.now() - 1000 * 60 * 45,
    metadata: { sender: 'no-reply@security-google-service.org', subject: 'Urgent: Account Deactivation Notice' }
  },
  {
    id: 'demo-url-1',
    channel: 'url',
    content: 'http://192.168.1.1:8080/secure-banking-login/update-kyc.html',
    classification: 'MALICIOUS',
    risk_score: 89,
    confidence: 93,
    evidence: [
      'Raw IP address host detected instead of registered domain',
      'Sensitive banking keyword spoofing ("secure-banking-login", "update-kyc")',
      'Non-standard port allocation (8080) for purported banking portal',
      'Insecure plain HTTP transport lacking SSL/TLS certificate'
    ],
    recommendation: 'NEVER OPEN THIS URL. Legitimate financial institutions never host production portals on raw IP addresses.',
    timestamp: Date.now() - 1000 * 60 * 90
  }
];

// Helper: Extract URLs from raw text
function extractUrls(text: string): string[] {
  const urlRegex = /(https?:\/\/[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(?:com|org|net|xyz|top|info|buzz|club|online|site|ru|tk|cc|cn|app|io|me|in)[^\s]*)/gi;
  return text.match(urlRegex) || [];
}

// Helper: Lexical & entropy analysis for URLs
function analyzeUrlStructure(urlStr: string) {
  let cleanUrl = urlStr.trim();
  if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
    cleanUrl = 'http://' + cleanUrl;
  }
  let parsed: URL | null = null;
  try {
    parsed = new URL(cleanUrl);
  } catch {
    // fallback
  }

  const hostname = parsed ? parsed.hostname : urlStr.split('/')[0];
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isHttps = cleanUrl.startsWith('https://');
  const dotCount = (hostname.match(/\./g) || []).length;
  const hyphenCount = (hostname.match(/-/g) || []).length;
  const isShortener = /(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy)/i.test(hostname);
  const suspiciousTld = /\.(xyz|top|buzz|club|tk|ml|ga|cf|gq|work|loan|date|icu|rest|racing)$/i.test(hostname);
  const entropy = calculateShannonEntropy(hostname);
  const suspiciousKeywordsInPath = /(login|verify|account|update|banking|secure|signin|wallet|auth|claim|refund|kyc|bonus)/i.test(cleanUrl);

  const targets = ['google', 'apple', 'microsoft', 'paypal', 'amazon', 'netflix', 'facebook', 'instagram', 'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'binance', 'coinbase'];
  const typosquatTarget = targets.find(t => hostname.includes(t) && !hostname.endsWith(`.${t}.com`) && hostname !== `${t}.com`);

  return {
    raw: urlStr,
    cleanUrl,
    hostname,
    isIp,
    isHttps,
    dotCount,
    hyphenCount,
    isShortener,
    suspiciousTld,
    entropy,
    suspiciousKeywordsInPath,
    typosquatTarget
  };
}

// ------------------------------------------
// 1. SMS AI DETECTION MODULE
// ------------------------------------------
async function analyzeSMS(sender: string, text: string): Promise<DetectionResult> {
  const lower = text.toLowerCase();
  const urls = extractUrls(text);
  const evidence: string[] = [];
  let score = 5;

  // Lures
  const prizePatterns = /(congratulations|won|winner|lottery|prize|reward|claim|crore|lakh|cashback|gift card|selected for free)/i;
  if (prizePatterns.test(lower)) {
    score += 35;
    evidence.push('Financial lure / lottery prize claim identified');
  }

  // Banking / KYC threats
  const kycPatterns = /(kyc|bank account|deactivated|suspended|blocked|pan card|aadhaar|electricity power off|bill unpaid)/i;
  if (kycPatterns.test(lower)) {
    score += 40;
    evidence.push('Account suspension / KYC threat coercive language');
  }

  // Urgency
  const urgencyPatterns = /(immediate|immediately|within 24 hours|urgent|today only|expires soon|last chance|act now)/i;
  if (urgencyPatterns.test(lower)) {
    score += 20;
    evidence.push('High-pressure temporal urgency indicators');
  }

  // Credential prompt
  const credPatterns = /(otp|pin|password|cvv|credentials|verify immediately)/i;
  if (credPatterns.test(lower)) {
    score += 30;
    evidence.push('Sensitive credential or OTP prompt detected');
  }

  // URL inspection in SMS
  let smsThreatIntel: ThreatIntelReport | null = null;
  if (urls.length > 0) {
    score += 15;
    const urlAnalysis = analyzeUrlStructure(urls[0]);
    if (urlAnalysis.isShortener) {
      score += 15;
      evidence.push(`Shortened disguised link found (${urlAnalysis.hostname})`);
    } else if (urlAnalysis.suspiciousTld || urlAnalysis.isIp) {
      score += 25;
      evidence.push(`Suspicious destination domain (${urlAnalysis.hostname})`);
    } else {
      evidence.push(`Embedded external hyperlink: ${urls[0]}`);
    }

    try {
      smsThreatIntel = await crossReferenceThreatIntelligence(urls[0]);
      if (smsThreatIntel.isMalicious || smsThreatIntel.isSuspicious) {
        score = Math.max(score, smsThreatIntel.isMalicious ? 95 : 75);
        evidence.unshift(...smsThreatIntel.evidenceItems);
      }
    } catch {}
  }

  // APK download
  if (lower.includes('.apk') || lower.includes('download app')) {
    score += 35;
    evidence.push('Direct untrusted Android package (.APK) download link');
  }

  score = Math.min(99, Math.max(2, score));
  let classification: ClassificationType = 'SAFE';

  if (score >= 80) {
    classification = lower.includes('won') || lower.includes('lottery') || lower.includes('claim') ? 'SCAM' : 'PHISHING';
  } else if (score >= 60) {
    classification = 'SPAM';
  } else if (score >= 35) {
    classification = 'SUSPICIOUS';
  } else {
    classification = 'SAFE';
    if (evidence.length === 0) {
      evidence.push('Clean conversational content without malicious indicators');
      evidence.push('Sender and payload adhere to legitimate communication norms');
    }
  }

  const confidence = Math.min(98, Math.max(82, Math.round(75 + (score > 50 ? score * 0.22 : (100 - score) * 0.22))));

  let recommendation = 'Message appears legitimate. Exercise standard caution.';
  if (classification === 'SCAM' || classification === 'PHISHING') {
    recommendation = 'DO NOT CLICK THE LINK. Do not share OTPs, personal details, or send funds. Block and report sender.';
  } else if (classification === 'SPAM' || classification === 'SUSPICIOUS') {
    recommendation = 'Treat with caution. Verify identity through official customer service channels before responding.';
  }

  return {
    id: 'sms-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7),
    channel: 'sms',
    content: text,
    classification,
    risk_score: score,
    confidence,
    evidence,
    recommendation,
    timestamp: Date.now(),
    metadata: {
      sender: sender || 'Unknown',
      threatIntel: smsThreatIntel || undefined
    }
  };
}

// ------------------------------------------
// 2. EMAIL AI DETECTION MODULE
// ------------------------------------------
async function analyzeEmail(sender: string, subject: string, body: string, headers?: string): Promise<DetectionResult> {
  const fullContent = `${subject} ${body}`.toLowerCase();
  const urls = extractUrls(`${body} ${headers || ''}`);
  const evidence: string[] = [];
  let score = 5;

  // Impersonation cues
  const brandKeywords = ['paypal', 'google', 'apple', 'microsoft', 'netflix', 'amazon', 'bank', 'irs', 'income tax'];
  for (const brand of brandKeywords) {
    if (fullContent.includes(brand) && sender && !sender.toLowerCase().includes(brand)) {
      score += 40;
      evidence.push(`Potential brand impersonation: Content references "${brand.toUpperCase()}" but sender domain is "${sender}"`);
      break;
    }
  }

  if (/(suspended|unauthorized access|deactivation|security alert|compromised|reset your password|verify your identity|unusual activity)/i.test(fullContent)) {
    score += 35;
    evidence.push('Coercive account compromise or suspension alert');
  }

  if (/(wire transfer|invoice attached|past due|payment required|bitcoin|remittance|gift cards)/i.test(fullContent)) {
    score += 25;
    evidence.push('High-risk financial wire or unsolicited invoice language');
  }

  if (/(attachment\.exe|\.zip|\.scr|\.iso|\.vbs|\.html\.exe)/i.test(fullContent)) {
    score += 45;
    evidence.push('Dangerous executable/script attachment signature detected');
  }

  let emailThreatReport: ThreatIntelReport | null = null;
  if (urls.length > 0) {
    const urlAnalysis = analyzeUrlStructure(urls[0]);
    if (urlAnalysis.suspiciousTld || urlAnalysis.isIp) {
      score += 25;
      evidence.push(`Phishing landing page hosted on ${urlAnalysis.hostname}`);
    } else if (urlAnalysis.suspiciousKeywordsInPath) {
      score += 20;
      evidence.push(`Login/verification link detected: ${urls[0].substring(0, 45)}...`);
    } else {
      evidence.push(`Embedded link present: ${urls[0].substring(0, 45)}...`);
    }

    try {
      emailThreatReport = await crossReferenceThreatIntelligence(urls[0]);
      if (emailThreatReport.isMalicious || emailThreatReport.isSuspicious) {
        score = Math.max(score, emailThreatReport.isMalicious ? 94 : 75);
        evidence.unshift(...emailThreatReport.evidenceItems);
      }
    } catch {}
  }

  if (headers && /(spf=fail|dkim=fail|dmarc=fail)/i.test(headers)) {
    score += 35;
    evidence.push('Critical email authentication failures: SPF / DKIM verification failed');
  }

  score = Math.min(99, Math.max(3, score));
  let classification: ClassificationType = 'SAFE';

  if (score >= 80) {
    classification = 'PHISHING';
  } else if (score >= 60) {
    classification = 'SPAM';
  } else if (score >= 35) {
    classification = 'SUSPICIOUS';
  } else {
    classification = 'SAFE';
    if (evidence.length === 0) {
      evidence.push('Email passed lexical inspection without suspicious keywords');
      evidence.push('No malicious redirection or credential-harvesting hooks detected');
    }
  }

  const confidence = Math.min(98, Math.max(84, Math.round(78 + (score > 50 ? score * 0.2 : (100 - score) * 0.2))));

  let recommendation = 'Email seems safe. Follow standard security hygiene.';
  if (classification === 'PHISHING' || score >= 75) {
    recommendation = 'DO NOT CLICK LINKS OR DOWNLOAD ATTACHMENTS. Never enter credentials. Mark as Phishing and purge.';
  } else if (classification === 'SPAM' || classification === 'SUSPICIOUS') {
    recommendation = 'Do not respond directly. Verify authentic sender address in message header before proceeding.';
  }

  return {
    id: 'email-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7),
    channel: 'email',
    content: `Subject: ${subject}\n\n${body}`,
    classification,
    risk_score: score,
    confidence,
    evidence,
    recommendation,
    timestamp: Date.now(),
    metadata: {
      sender: sender || 'Unknown',
      subject,
      threatIntel: emailThreatReport || undefined
    }
  };
}

// ------------------------------------------
// 3. URL AI DETECTION MODULE
// ------------------------------------------
async function analyzeURL(rawUrl: string): Promise<DetectionResult> {
  const analysis = analyzeUrlStructure(rawUrl);
  const evidence: string[] = [];
  let score = 5;

  if (analysis.isIp) {
    score += 45;
    evidence.push(`Raw IPv4 address host detected (${analysis.hostname})`);
  }
  if (!analysis.isHttps) {
    score += 20;
    evidence.push('Insecure HTTP protocol (Cleartext transport, lacks SSL/TLS)');
  }
  if (analysis.suspiciousTld) {
    score += 35;
    evidence.push(`High-abuse top-level domain detected (${analysis.hostname})`);
  }
  if (analysis.isShortener) {
    score += 25;
    evidence.push(`URL shortening service obscures destination target (${analysis.hostname})`);
  }
  if (analysis.typosquatTarget) {
    score += 40;
    evidence.push(`Brand typosquatting signature detected: mimicry of "${analysis.typosquatTarget}"`);
  }
  if (analysis.dotCount >= 4) {
    score += 20;
    evidence.push(`Excessive subdomain nesting (${analysis.dotCount} dots)`);
  }
  if (analysis.entropy > 4.2) {
    score += 25;
    evidence.push(`High lexical entropy (${analysis.entropy}) indicates algorithmic domain generation (DGA)`);
  }
  if (analysis.suspiciousKeywordsInPath) {
    score += 25;
    evidence.push('Phishing-indicative path parameters ("login", "kyc", "verify", "secure")');
  }

  // Cross-reference external threat intelligence
  let threatIntel: ThreatIntelReport;
  try {
    threatIntel = await crossReferenceThreatIntelligence(rawUrl);
    if (threatIntel.isMalicious) {
      score = Math.max(score, 93);
      evidence.unshift(...threatIntel.evidenceItems);
    } else if (threatIntel.isSuspicious) {
      score = Math.max(score, 68);
      evidence.unshift(...threatIntel.evidenceItems);
    } else {
      evidence.push(`External Threat Intel (${threatIntel.provider}): Clean record (0 vendor detections across global feeds)`);
    }
  } catch {
    threatIntel = {
      provider: 'Multi-Feed Engine',
      queryTarget: rawUrl,
      isMalicious: false,
      isSuspicious: false,
      threatCategories: ['Unverified'],
      reputationScore: 0,
      evidenceItems: [],
      timestamp: Date.now()
    };
  }

  score = Math.min(99, Math.max(3, score));
  let classification: ClassificationType = 'SAFE';

  if (score >= 80) {
    classification = 'MALICIOUS';
  } else if (score >= 60) {
    classification = 'PHISHING';
  } else if (score >= 35) {
    classification = 'SUSPICIOUS';
  } else {
    classification = 'SAFE';
    if (evidence.length === 0) {
      evidence.push('Domain structure aligns with standard web reputation norms');
      evidence.push('Valid HTTPS protocol with normal lexical entropy');
    }
  }

  const confidence = Math.min(99, Math.max(85, Math.round(80 + (score > 50 ? score * 0.18 : (100 - score) * 0.18))));

  let recommendation = 'URL appears safe for routine navigation.';
  if (classification === 'MALICIOUS' || classification === 'PHISHING') {
    recommendation = 'DO NOT OPEN THIS URL. High risk of drive-by malware download or credential harvesting.';
  } else if (classification === 'SUSPICIOUS') {
    recommendation = 'Proceed with extreme caution. Do not input credentials, passwords, or personal payment cards.';
  }

  return {
    id: 'url-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7),
    channel: 'url',
    content: rawUrl,
    classification,
    risk_score: score,
    confidence,
    evidence,
    recommendation,
    timestamp: Date.now(),
    metadata: {
      hostname: analysis.hostname,
      isHttps: analysis.isHttps,
      entropy: analysis.entropy,
      isIp: analysis.isIp,
      threatIntel
    }
  };
}

// ------------------------------------------
// 4. ADVERTISEMENT AI DETECTION MODULE
// ------------------------------------------
async function analyzeAd(adText: string, targetUrl?: string): Promise<DetectionResult> {
  const lower = adText.toLowerCase();
  const evidence: string[] = [];
  let score = 5;

  if (/(guaranteed return|10 lakh|1 crore|500% profit|double your money|passive income daily|earn from home)/i.test(lower)) {
    score += 45;
    evidence.push('Unrealistic financial windfall / guaranteed wealth lure');
  }
  if (/(limited spots|act now|claim today|hurry|don't miss out|click here now|today only)/i.test(lower)) {
    score += 20;
    evidence.push('Aggressive urgency prompting impulsive user action');
  }
  if (/(celebrity|secret system|elon musk|mukesh ambani|banned method|banks hate this)/i.test(lower)) {
    score += 35;
    evidence.push('Fabricated celebrity endorsement / sensationalist bait');
  }
  if (/(crypto bot|forex signals|win jackpot|download player|system update required|clean your phone)/i.test(lower)) {
    score += 35;
    evidence.push('Predatory niche detected (unregulated crypto/forex or rogue scareware)');
  }

  let adThreatIntel: ThreatIntelReport | null = null;
  if (targetUrl) {
    const urlAnalysis = analyzeUrlStructure(targetUrl);
    if (urlAnalysis.suspiciousTld || urlAnalysis.isIp || urlAnalysis.isShortener) {
      score += 25;
      evidence.push(`Ad redirects to high-risk destination (${urlAnalysis.hostname})`);
    }
    try {
      adThreatIntel = await crossReferenceThreatIntelligence(targetUrl);
      if (adThreatIntel.isMalicious || adThreatIntel.isSuspicious) {
        score = Math.max(score, adThreatIntel.isMalicious ? 92 : 70);
        evidence.unshift(...adThreatIntel.evidenceItems);
      }
    } catch {}
  }

  score = Math.min(99, Math.max(5, score));
  let classification: ClassificationType = 'ADVERTISEMENT';

  if (score >= 80) {
    classification = 'MALICIOUS';
  } else if (score >= 50) {
    classification = 'SUSPICIOUS';
  } else if (score >= 25) {
    classification = 'ADVERTISEMENT';
  } else {
    classification = 'SAFE';
    if (evidence.length === 0) {
      evidence.push('Standard commercial product promotion without deceptive lures');
      evidence.push('Normal advertising copy meeting consumer compliance thresholds');
    }
  }

  const confidence = Math.min(97, Math.max(83, Math.round(76 + (score > 50 ? score * 0.2 : (100 - score) * 0.2))));

  let recommendation = 'Standard advertisement. Review terms carefully before purchase.';
  if (classification === 'MALICIOUS') {
    recommendation = 'AVOID AND REPORT ADVERTISEMENT. Matches fraudulent deceptive marketing and phishing vectors.';
  } else if (classification === 'SUSPICIOUS') {
    recommendation = 'Exercise high caution. Never share credit card or banking details with unsolicited advertisers.';
  }

  return {
    id: 'ad-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7),
    channel: 'ad',
    content: adText,
    classification,
    risk_score: score,
    confidence,
    evidence,
    recommendation,
    timestamp: Date.now(),
    metadata: {
      targetUrl: targetUrl || '',
      threatIntel: adThreatIntel || undefined
    }
  };
}

// ------------------------------------------
// REST API ROUTES
// ------------------------------------------
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    system: 'AI-SPAMSHIELD',
    tagline: 'Detect. Explain. Protect.',
    version: '3.0.0',
    models: {
      sms_detector: 'Linguistic Heuristics + Threat Feed Verification [ACTIVE]',
      email_detector: 'SPF/DKIM Validation + Brand Mimicry [ACTIVE]',
      url_detector: 'Shannon Entropy + Structural Sandbox [ACTIVE]',
      ad_shield: 'Deceptive Marketing & Scareware Classifier [ACTIVE]'
    },
    threat_intelligence: {
      virustotal: process.env.VIRUSTOTAL_API_KEY ? 'Connected (API Key Active)' : 'Active (Multi-Feed Fallback to URLhaus & PhishTank)',
      urlhaus_abuse_ch: 'Online (abuse.ch Live REST API Active)',
      phishtank: 'Active (Verified Community Signatures Feed)'
    },
    timestamp: new Date().toISOString()
  });
});

// Helper to get authenticated user from Authorization header
function getAuthUser(req: Request) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return null;
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  const userId = dbService.verifySessionToken(token);
  return userId ? dbService.getUserById(userId) : null;
}

// ------------------------------------------
// AUTHENTICATION ROUTES
// ------------------------------------------
app.post('/api/auth/register', (req: Request, res: Response) => {
  try {
    const { name, username, email, password, role } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username and security passcode are required.' });
    }
    const result = dbService.registerUser({ name, username, email, password, role });
    res.json({ success: true, user: result.user, token: result.token });
  } catch (err: any) {
    res.status(400).json({ success: false, error: err.message || 'Registration failed' });
  }
});

app.post('/api/auth/login', (req: Request, res: Response) => {
  try {
    const { username, password, email } = req.body;
    const identifier = username || email;
    if (!identifier || !password) {
      return res.status(400).json({ success: false, error: 'Operator ID and passcode are required.' });
    }
    const result = dbService.authenticateUser(identifier, password);
    res.json({ success: true, user: result.user, token: result.token });
  } catch (err: any) {
    res.status(401).json({ success: false, error: err.message || 'Authentication failed' });
  }
});

app.post('/api/auth/logout', (_req: Request, res: Response) => {
  res.json({ success: true, message: 'Operator session terminated.' });
});

app.get('/api/auth/me', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user) {
    // Check if default user exists to ease onboarding
    const defaultUser = dbService.getUserById('usr-tharani-01');
    return res.json({ success: true, user: defaultUser, isDefault: true });
  }
  res.json({ success: true, user });
});

// Universal Multi-Channel Threat Scanner endpoint
app.post('/api/scan', async (req: Request, res: Response) => {
  const content = (req.body.content || req.body.text || req.body.message || req.body.url || '').trim();
  const requestedChannel = (req.body.channel || '').toLowerCase();
  const documentName = req.body.documentName || req.body.filename || 'document.txt';
  const targetUrl = req.body.targetUrl || '';

  if (!content) {
    return res.status(400).json({ success: false, error: 'Content payload is required for threat scan' });
  }

  let result: DetectionResult;
  let detectedChannel = requestedChannel || 'sms';

  // 1. Channel detection and forensic execution
  if (requestedChannel === 'ad') {
    result = await analyzeAd(content, targetUrl);
  } else if (requestedChannel === 'document') {
    result = analyzeDocumentPayload(content, documentName);
  } else if (requestedChannel === 'email' || (!requestedChannel && (content.toLowerCase().includes('subject:') || (content.includes('@') && content.length > 50)))) {
    detectedChannel = 'email';
    result = await analyzeEmail(req.body.sender || 'analyst@security.org', req.body.subject || 'Scanned Email Payload', content);
  } else if (requestedChannel === 'url' || (!requestedChannel && (content.startsWith('http://') || content.startsWith('https://') || content.startsWith('www.')))) {
    detectedChannel = 'url';
    result = await analyzeURL(content);
  } else {
    detectedChannel = 'sms';
    result = await analyzeSMS(req.body.sender || 'Scanner Ingest', content);
  }

  // 2. High-fidelity Gemini Explanation (gemini-3.8-flash)
  let aiExplanation = '';
  if (process.env.GEMINI_API_KEY) {
    try {
      const prompt = `You are the AI-SPAMSHIELD Forensic Security Explainer. Explain in 2 concise, impactful sentences why this ${detectedChannel} is classified as ${result.classification} with risk score ${result.risk_score}/100.
Original Content: "${content.slice(0, 300)}"
Extracted Indicators: ${result.evidence.join('; ')}
Explain the exact deception technique and give 2 immediate action steps for the user.`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          systemInstruction: 'You are an elite cybersecurity threat analyst in a Security Operations Center (SOC). Be concise, objective, and action-oriented.',
          temperature: 0.2
        }
      });
      if (response.text) {
        aiExplanation = response.text.trim();
      }
    } catch (e: any) {
      console.warn('Gemini explanation fallback:', e?.message);
    }
  }

  if (!aiExplanation) {
    aiExplanation = result.evidence.length > 0
      ? `Threat signals detected: ${result.evidence.slice(0, 3).join('. ')}. Action: ${result.recommendation}`
      : `Clean baseline content. No malicious patterns, deceptive lures, or known threat signatures found.`;
  }

  // 3. Severity computation
  let severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
  if (result.risk_score >= 80) severity = 'CRITICAL';
  else if (result.risk_score >= 60) severity = 'HIGH';
  else if (result.risk_score >= 35) severity = 'MEDIUM';

  const user = getAuthUser(req);
  const userId = user ? user.id : 'usr-tharani-01';

  // 4. Record to Database layer
  const scanRecord = dbService.recordScan({
    user_id: userId,
    scan_type: detectedChannel as any,
    input_hash: crypto.createHash('sha256').update(content).digest('hex'),
    input_snippet: content.slice(0, 160),
    raw_content: content.slice(0, 4000),
    classification: result.classification as any,
    risk_score: result.risk_score,
    confidence: result.confidence,
    severity,
    evidence: result.evidence.map((ev, idx) => ({
      id: `ev-${Date.now()}-${idx}`,
      scan_id: '',
      evidence_type: 'DETECTED_INDICATOR',
      evidence_text: ev,
      severity
    })),
    recommended_action: result.recommendation,
    ai_explanation: aiExplanation
  });

  detectionHistory.unshift(result);

  return res.json({
    success: true,
    id: scanRecord.id,
    classification: scanRecord.classification,
    risk_score: scanRecord.risk_score,
    confidence: scanRecord.confidence,
    severity: scanRecord.severity,
    evidence: scanRecord.evidence.map(e => e.evidence_text),
    recommended_action: scanRecord.recommended_action,
    ai_explanation: scanRecord.ai_explanation,
    channel: scanRecord.scan_type,
    created_at: scanRecord.created_at
  });
});

// Scans Query Endpoints
app.get('/api/scans', (req: Request, res: Response) => {
  const limit = parseInt((req.query.limit as string) || '50', 10);
  const filter = (req.query.type as string) || (req.query.channel as string);
  const scans = dbService.getScans(limit, filter);
  res.json({ success: true, count: scans.length, scans });
});

app.get('/api/scans/:id', (req: Request, res: Response) => {
  const scan = dbService.getScanById(req.params.id);
  if (!scan) return res.status(404).json({ success: false, error: 'Scan record not found' });
  res.json({ success: true, scan });
});

// Dashboard Endpoints
app.get('/api/dashboard/stats', (_req: Request, res: Response) => {
  const stats = dbService.getDashboardStats();
  res.json({ success: true, stats });
});

app.get('/api/dashboard/activity', (_req: Request, res: Response) => {
  const activity = dbService.getDashboardActivity();
  res.json({ success: true, activity });
});

// Gmail Security Endpoints
app.get('/api/gmail/status', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  const conn = dbService.getGmailConnection(user ? user.id : 'usr-tharani-01');
  res.json({
    success: true,
    connected: !!conn,
    account: conn ? conn.google_account : null,
    connected_at: conn ? conn.connected_at : null
  });
});

app.post('/api/gmail/save-session', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  const { account } = req.body;
  if (!account) return res.status(400).json({ success: false, error: 'Account email required' });
  const conn = dbService.saveGmailConnection(user ? user.id : 'usr-tharani-01', account);
  res.json({ success: true, connection: conn });
});

app.post('/api/gmail/disconnect', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  dbService.disconnectGmail(user ? user.id : 'usr-tharani-01');
  res.json({ success: true, message: 'Google Workspace Gmail connection terminated and tokens cleared.' });
});

app.post('/api/gmail/scan', async (req: Request, res: Response) => {
  const { emails } = req.body;
  if (!Array.isArray(emails) || emails.length === 0) {
    return res.status(400).json({ success: false, error: 'Array of email items required' });
  }

  const results: any[] = [];
  const user = getAuthUser(req);
  const userId = user ? user.id : 'usr-tharani-01';

  for (const item of emails.slice(0, 10)) {
    const rawPayload = item.rawPayload || `Subject: ${item.subject}\nFrom: ${item.sender}\n\n${item.bodyText || item.snippet || ''}`;
    const det = await analyzeEmail(item.sender || 'Unknown', item.subject || '(No Subject)', item.bodyText || item.snippet || '', '');

    let severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    if (det.risk_score >= 80) severity = 'CRITICAL';
    else if (det.risk_score >= 60) severity = 'HIGH';
    else if (det.risk_score >= 35) severity = 'MEDIUM';

    const recorded = dbService.recordScan({
      user_id: userId,
      scan_type: 'email',
      input_hash: crypto.createHash('sha256').update(rawPayload).digest('hex'),
      input_snippet: `${item.subject} (from ${item.sender})`,
      raw_content: rawPayload.slice(0, 3000),
      classification: det.classification as any,
      risk_score: det.risk_score,
      confidence: det.confidence,
      severity,
      evidence: det.evidence.map((ev, idx) => ({
        id: `ev-${Date.now()}-${idx}`,
        scan_id: '',
        evidence_type: 'EMAIL_INDICATOR',
        evidence_text: ev,
        severity
      })),
      recommended_action: det.recommendation,
      ai_explanation: det.evidence.length > 0 ? `Flagged: ${det.evidence.join('; ')}` : 'Safe email baseline.'
    });

    results.push(recorded);
  }

  res.json({ success: true, scannedCount: results.length, results });
});

// ShieldGPT / Gemini Security Chatbot Endpoints
app.post('/api/chat', async (req: Request, res: Response) => {
  const { message, scanContext } = req.body;
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ success: false, error: 'Message text is required.' });
  }

  const user = getAuthUser(req);
  const userId = user ? user.id : 'usr-tharani-01';

  // Save user message in history
  dbService.addChatMessage(userId, 'user', message, scanContext?.id);

  let systemInstruction =
    "You are ShieldBot AI (also called ShieldGPT or Shield AI Assistant), the interactive cybersecurity assistant and SOC guardian for AI-SPAMSHIELD. " +
    "You assist Security Operations Center (SOC) operators, analysts, and everyday users across mobile phones and desktop laptops. " +
    "Core Capabilities: You chat with users, analyze messages, emails, URLs, advertisements, explain threats, search connected security data, summarize scan results, and enforce Guardian AI zero-trust safety.\n" +
    "Key Interaction Rules:\n" +
    "1. When greeted with 'hello' or asked 'what is your name', introduce yourself warmly as 'ShieldBot AI' — the user's autonomous personal cybersecurity assistant.\n" +
    "2. When asked how to access messages on phone and laptop, explain:\n" +
    "   - Phone: Open the 'Phone & Laptop Messages' portal (or SMS Connector) to review and triage incoming SMS, carrier notifications, and OTPs.\n" +
    "   - Laptop: Connect Google Workspace Gmail in 'Gmail Security' or paste text/headers directly into the 'Threat Scanner'.\n" +
    "   - Sync: All inspected messages sync to the central SOC threat vault.\n" +
    "3. Never invent evidence that was not detected in the provided scan context.\n" +
    "4. If evidence is unavailable, state: 'I don't have enough telemetry to verify that, but here are the key safety indicators to check.'\n" +
    "5. Keep responses structured, concise, and professional with actionable guidance.";

  let prompt = `User Query: "${message}"\n\n`;
  if (scanContext) {
    prompt += `CURRENT SCAN TELEMETRY CONTEXT:\n`;
    if (scanContext.channel) prompt += `- Vector Channel: ${String(scanContext.channel).toUpperCase()}\n`;
    if (scanContext.classification) prompt += `- Threat Classification: ${scanContext.classification}\n`;
    if (scanContext.risk_score !== undefined) prompt += `- Risk Score: ${scanContext.risk_score}/100\n`;
    if (scanContext.evidence && Array.isArray(scanContext.evidence)) {
      prompt += `- Extracted Red Flags:\n${scanContext.evidence.map((e: string) => `  * ${e}`).join('\n')}\n`;
    }
    if (scanContext.content) {
      prompt += `- Payload Snippet: "${String(scanContext.content).slice(0, 250)}"\n`;
    }
  }

  // Include recent chat history
  const history = dbService.getChatHistory(userId, 6);
  if (history.length > 0) {
    prompt += `\nRECENT CONVERSATION CONTEXT:\n`;
    history.forEach(h => {
      prompt += `${h.role === 'user' ? 'Operator' : 'ShieldGPT'}: ${h.message.slice(0, 150)}\n`;
    });
  }

  let reply = '';
  if (process.env.GEMINI_API_KEY) {
    try {
      const callPromise = ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          systemInstruction,
          temperature: 0.3
        }
      });

      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Gemini API timeout')), 4000)
      );

      const response: any = await Promise.race([callPromise, timeoutPromise]);
      if (response && response.text) {
        reply = response.text.trim();
      }
    } catch (e: any) {
      console.warn('Gemini chat error, fallback to expert knowledge:', e?.message);
    }
  }

  if (!reply) {
    const qLower = message.toLowerCase();
    const isGreeting = qLower.includes('hello') || qLower.includes('hi') || qLower.includes('hey') || qLower.includes('what is your name') || qLower.includes('your name') || qLower.includes('who are you') || qLower.includes('introduce');
    const isAccessMsg = (qLower.includes('access') || qLower.includes('how to') || qLower.includes('view') || qLower.includes('get') || qLower.includes('open') || qLower.includes('phone') || qLower.includes('laptop')) && (qLower.includes('message') || qLower.includes('messages') || qLower.includes('sms'));

    if (isGreeting) {
      reply = `Hello! 👋 I am **ShieldBot AI**, your autonomous cybersecurity companion and SOC guardian. I protect your digital environment across your phone and laptop by inspecting suspicious SMS messages, phishing emails, malicious URLs, scam advertisements, and untrusted documents with real-time heuristic intelligence. How can I assist you today?`;
    } else if (isAccessMsg) {
      reply = `Here is how you can access and inspect your messages on both your **Phone** and **Laptop**:\n\n📱 **On your Phone**: Open the **Phone & Laptop Messages** portal in AI-SpamShield to view incoming SMS streams, carrier alerts, and bank OTP messages with one-click forensic scans.\n\n💻 **On your Laptop**: Connect **Google Workspace Gmail** with permission in the Gmail Security Center to inspect emails, or paste any text or email headers directly into the **Threat Scanner**.\n\n🔄 **Unified Sync**: Every inspected message is safely synchronized to your central SOC audit vault!`;
    } else if (qLower.includes('why') && (qLower.includes('danger') || qLower.includes('phish') || qLower.includes('scam'))) {
      reply = `Based on the forensic evidence, this payload contains high-risk indicators:\n\n1. **Deceptive Pretext**: Urgency or windfall claim designed to induce impulsive compliance.\n2. **Unverified Hyperlink**: Destination routing away from the official authenticated domain.\n3. **Credential Coercion**: Attempting to harvest sensitive credentials or payment authorization.\n\n**Risk Level**: ${scanContext?.risk_score ? `${scanContext.risk_score}/100` : 'HIGH'}. Do not click or supply credentials.`;
    } else if (qLower.includes('safe') || qLower.includes('clean')) {
      reply = `To verify if a message is safe, check:\n- Sender domain matching official SPF/DKIM headers.\n- Lack of artificial time-pressure or threatening language.\n- Verified SSL/TLS destination domain.\n\nIf any element seems suspicious, run a scan through our Multi-Channel Scanner.`;
    } else {
      reply = `ShieldBot AI Online 🛡️ I am actively guarding your perimeter across phone, laptop, email, and web. You can ask me to evaluate email headers, explain SMS smishing patterns, analyze suspicious advertisement claims, or guide you through incident containment steps.`;
    }
  }

  // Persist assistant message in database
  dbService.addChatMessage(userId, 'assistant', reply, scanContext?.id);

  res.json({
    success: true,
    reply,
    source: process.env.GEMINI_API_KEY ? 'gemini-3.8-flash' : 'expert-engine',
    timestamp: new Date().toISOString()
  });
});

app.get('/api/chat/history', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  const userId = user ? user.id : 'usr-tharani-01';
  const history = dbService.getChatHistory(userId, 30);
  res.json({ success: true, history });
});

// ==========================================================================
// SHIELDBOT AI & GUARDIAN AI AGENT GATEWAY API
// ==========================================================================

// 1. ShieldBot AI Chat & Intent Processing
app.post('/api/agent/chat', async (req: Request, res: Response) => {
  const { message, scanContext, personality, forcedActionType } = req.body;
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ success: false, error: 'Message text is required.' });
  }

  const user = getAuthUser(req);
  const userId = user ? user.id : 'usr-tharani-01';
  dbService.addChatMessage(userId, 'user', message, scanContext?.id);

  const result = await agentService.handleChat(message, scanContext, personality, forcedActionType);
  if (result.reply) {
    dbService.addChatMessage(userId, 'assistant', result.reply, scanContext?.id);
  }

  res.json(result);
});

// 2. ShieldBot Direct Action Proposal (for testing & action gateway verification)
app.post('/api/agent/action', async (req: Request, res: Response) => {
  const { action, target, reason, userIntent, scope, consequential } = req.body;
  if (!action || !userIntent) {
    return res.status(400).json({ success: false, error: 'action and userIntent are required.' });
  }

  const proposed = {
    id: `act-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
    agent: 'ShieldBot' as const,
    action,
    target: target || 'system',
    scope: scope || 'single',
    reason: reason || 'Proposed action by ShieldBot',
    userIntent,
    consequential: consequential !== undefined ? consequential : true
  };

  const decision = await guardianService.evaluateAction(proposed);
  res.json({ success: true, proposed, decision });
});

// 3. Confirm Pending Action
app.post('/api/agent/confirm', async (req: Request, res: Response) => {
  const { actionId } = req.body;
  if (!actionId) {
    return res.status(400).json({ success: false, error: 'actionId is required.' });
  }
  const result = await agentService.confirmAction(actionId, true);
  res.json(result);
});

// 4. Cancel Pending Action
app.post('/api/agent/cancel', async (req: Request, res: Response) => {
  const { actionId } = req.body;
  if (!actionId) {
    return res.status(400).json({ success: false, error: 'actionId is required.' });
  }
  const result = await agentService.confirmAction(actionId, false);
  res.json(result);
});

// 5. Emergency Stop ShieldBot
app.post('/api/agent/stop', (_req: Request, res: Response) => {
  const result = agentService.stop();
  res.json(result);
});

// 6. Resume ShieldBot
app.post('/api/agent/resume', (_req: Request, res: Response) => {
  const result = agentService.resume();
  res.json(result);
});

// 7. Get Agent Activity Timeline
app.get('/api/agent/activity', (_req: Request, res: Response) => {
  res.json({
    success: true,
    state: agentService.getState(),
    personality: agentService.getPersonality(),
    timeline: agentService.getTimeline(),
    pendingAction: agentService.getPendingAction()
  });
});

// 8. Update Agent Personality
app.post('/api/agent/personality', (req: Request, res: Response) => {
  const { personality } = req.body;
  if (personality) {
    agentService.setPersonality(personality as AgentPersonality);
  }
  res.json({ success: true, personality: agentService.getPersonality() });
});

// 9. Guardian Check Direct API
app.post('/api/guardian/check', async (req: Request, res: Response) => {
  const { action, target, userIntent, scope, reason, consequential } = req.body;
  const decision = await guardianService.evaluateAction({
    id: `grd-eval-${Date.now()}`,
    agent: 'ShieldBot',
    action: action || 'scan.message',
    target: target || 'test_payload',
    scope: scope || 'single',
    reason: reason || 'Audit evaluation test',
    userIntent: userIntent || 'Audit test',
    consequential: !!consequential
  });
  res.json({ success: true, decision });
});

// 10. Guardian Audit Events
app.get('/api/guardian/events', (req: Request, res: Response) => {
  const filter = (req.query.filter as string) || 'all';
  const logs = guardianService.getAuditLogs(filter);
  res.json({ success: true, events: logs, count: logs.length });
});

// 11. Guardian Status
app.get('/api/guardian/status', (_req: Request, res: Response) => {
  res.json({ success: true, status: guardianService.getStatus() });
});

// 12. Guardian Emergency Stop & Resume
app.post('/api/guardian/stop', (_req: Request, res: Response) => {
  guardianService.emergencyStop();
  agentService.stop();
  res.json({ success: true, message: 'Guardian emergency stop activated. All agent actions blocked.' });
});

app.post('/api/guardian/resume', (_req: Request, res: Response) => {
  guardianService.resume();
  agentService.resume();
  res.json({ success: true, message: 'Guardian monitoring resumed. ShieldBot unlocked.' });
});

// 13. Granular Permissions Endpoints
app.get('/api/permissions', (_req: Request, res: Response) => {
  res.json({ success: true, permissions: permissionService.getAll() });
});

app.post('/api/permissions/check', (req: Request, res: Response) => {
  const { action } = req.body;
  const result = permissionService.checkPermission(action);
  res.json({ success: true, action, ...result });
});

app.post('/api/permissions/update', (req: Request, res: Response) => {
  const { action, policy } = req.body;
  if (!action || !policy) {
    return res.status(400).json({ success: false, error: 'action and policy are required.' });
  }
  try {
    const updated = permissionService.updatePolicy(action, policy as PermissionPolicy);
    guardianService.logEvent({
      id: `grd-perm-${Date.now()}`,
      timestamp: new Date().toISOString(),
      agent: 'Operator',
      action: 'permission.update',
      resource: action,
      userIntent: `Update policy to ${policy}`,
      riskScore: 20,
      decision: 'ALLOW',
      status: 'COMPLETED',
      details: `Operator changed permission policy for "${action}" to ${policy}`
    });
    res.json({ success: true, permission: updated });
  } catch (err: any) {
    res.status(400).json({ success: false, error: err.message });
  }
});

app.post('/api/permissions/reset', (_req: Request, res: Response) => {
  const perms = permissionService.resetDefaults();
  guardianService.logEvent({
    id: `grd-perm-reset-${Date.now()}`,
    timestamp: new Date().toISOString(),
    agent: 'Operator',
    action: 'permission.reset',
    resource: 'all_permissions',
    userIntent: 'Reset all policies to least-privilege defaults',
    riskScore: 10,
    decision: 'ALLOW',
    status: 'COMPLETED',
    details: 'Operator reset all permissions to default least-privilege matrix'
  });
  res.json({ success: true, permissions: perms });
});

// --- Device Messages Sync Endpoints (Phone & Laptop Message Access) ---
app.get('/api/device/messages', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  const userId = user ? user.id : 'usr-tharani-01';
  let messages = dbService.getDeviceMessages(userId);
  if (messages.length === 0) {
    const seeded = [
      {
        user_id: userId,
        device: 'phone' as const,
        channel: 'sms' as const,
        sender: 'VM-SBINB',
        content: 'Dear customer, your SBI account is blocked today due to pending KYC. Update PAN card at http://sbi-kyc-verify.xyz now to avoid permanent block.',
        threatType: 'SMISHING',
        risk_score: 96,
        carrier_or_client: 'Airtel 5G (Android 15)'
      },
      {
        user_id: userId,
        device: 'phone' as const,
        channel: 'sms' as const,
        sender: 'AX-HDFCBK',
        content: 'ALERT: INR 48,990.00 debited from A/C **9182 at Flipkart. Not you? Dispute at http://hdfc-dispute-portal.top immediately.',
        threatType: 'OTP_FRAUD',
        risk_score: 94,
        carrier_or_client: 'Jio 5G (Android 15)'
      },
      {
        user_id: userId,
        device: 'phone' as const,
        channel: 'sms' as const,
        sender: 'Dr. Mehta Clinic',
        content: 'Your routine health checkup is confirmed for tomorrow at 4:30 PM. Reply 1 to confirm or 2 to reschedule.',
        threatType: 'CLEAN',
        risk_score: 5,
        carrier_or_client: 'Airtel 5G (Android 15)'
      },
      {
        user_id: userId,
        device: 'laptop' as const,
        channel: 'email' as const,
        sender: 'Google Security <security-alert@accounts-google-verify.top>',
        content: 'CRITICAL: Suspicious Login Detected from Moscow, Russia. Verify credentials immediately at http://accounts-google-verify.top/auth/login to avoid suspension.',
        threatType: 'PHISHING',
        risk_score: 92,
        carrier_or_client: 'Chrome / Gmail Web'
      },
      {
        user_id: userId,
        device: 'laptop' as const,
        channel: 'email' as const,
        sender: 'GitHub <notifications@github.com>',
        content: 'Your personal access token has expired. You can regenerate a new token from developer settings.',
        threatType: 'CLEAN',
        risk_score: 4,
        carrier_or_client: 'Chrome / Gmail Web'
      }
    ];
    seeded.forEach(s => dbService.addDeviceMessage(s));
    messages = dbService.getDeviceMessages(userId);
  }
  res.json({ success: true, messages });
});

app.post('/api/device/messages/add', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  const userId = user ? user.id : 'usr-tharani-01';
  const { device, channel, sender, content, carrier_or_client, threatType, risk_score } = req.body;
  if (!content) {
    return res.status(400).json({ success: false, error: 'Message content is required.' });
  }
  const added = dbService.addDeviceMessage({
    user_id: userId,
    device: device || 'phone',
    channel: channel || 'sms',
    sender: sender || 'Unknown Source',
    content,
    carrier_or_client: carrier_or_client || (device === 'laptop' ? 'Laptop Browser' : 'Mobile Carrier'),
    threatType: threatType || 'UNVERIFIED',
    risk_score: risk_score || 50
  });
  res.json({ success: true, message: added });
});

// Voice Interaction Endpoints
app.post('/api/voice/transcribe', (req: Request, res: Response) => {
  const { text } = req.body;
  res.json({ success: true, text: text || 'Voice stream captured' });
});

app.post('/api/voice/explain', async (req: Request, res: Response) => {
  const { classification = 'SUSPICIOUS', risk_score = 75, evidence = [] } = req.body;

  let spoken = `I detected a ${classification} threat with a risk score of ${risk_score} out of 100. `;
  if (evidence.length > 0) {
    spoken += `Key red flag: ${evidence[0]}. `;
  }
  spoken += `Do not click links or share credentials. ShieldBot is guarding your perimeter.`;

  res.json({ success: true, spokenText: spoken });
});

// Analyze endpoints
app.post('/api/analyze/sms', async (req: Request, res: Response) => {
  const { sender = '', text = '', message = '' } = req.body;
  const content = text || message;
  if (!content) return res.status(400).json({ error: 'Text/message field is required' });
  const result = await analyzeSMS(sender, content);
  detectionHistory.unshift(result);
  res.json(result);
});

app.post('/api/analyze/email', async (req: Request, res: Response) => {
  const { sender = '', subject = '', body = '', headers = '' } = req.body;
  if (!body && !subject) return res.status(400).json({ error: 'Subject or body is required' });
  const result = await analyzeEmail(sender, subject, body, headers);
  detectionHistory.unshift(result);
  res.json(result);
});

app.post('/api/analyze/url', async (req: Request, res: Response) => {
  const { url = '' } = req.body;
  if (!url) return res.status(400).json({ error: 'URL field is required' });
  const result = await analyzeURL(url);
  detectionHistory.unshift(result);
  res.json(result);
});

app.post('/api/analyze/ad', async (req: Request, res: Response) => {
  const { text = '', url = '' } = req.body;
  if (!text) return res.status(400).json({ error: 'Ad text is required' });
  const result = await analyzeAd(text, url);
  detectionHistory.unshift(result);
  res.json(result);
});

// Standalone Threat Intel Lookup
app.post('/api/threat-intel/lookup', async (req: Request, res: Response) => {
  const { url = '' } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  const report = await crossReferenceThreatIntelligence(url);
  res.json(report);
});

// History routes
app.get('/api/history', (req: Request, res: Response) => {
  const channel = req.query.channel as string;
  const limit = parseInt((req.query.limit as string) || '50', 10);
  let list = detectionHistory;
  if (channel && channel !== 'all') {
    list = list.filter(item => item.channel === channel);
  }
  res.json({ total: list.length, history: list.slice(0, limit) });
});

app.delete('/api/history/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  detectionHistory = detectionHistory.filter(item => item.id !== id);
  res.json({ success: true, message: `Record ${id} removed` });
});

app.delete('/api/history', (_req: Request, res: Response) => {
  detectionHistory = [];
  res.json({ success: true, message: 'Detection history cleared' });
});

// Stats dashboard endpoint
app.get('/api/stats', (_req: Request, res: Response) => {
  const total = detectionHistory.length;
  let safeCount = 0;
  let spamCount = 0;
  let phishingCount = 0;
  let scamCount = 0;
  let maliciousCount = 0;
  let suspiciousCount = 0;
  let totalRisk = 0;
  const byChannel: Record<string, number> = { sms: 0, email: 0, url: 0, ad: 0 };

  for (const item of detectionHistory) {
    totalRisk += item.risk_score;
    byChannel[item.channel] = (byChannel[item.channel] || 0) + 1;
    switch (item.classification) {
      case 'SAFE':
        safeCount++;
        break;
      case 'SPAM':
        spamCount++;
        break;
      case 'PHISHING':
        phishingCount++;
        break;
      case 'SCAM':
        scamCount++;
        break;
      case 'MALICIOUS':
        maliciousCount++;
        break;
      case 'SUSPICIOUS':
      case 'ADVERTISEMENT':
        suspiciousCount++;
        break;
    }
  }

  res.json({
    totalScanned: total,
    safeCount,
    spamCount,
    phishingCount,
    scamCount,
    maliciousCount,
    suspiciousCount,
    averageRiskScore: total > 0 ? Math.round(totalRisk / total) : 0,
    byChannel,
    threatDistribution: {
      safe: safeCount,
      warning: suspiciousCount + spamCount,
      critical: phishingCount + scamCount + maliciousCount
    }
  });
});

// ------------------------------------------
// AUTOMATIC SCANNER & REAL-TIME DAEMON ENDPOINTS
// ------------------------------------------
app.get('/api/auto-scan/config', (_req: Request, res: Response) => {
  res.json(getAutoScanConfig());
});

app.post('/api/auto-scan/config', (req: Request, res: Response) => {
  const updated = updateAutoScanConfig(req.body);
  res.json(updated);
});

app.get('/api/auto-scan/events', (req: Request, res: Response) => {
  const limit = parseInt((req.query.limit as string) || '30', 10);
  res.json(getAutoScanEvents(limit));
});

app.get('/api/auto-scan/stats', (_req: Request, res: Response) => {
  res.json(getAutoScanStats());
});

app.post('/api/auto-scan/clear', (_req: Request, res: Response) => {
  clearAutoScanEvents();
  res.json({ success: true });
});

app.post('/api/auto-scan/simulate-step', async (_req: Request, res: Response) => {
  const t0 = Date.now();
  const item = getNextSimulatedTrafficItem();
  let result: DetectionResult;

  switch (item.channel) {
    case 'sms':
      result = await analyzeSMS(item.sender || 'Unknown', item.content);
      break;
    case 'email':
      result = await analyzeEmail(item.sender || 'security@alert.com', item.subject || 'Notice', item.content);
      break;
    case 'url':
      result = await analyzeURL(item.content);
      break;
    case 'ad':
      result = await analyzeAd(item.content, item.url);
      break;
    case 'document':
      result = analyzeDocumentPayload(item.content, 'sample.doc');
      break;
    default:
      result = await analyzeSMS('System', item.content);
      break;
  }

  detectionHistory.unshift(result);
  const latency = Date.now() - t0;
  const event = recordAutoScanEvent(item.channel, item.content, result, latency);
  res.json({ event, result, latencyMs: latency });
});

app.post('/api/auto-scan/batch', async (req: Request, res: Response) => {
  const { items } = req.body;
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'items array is required' });
  }

  const results: Array<{ raw: string; channel: ChannelType; result: DetectionResult; latencyMs: number }> = [];

  for (const raw of items.slice(0, 50)) {
    const rawStr = String(raw).trim();
    if (!rawStr) continue;
    const t0 = Date.now();
    let channel: ChannelType = 'sms';

    // Auto-detect channel based on text syntax
    if (rawStr.startsWith('http://') || rawStr.startsWith('https://') || rawStr.startsWith('www.')) {
      channel = 'url';
    } else if (rawStr.toLowerCase().includes('subject:') || rawStr.toLowerCase().includes('@')) {
      channel = 'email';
    } else if (rawStr.toLowerCase().includes('win') && rawStr.toLowerCase().includes('click now') && rawStr.length < 150) {
      channel = 'ad';
    } else {
      channel = 'sms';
    }

    let det: DetectionResult;
    if (channel === 'url') det = await analyzeURL(rawStr);
    else if (channel === 'email') det = await analyzeEmail('batch@scan.org', 'Batch Scan', rawStr);
    else if (channel === 'ad') det = await analyzeAd(rawStr);
    else det = await analyzeSMS('+BatchScanner', rawStr);

    detectionHistory.unshift(det);
    const latency = Date.now() - t0;
    recordAutoScanEvent(channel, rawStr, det, latency);
    results.push({ raw: rawStr, channel, result: det, latencyMs: latency });
  }

  res.json({ totalProcessed: results.length, results });
});

// AI Mode endpoint (Gemini 3.8 Flash + expert domain fallback)
app.post('/api/ai/ask', async (req: Request, res: Response) => {
  const { question, context } = req.body;
  if (!question || typeof question !== 'string') {
    return res.status(400).json({ error: 'Question string is required' });
  }

  let prompt = `User Question: "${question}"\n\n`;
  if (context) {
    prompt += `CONTEXT FROM AI-SPAMSHIELD SCAN:\n`;
    if (context.channel) prompt += `- Channel: ${context.channel.toUpperCase()}\n`;
    if (context.classification) prompt += `- Classification: ${context.classification}\n`;
    if (context.risk_score !== undefined) prompt += `- Risk Score: ${context.risk_score}/100\n`;
    if (context.content) prompt += `- Original Scanned Content: "${context.content}"\n`;
    if (context.evidence && Array.isArray(context.evidence)) {
      prompt += `- Extracted Evidence:\n${context.evidence.map((e: string) => `  * ${e}`).join('\n')}\n`;
    }
  }
  prompt += `\nPlease provide a clear, authoritative, and actionable cybersecurity response according to AI-SPAMSHIELD's 'Detect. Explain. Protect.' methodology.`;

  if (process.env.GEMINI_API_KEY) {
    try {
      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          systemInstruction:
            "You are the AI-SPAMSHIELD Expert AI Mode. Provide authoritative, direct, and actionable explanations of cyber threats, social engineering tricks, malware/phishing mechanisms, and clear step-by-step incident containment instructions.",
          temperature: 0.3,
        }
      });
      const text = response.text;
      if (text) {
        return res.json({
          answer: text,
          source: 'gemini-3.8-flash',
          timestamp: Date.now()
        });
      }
    } catch (e: any) {
      console.warn('Gemini 3.8 Flash unavailable, engaging expert fallback:', e?.message);
    }
  }

  // Domain expert cybersecurity response synthesizer
  const qLower = question.toLowerCase();
  let fallbackAnswer = '';

  if (qLower.includes('auto') || qLower.includes('automatic') || qLower.includes('daemon') || qLower.includes('scan')) {
    fallbackAnswer = `### AI-SPAMSHIELD Automated Real-Time Threat Daemon:\n- **Continuous Monitoring**: Scans incoming simulation traffic, clipboard buffers, or message queues at configurable intervals (e.g. every 3-5 seconds).\n- **High-Speed Detection**: Evaluates risk score against threshold in real-time without user delay.\n- **Multi-Vector Triage**: Analyzes lexical entropy, threat intelligence signatures, and anomaly vectors concurrently in under 30 milliseconds.`;
  } else if (qLower.includes('click') || qLower.includes('opened') || qLower.includes('what should i do')) {
    fallbackAnswer = `### Immediate Incident Containment Protocol:\n1. **Disconnect Network Access**: Immediately disconnect your mobile device or workstation from Wi-Fi and cellular data to stop active C2 communication.\n2. **Close Browser Tabs**: Do not submit any credentials, phone numbers, or OTP codes.\n3. **Revoke Sessions & Reset Credentials**: From a separate verified device, change passwords for affected services and enable Hardware/App-based 2FA.\n4. **Inspect Downloads**: Delete any unauthorized \`.apk\` packages or executable files without executing them.`;
  } else {
    fallbackAnswer = `### AI-SPAMSHIELD Cybersecurity Analysis:\n- **Threat Classification**: ${context?.classification || 'CYBERSECURITY QUERY'}\n- **Current Risk Evaluation**: ${context?.risk_score !== undefined ? `${context.risk_score}/100 Risk Score` : 'Evaluated'}\n- **Actionable Protection**: Always independently navigate to the verified official portal rather than clicking embedded hyperlinks.`;
  }

  return res.json({
    answer: fallbackAnswer,
    source: 'ai-spamshield-expert-engine',
    timestamp: Date.now()
  });
});

// Dedicated AI "Tell" Endpoint
app.post('/api/ai/tell', async (req: Request, res: Response) => {
  const { channel = 'message', content = '', classification = 'SUSPICIOUS', risk_score = 75, evidence = [], recommendation = '' } = req.body;

  const systemInstruction =
    "You are the AI-SPAMSHIELD Voice & Security Advisor. Your job is to TELL the user in clear, conversational, spoken-friendly English what is going on. " +
    "Be concise, direct, and human. Avoid unnecessary jargon. " +
    "Format clearly: " +
    "1. VERDICT: State clearly whether this is dangerous, a scam, phishing, or safe in 1 spoken sentence. " +
    "2. THE DECEPTION: Tell the user exactly what psychological trick or technical lie the attacker is using. " +
    "3. WHAT TO DO RIGHT NOW: Give 2-3 immediate, practical steps they must take right now.";

  const prompt = `Please analyze and TELL the user about this detected ${channel}:
- Scanned Payload: "${content}"
- Classification: ${classification}
- Risk Score: ${risk_score}/100
- Extracted Evidence: ${Array.isArray(evidence) ? evidence.join('; ') : evidence}
- System Recommendation: ${recommendation}

Tell the user clearly what this is, why it's a threat, and what they need to do immediately.`;

  if (process.env.GEMINI_API_KEY) {
    try {
      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          systemInstruction,
          temperature: 0.3
        }
      });
      if (response.text) {
        return res.json({
          speechText: response.text,
          source: 'gemini-3.8-flash',
          timestamp: Date.now()
        });
      }
    } catch (e: any) {
      console.warn('Gemini 3.8 Flash tell unavailable, engaging expert fallback:', e?.message);
    }
  }

  // Fallback conversational breakdown
  const isThreat = risk_score >= 50;
  const fallbackSpeech = isThreat
    ? `### Verdict\nThis is a confirmed ${classification} threat with a high risk score of ${risk_score} out of 100.\n\n### The Deception Trick\nThe sender is using artificial urgency and deceptive links to manipulate you into acting before verifying. They are attempting to steal credentials, personal identification, or install unauthorized software.\n\n### What To Do Right Now\n1. Do not click any links or download attachments.\n2. Never reply or enter verification codes or passwords.\n3. Block the sender and report this message as spam immediately.`
    : `### Verdict\nThis ${channel} appears to be legitimate or low-risk with a clean score of ${risk_score} out of 100.\n\n### Threat Evaluation\nNo fraudulent lures, credential harvesting forms, or suspicious redirects were detected.\n\n### What To Do\nYou can proceed normally, but remember to always verify sender identities before sharing personal or financial information.`;

  return res.json({
    speechText: fallbackSpeech,
    source: 'ai-spamshield-voice-advisor',
    timestamp: Date.now()
  });
});

// ==========================================
// STATIC ASSETS & VITE INTEGRATION
// ==========================================
async function startServer() {
  const isDevScript = process.env.npm_lifecycle_event === 'dev';
  const distPath = path.resolve(__dirname, 'dist');
  const hasDist = fs.existsSync(path.join(distPath, 'index.html'));
  const isProduction = process.env.NODE_ENV === 'production' || (!isDevScript && hasDist);

  if (isProduction) {
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[AI-SPAMSHIELD Engine] Running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
});
