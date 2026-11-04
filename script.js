/**
 * AI-SPAMSHIELD — SHIELDBOT Interactive AI Cybersecurity Agent
 * Real-time frontend companion with dynamic movement, expressions,
 * speech synthesis, and deep threat explanation.
 */

(function () {
  'use strict';

  // State Management
  const state = {
    aiActive: false,
    currentMood: 'IDLE', // IDLE, ACTIVATING, SCANNING, SAFE, SUSPICIOUS, HIGH_RISK, PHISHING, SPAM, SCAM, THINKING
    currentPosition: 'home',
    soundEnabled: true,
    lastScanResult: null,
    isDragging: false,
    dragStart: { x: 0, y: 0 },
    robotPos: { x: 0, y: 0 },
    hasDragged: false,
    typingTimer: null
  };

  // DOM Elements
  let elRobotWrapper;
  let elSpeechBubble;
  let elBubbleText;
  let elBubbleMood;
  let elEyeLeft;
  let elEyeRight;
  let elScanBeam;
  let elDialogPanel;
  let elDialogChat;
  let elDialogInput;
  let elActivateBtn;
  let elScannerTextarea;
  let elScanSubmitBtn;
  let elRadarBox;
  let elVerdictSection;
  let elHistoryTbody;

  // Web Audio Synthesizer for futuristic robotic audio feedback
  const audioContext = (function () {
    let ctx = null;
    return function () {
      if (!ctx && (window.AudioContext || window.webkitAudioContext)) {
        ctx = new (window.AudioContext || window.webkitAudioContext)();
      }
      return ctx;
    };
  })();

  function playCyberSound(type) {
    if (!state.soundEnabled) return;
    try {
      const ctx = audioContext();
      if (!ctx) return;
      if (ctx.state === 'suspended') ctx.resume();

      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      if (type === 'boot') {
        // Futuristic boot chord
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(140, now);
        osc.frequency.exponentialRampToValueAtTime(580, now + 0.35);
        gain.gain.setValueAtTime(0.12, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.45);
        osc.start(now);
        osc.stop(now + 0.45);
      } else if (type === 'scan') {
        // Frequency sweep laser
        osc.type = 'sine';
        osc.frequency.setValueAtTime(450, now);
        osc.frequency.linearRampToValueAtTime(950, now + 0.2);
        osc.frequency.linearRampToValueAtTime(350, now + 0.4);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.45);
        osc.start(now);
        osc.stop(now + 0.45);
      } else if (type === 'safe') {
        // Cheerful major chord blip
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(523.25, now); // C5
        osc.frequency.setValueAtTime(659.25, now + 0.1); // E5
        osc.frequency.setValueAtTime(783.99, now + 0.2); // G5
        gain.gain.setValueAtTime(0.12, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
        osc.start(now);
        osc.stop(now + 0.35);
      } else if (type === 'alert') {
        // Warning siren pulse
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(800, now);
        osc.frequency.setValueAtTime(400, now + 0.15);
        osc.frequency.setValueAtTime(850, now + 0.3);
        gain.gain.setValueAtTime(0.18, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.4);
        osc.start(now);
        osc.stop(now + 0.4);
      } else if (type === 'click') {
        // Subdued mechanical click
        osc.type = 'sine';
        osc.frequency.setValueAtTime(1200, now);
        gain.gain.setValueAtTime(0.05, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.05);
        osc.start(now);
        osc.stop(now + 0.05);
      }
    } catch {
      // Audio not permitted without interaction
    }
  }

  // ==========================================================================
  // SHIELDBOT MOVEMENT SYSTEM
  // ==========================================================================

  function initRobotPosition() {
    // Default home: bottom-right of viewport with safe margins
    const margin = 24;
    const x = window.innerWidth - 210 - margin;
    const y = window.innerHeight - 250 - margin;
    setRobotCoordinates(Math.max(10, x), Math.max(10, y));
  }

  function setRobotCoordinates(x, y) {
    // Keep robot strictly inside viewport
    const maxX = window.innerWidth - (elRobotWrapper.offsetWidth || 180) - 10;
    const maxY = window.innerHeight - (elRobotWrapper.offsetHeight || 220) - 10;
    
    state.robotPos.x = Math.max(10, Math.min(x, maxX));
    state.robotPos.y = Math.max(10, Math.min(y, maxY));

    elRobotWrapper.style.transform = `translate3d(${state.robotPos.x}px, ${state.robotPos.y}px, 0)`;
  }

  /**
   * Move ShieldBot smoothly to predefined application zones
   */
  window.moveShieldBot = function (target) {
    if (!elRobotWrapper) return;
    state.currentPosition = target;

    const viewportW = window.innerWidth;
    const viewportH = window.innerHeight;
    const isMobile = viewportW < 768;

    let targetX = state.robotPos.x;
    let targetY = state.robotPos.y;

    if (target === 'home') {
      targetX = viewportW - (isMobile ? 150 : 200) - 20;
      targetY = viewportH - (isMobile ? 190 : 250) - 20;
    } else {
      // Look for DOM elements matching the target
      let anchorSelector = '';
      if (target === 'scanner') anchorSelector = '#scanner-section';
      else if (target === 'analyzing') anchorSelector = '#radar-analysis-box';
      else if (target === 'result') anchorSelector = '#verdict-section';
      else if (target === 'evidence') anchorSelector = '#evidence-list-container';
      else if (target === 'history') anchorSelector = '#history-section';
      else if (target === 'assistant') anchorSelector = '#shieldbot-dialog';

      const anchorEl = anchorSelector ? document.querySelector(anchorSelector) : null;

      if (anchorEl) {
        const rect = anchorEl.getBoundingClientRect();
        // Position robot slightly to the right or above depending on layout
        if (isMobile) {
          targetX = Math.max(10, viewportW - 160);
          targetY = Math.max(80, rect.top - 70);
        } else {
          // If wide screen, position just to the right or left of element
          if (rect.right + 210 < viewportW) {
            targetX = rect.right + 15;
            targetY = Math.max(75, rect.top + 10);
          } else {
            targetX = Math.max(10, rect.left - 200);
            targetY = Math.max(75, rect.top + 10);
          }
        }
      }
    }

    setRobotCoordinates(targetX, targetY);
  };

  // ==========================================================================
  // DRAGGING SYSTEM
  // ==========================================================================

  function setupDragging() {
    let startX = 0;
    let startY = 0;
    let initialX = 0;
    let initialY = 0;

    function onPointerDown(e) {
      if (e.target.closest('.shieldbot-speech-bubble') || e.target.closest('button')) {
        return;
      }
      state.isDragging = true;
      state.hasDragged = false;
      const clientX = e.clientX || (e.touches && e.touches[0].clientX);
      const clientY = e.clientY || (e.touches && e.touches[0].clientY);

      startX = clientX;
      startY = clientY;
      initialX = state.robotPos.x;
      initialY = state.robotPos.y;

      elRobotWrapper.style.transition = 'none'; // Instant tracking while dragging
      document.body.style.userSelect = 'none';

      window.addEventListener('pointermove', onPointerMove, { passive: false });
      window.addEventListener('pointerup', onPointerUp);
    }

    function onPointerMove(e) {
      if (!state.isDragging) return;
      const clientX = e.clientX || (e.touches && e.touches[0].clientX);
      const clientY = e.clientY || (e.touches && e.touches[0].clientY);

      const dx = clientX - startX;
      const dy = clientY - startY;

      if (Math.abs(dx) > 5 || Math.abs(dy) > 5) {
        state.hasDragged = true;
      }

      setRobotCoordinates(initialX + dx, initialY + dy);
      e.preventDefault();
    }

    function onPointerUp() {
      if (!state.isDragging) return;
      state.isDragging = false;
      document.body.style.userSelect = '';
      elRobotWrapper.style.transition = 'transform 0.65s cubic-bezier(0.25, 1, 0.5, 1)';

      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerup', onPointerUp);

      // Snap gently to nearest viewport edge (left or right)
      const currentX = state.robotPos.x;
      const midPoint = window.innerWidth / 2;
      let snapX = currentX;

      if (currentX < midPoint) {
        snapX = 20; // Snap toward left margin
      } else {
        snapX = window.innerWidth - (elRobotWrapper.offsetWidth || 180) - 20; // Snap toward right margin
      }

      setRobotCoordinates(snapX, state.robotPos.y);

      // If user merely tapped/clicked without dragging, open Companion Panel
      if (!state.hasDragged) {
        toggleShieldBotDialog();
      }
    }

    elRobotWrapper.addEventListener('pointerdown', onPointerDown);
  }

  // ==========================================================================
  // SHIELDBOT SPEECH BUBBLE & TYPEWRITER SYSTEM
  // ==========================================================================

  function speak(text, mood = 'SECURITY AGENT', delay = 25, autoDismissMs = 6000) {
    if (!elSpeechBubble || !elBubbleText) return;

    if (state.typingTimer) {
      clearInterval(state.typingTimer);
    }

    elBubbleMood.textContent = mood;
    elBubbleText.innerHTML = '';
    elSpeechBubble.classList.add('visible');

    let i = 0;
    playCyberSound('click');

    state.typingTimer = setInterval(() => {
      if (i < text.length) {
        elBubbleText.textContent += text.charAt(i);
        i++;
      } else {
        clearInterval(state.typingTimer);
        state.typingTimer = null;
        if (autoDismissMs > 0) {
          setTimeout(() => {
            elSpeechBubble.classList.remove('visible');
          }, autoDismissMs);
        }
      }
    }, delay);
  }

  // ==========================================================================
  // EXPRESSIONS & MOOD ENGINE
  // ==========================================================================

  function setShieldBotMood(mood) {
    state.currentMood = mood;
    if (!elRobotWrapper) return;

    // Reset mood classes
    elRobotWrapper.classList.remove('inactive', 'active', 'scanning', 'safe', 'suspicious', 'high-risk', 'alert');

    if (!state.aiActive) {
      elRobotWrapper.classList.add('inactive');
      return;
    }

    elRobotWrapper.classList.add('active');

    switch (mood) {
      case 'SCANNING':
        elRobotWrapper.classList.add('scanning');
        playCyberSound('scan');
        break;
      case 'SAFE':
        elRobotWrapper.classList.add('safe');
        playCyberSound('safe');
        break;
      case 'SUSPICIOUS':
        elRobotWrapper.classList.add('suspicious');
        playCyberSound('click');
        break;
      case 'HIGH_RISK':
      case 'PHISHING':
      case 'SCAM':
        elRobotWrapper.classList.add('high-risk');
        playCyberSound('alert');
        break;
      case 'ALERT':
        elRobotWrapper.classList.add('alert');
        playCyberSound('alert');
        break;
      default:
        // IDLE active
        break;
    }
  }

  // ==========================================================================
  // ACTIVATE / DEACTIVATE AI
  // ==========================================================================

  function toggleAiActivation() {
    state.aiActive = !state.aiActive;

    if (state.aiActive) {
      elActivateBtn.classList.add('ai-active');
      elActivateBtn.querySelector('.btn-label').textContent = 'AI ACTIVE';
      playCyberSound('boot');

      setShieldBotMood('IDLE');
      moveShieldBot('scanner');

      speak('ShieldBot online. Security neural net engaged.', 'SYSTEM READY', 20, 3500);

      setTimeout(() => {
        if (state.aiActive) {
          speak('Ready to inspect messages, URLs, or scam ads. Feed me raw text!', 'SHIELDBOT', 25, 4500);
        }
      }, 3600);
    } else {
      elActivateBtn.classList.remove('ai-active');
      elActivateBtn.querySelector('.btn-label').textContent = 'ACTIVATE AI';
      setShieldBotMood('inactive');
      elSpeechBubble.classList.remove('visible');
      closeShieldBotDialog();
      moveShieldBot('home');
    }
  }

  // ==========================================================================
  // COMPANION ASSISTANT HUD DIALOG
  // ==========================================================================

  function toggleShieldBotDialog() {
    if (elDialogPanel.classList.contains('open')) {
      closeShieldBotDialog();
    } else {
      openShieldBotDialog();
    }
  }

  function openShieldBotDialog() {
    // If AI is inactive, automatically wake up!
    if (!state.aiActive) {
      toggleAiActivation();
    }

    elDialogPanel.classList.add('open');

    // Position panel near ShieldBot inside viewport
    const robotRect = elRobotWrapper.getBoundingClientRect();
    const panelWidth = 360;
    let panelX = robotRect.left - panelWidth - 15;
    let panelY = robotRect.top - 20;

    if (panelX < 15) {
      panelX = robotRect.right + 15;
    }
    if (panelX + panelWidth > window.innerWidth) {
      panelX = window.innerWidth - panelWidth - 20;
    }
    if (panelY + 400 > window.innerHeight) {
      panelY = window.innerHeight - 420;
    }
    panelY = Math.max(70, panelY);

    elDialogPanel.style.left = `${panelX}px`;
    elDialogPanel.style.top = `${panelY}px`;

    playCyberSound('click');
  }

  function closeShieldBotDialog() {
    elDialogPanel.classList.remove('open');
  }

  function addDialogMessage(sender, text) {
    const msg = document.createElement('div');
    msg.className = `dialog-msg ${sender}`;
    msg.textContent = text;
    elDialogChat.appendChild(msg);
    elDialogChat.scrollTop = elDialogChat.scrollHeight;
  }

  async function handleUserQuestion(question) {
    if (!question.trim()) return;
    addDialogMessage('user', question);
    elDialogInput.value = '';

    setShieldBotMood('SCANNING');
    speak('Analyzing inquiry...', 'PROCESSING', 20, 2000);

    // Call server AI endpoint or local fallback
    try {
      const res = await fetch('/api/ai/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question: question,
          context: state.lastScanResult ? {
            classification: state.lastScanResult.classification,
            risk_score: state.lastScanResult.risk_score,
            evidence: state.lastScanResult.evidence,
            content: state.lastScanResult.content || ''
          } : undefined
        })
      });

      if (res.ok) {
        const data = await res.json();
        addDialogMessage('bot', data.answer);
        speak(data.answer.slice(0, 100) + '...', 'SHIELDBOT', 20, 5000);
      } else {
        throw new Error('Fallback required');
      }
    } catch {
      // Local witty SOC knowledge responses
      const qLower = question.toLowerCase();
      let reply = '';
      if (qLower.includes('risk') || qLower.includes('score')) {
        reply = state.lastScanResult
          ? `Current risk is evaluated at ${state.lastScanResult.risk_score}/100 based on lexical anomalies and threat signatures.`
          : 'No scan performed yet. Paste a suspicious message above so I can compute its risk score!';
      } else if (qLower.includes('evidence') || qLower.includes('why')) {
        reply = state.lastScanResult && state.lastScanResult.evidence.length > 0
          ? `Top signals: ${state.lastScanResult.evidence.join('; ')}.`
          : 'I look for phishing domains, high-pressure urgency words, suspicious TLDs (.xyz, .top), and financial lure baits.';
      } else if (qLower.includes('click') || qLower.includes('what should i do')) {
        reply = 'Rule #1: Never click embedded links! Independently visit the official verified website in a fresh browser tab.';
      } else {
        reply = 'I am ShieldBot, your cybersecurity companion. I analyze social engineering tricks, credential harvesting traps, and scam payloads.';
      }
      addDialogMessage('bot', reply);
      speak(reply.slice(0, 110) + '...', 'SHIELDBOT', 20, 5000);
    } finally {
      setShieldBotMood(state.lastScanResult ? (state.lastScanResult.risk_score >= 60 ? 'HIGH_RISK' : 'SAFE') : 'IDLE');
    }
  }

  // ==========================================================================
  // SCAN WORKFLOW & FALLBACK ENGINE
  // ==========================================================================

  async function executeScan(content) {
    if (!content.trim()) return;

    // Wake robot up if sleeping
    if (!state.aiActive) {
      toggleAiActivation();
    }

    setShieldBotMood('SCANNING');
    moveShieldBot('scanner');

    // UI state
    elScanSubmitBtn.disabled = true;
    elScanSubmitBtn.textContent = 'SCANNING PAYLOAD...';
    elRadarBox.style.display = 'flex';
    elVerdictSection.style.display = 'none';

    speak('Scanning incoming payload... checking patterns and feeds.', 'ANALYZING', 20, 3000);

    let scanResult = null;

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: content })
      });

      if (res.ok) {
        scanResult = await res.json();
      } else {
        throw new Error('API server returned error, engaging local SOC engine');
      }
    } catch {
      // Local robust heuristic fallback
      scanResult = localScanFallback(content);
    }

    // Artificial tiny delay for smooth realistic telemetry
    await new Promise(r => setTimeout(r, 650));

    state.lastScanResult = scanResult;
    displayVerdict(scanResult);

    // Re-enable UI
    elScanSubmitBtn.disabled = false;
    elScanSubmitBtn.textContent = 'RUN SECURITY SCAN';
    elRadarBox.style.display = 'none';
    elVerdictSection.style.display = 'block';

    // Move ShieldBot to Result and speak verdict
    moveShieldBot('result');

    const score = scanResult.risk_score;
    const classification = scanResult.classification;

    if (score >= 75) {
      setShieldBotMood('HIGH_RISK');
      if (classification === 'PHISHING') {
        speak('Whoa! This link is trying way too hard to look authentic. Definitely a phishing trap!', 'THREAT DETECTED', 22, 6500);
      } else if (classification === 'SCAM') {
        speak('Classic deception trick! Someone is promising impossible windfalls to lure you in.', 'SCAM TRAPPED', 22, 6500);
      } else {
        speak('Critical risk detected! High confidence malicious patterns found.', 'CRITICAL WARNING', 22, 6500);
      }
    } else if (score >= 40) {
      setShieldBotMood('SUSPICIOUS');
      speak('Okay... this message has some suspicious urgency cues. Proceed with caution.', 'SUSPICIOUS', 24, 6000);
    } else {
      setShieldBotMood('SAFE');
      speak('Looks squeaky clean! No deceptive lures or blacklisted links detected.', 'ALL CLEAR', 24, 5500);
    }

    // Add to audit table
    addAuditEntry(scanResult);
  }

  // Local fallback heuristic scanner
  function localScanFallback(raw) {
    const text = raw.toLowerCase();
    const evidence = [];
    let score = 5;
    let classification = 'SAFE';

    // Patterns
    if (/(congratulations|won|winner|lottery|prize|reward|claim|crore|lakh|\$500,000)/i.test(text)) {
      score += 45;
      evidence.push('Unrealistic lottery / prize windfall bait');
    }
    if (/(kyc|account is blocked|suspended|deactivated|pan card|electricity power off)/i.test(text)) {
      score += 40;
      evidence.push('Coercive account deactivation or banking KYC demand');
    }
    if (/(immediate|immediately|within 24 hours|urgent|today only|expires soon|act now)/i.test(text)) {
      score += 20;
      evidence.push('High-pressure temporal urgency indicators');
    }
    if (/(otp|password|credentials|cvv|verify immediately|login)/i.test(text)) {
      score += 25;
      evidence.push('Sensitive credential or reverse OTP prompt');
    }
    if (/(\.xyz|\.top|\.buzz|\.tk|192\.168\.|http:\/\/)/i.test(text)) {
      score += 35;
      evidence.push('Suspicious unverified domain or insecure plain HTTP protocol');
    }
    if (/(guaranteed return|1000%|500% profit|double your money|automated trading)/i.test(text)) {
      score += 45;
      evidence.push('Impossible guaranteed investment return scheme');
    }

    score = Math.min(98, Math.max(4, score));

    if (score >= 75) {
      classification = text.includes('won') || text.includes('prize') ? 'SCAM' : 'PHISHING';
    } else if (score >= 40) {
      classification = 'SUSPICIOUS';
    } else {
      classification = 'SAFE';
      evidence.push('Content conforms to standard benign communication norms');
    }

    const confidence = Math.min(98, Math.max(85, Math.round(75 + score * 0.22)));

    return {
      classification,
      risk_score: score,
      confidence,
      threat_type: classification,
      evidence,
      explanation: evidence[0] || 'Clean baseline content.',
      recommended_action: score >= 60
        ? 'DO NOT CLICK LINKS OR SHARE OTPS. Block sender immediately.'
        : 'Communication appears legitimate. Maintain routine awareness.'
    };
  }

  function displayVerdict(res) {
    const badge = document.getElementById('verdict-badge');
    const scoreVal = document.getElementById('verdict-score');
    const confVal = document.getElementById('verdict-confidence');
    const whyList = document.getElementById('verdict-evidence-list');
    const actionText = document.getElementById('verdict-action-text');
    const actionBox = document.getElementById('verdict-recommendation-box');

    if (!badge) return;

    badge.className = 'verdict-title-badge ' + (res.risk_score >= 70 ? 'high-risk' : (res.risk_score >= 40 ? 'suspicious' : 'safe'));
    badge.textContent = `${res.classification} DETECTED`;

    scoreVal.textContent = res.risk_score;
    confVal.textContent = `${res.confidence}%`;

    whyList.innerHTML = '';
    (res.evidence || []).forEach(ev => {
      const item = document.createElement('div');
      item.className = 'evidence-pill-item';
      item.innerHTML = `<span class="bullet-icon">▸</span><span>${ev}</span>`;
      whyList.appendChild(item);
    });

    actionText.textContent = res.recommended_action || 'Maintain security vigilance.';
    actionBox.className = 'recommendation-banner ' + (res.risk_score >= 70 ? 'high-risk' : (res.risk_score >= 40 ? '' : 'safe'));
  }

  function addAuditEntry(res) {
    if (!elHistoryTbody) return;
    const row = document.createElement('tr');
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    let colorClass = 'primary';
    if (res.risk_score >= 70) colorClass = 'danger';
    else if (res.risk_score >= 40) colorClass = 'warning';
    else colorClass = 'safe';

    row.innerHTML = `
      <td>${time}</td>
      <td style="color: var(--cyan-secondary); font-weight: bold;">${res.channel || 'INSPECT'}</td>
      <td class="${colorClass}">${res.classification}</td>
      <td class="${colorClass}" style="font-weight: 800;">${res.risk_score}/100</td>
      <td>${res.evidence && res.evidence[0] ? res.evidence[0] : 'Nominal inspection'}</td>
    `;

    elHistoryTbody.prepend(row);
  }

  // ==========================================================================
  // INITIALIZATION & EVENT LISTENERS
  // ==========================================================================

  function init() {
    elRobotWrapper = document.getElementById('shieldbot-wrapper');
    elSpeechBubble = document.getElementById('shieldbot-speech-bubble');
    elBubbleText = document.getElementById('bubble-text');
    elBubbleMood = document.getElementById('bubble-mood');
    elEyeLeft = document.getElementById('robot-eye-left');
    elEyeRight = document.getElementById('robot-eye-right');
    elScanBeam = document.getElementById('shieldbot-scanner-beam');
    elDialogPanel = document.getElementById('shieldbot-dialog');
    elDialogChat = document.getElementById('dialog-chat-container');
    elDialogInput = document.getElementById('dialog-chat-input');
    elActivateBtn = document.getElementById('activate-ai-btn');
    elScannerTextarea = document.getElementById('scanner-input');
    elScanSubmitBtn = document.getElementById('scan-submit-btn');
    elRadarBox = document.getElementById('radar-analysis-box');
    elVerdictSection = document.getElementById('verdict-section');
    elHistoryTbody = document.getElementById('history-tbody');

    if (!elRobotWrapper) return;

    initRobotPosition();
    setupDragging();

    // Activate AI button
    if (elActivateBtn) {
      elActivateBtn.addEventListener('click', toggleAiActivation);
    }

    // Scanner actions
    if (elScanSubmitBtn && elScannerTextarea) {
      elScanSubmitBtn.addEventListener('click', () => {
        executeScan(elScannerTextarea.value);
      });

      // Quick inspect typing detection
      let typingTimeout;
      elScannerTextarea.addEventListener('input', () => {
        clearTimeout(typingTimeout);
        typingTimeout = setTimeout(() => {
          if (elScannerTextarea.value.trim().length > 10 && state.aiActive) {
            moveShieldBot('scanner');
            speak('I see you pasted something. Hit "RUN SECURITY SCAN" so I can inspect it!', 'OBSERVING', 25, 3500);
          }
        }, 500);
      });
    }

    // Presets
    document.querySelectorAll('.preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const sampleText = btn.getAttribute('data-sample');
        if (sampleText && elScannerTextarea) {
          elScannerTextarea.value = sampleText;
          executeScan(sampleText);
        }
      });
    });

    // Clear input
    const clearBtn = document.getElementById('clear-input-btn');
    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        if (elScannerTextarea) elScannerTextarea.value = '';
        if (elVerdictSection) elVerdictSection.style.display = 'none';
        setShieldBotMood('IDLE');
        moveShieldBot('home');
      });
    }

    // Dialog buttons & quick prompts
    const closeDialogBtn = document.getElementById('dialog-close-btn');
    if (closeDialogBtn) {
      closeDialogBtn.addEventListener('click', closeShieldBotDialog);
    }

    const sendDialogBtn = document.getElementById('dialog-send-btn');
    if (sendDialogBtn && elDialogInput) {
      sendDialogBtn.addEventListener('click', () => {
        handleUserQuestion(elDialogInput.value);
      });
      elDialogInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          handleUserQuestion(elDialogInput.value);
        }
      });
    }

    document.querySelectorAll('.dialog-quick-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const prompt = btn.getAttribute('data-prompt');
        if (prompt) handleUserQuestion(prompt);
      });
    });

    // Sound toggle
    const audioToggleBtn = document.getElementById('audio-toggle-btn');
    if (audioToggleBtn) {
      audioToggleBtn.addEventListener('click', () => {
        state.soundEnabled = !state.soundEnabled;
        audioToggleBtn.classList.toggle('active', state.soundEnabled);
        audioToggleBtn.querySelector('span').textContent = state.soundEnabled ? 'AUDIO: ON' : 'AUDIO: MUTED';
      });
    }

    // Keyboard support
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeShieldBotDialog();
      }
    });

    // Handle resize
    window.addEventListener('resize', () => {
      setRobotCoordinates(state.robotPos.x, state.robotPos.y);
    });

    // Welcome notice
    setTimeout(() => {
      speak('Welcome to AI-SPAMSHIELD. Click [ ACTIVATE AI ] to wake me up!', 'SECURITY ASSISTANT', 25, 4500);
    }, 1200);
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
