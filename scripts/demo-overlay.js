/**
 * Sentinel-AI Video Generator: Interactive Visual Overlay
 * (Google #BuildHybridAI 2026 Hackathon)
 * Injects Bezier visual cursor, click ripples, component spotlights, and English subtitles.
 */

(function () {
  if (window.__demo) return;

  const style = document.createElement('style');
  style.id = 'sentinel-demo-styles';
  style.textContent = `
    html, body {
      zoom: 1.15;
    }

    /* Crisp High-DPI Code Font Enhancements for 1080p Video Clarity */
    #codeInput, #diffView pre, #testCodeView pre, .gh-diff-table {
      font-size: 0.96rem !important;
      line-height: 1.6 !important;
      font-weight: 500 !important;
    }

    #demo-cursor {
      position: fixed;
      top: 0;
      left: 0;
      width: 32px;
      height: 32px;
      z-index: 2147483647;
      pointer-events: none;
      transform: translate(-4px, -4px);
      transition: transform 0.05s linear;
      filter: drop-shadow(0 0 12px rgba(56, 189, 248, 0.85));
    }

    #demo-cursor .cursor-body {
      width: 100%;
      height: 100%;
      position: relative;
    }

    #demo-cursor svg {
      width: 28px;
      height: 28px;
      fill: #38bdf8;
      stroke: #0f172a;
      stroke-width: 1.5;
    }

    #demo-cursor .cursor-pulse {
      position: absolute;
      top: 0;
      left: 0;
      width: 12px;
      height: 12px;
      border-radius: 50%;
      background: rgba(34, 197, 94, 0.7);
      box-shadow: 0 0 16px #22c55e;
      animation: demoPulse 1.2s infinite ease-in-out;
      transform: translate(-3px, -3px);
    }

    @keyframes demoPulse {
      0% { transform: translate(-3px, -3px) scale(0.8); opacity: 0.9; }
      50% { transform: translate(-3px, -3px) scale(1.6); opacity: 0.3; }
      100% { transform: translate(-3px, -3px) scale(0.8); opacity: 0.9; }
    }

    .demo-ripple {
      position: fixed;
      width: 20px;
      height: 20px;
      border-radius: 50%;
      border: 3px solid #38bdf8;
      background: rgba(56, 189, 248, 0.25);
      z-index: 2147483646;
      pointer-events: none;
      transform: translate(-50%, -50%) scale(1);
      animation: demoRippleEffect 0.6s cubic-bezier(0.1, 0.8, 0.3, 1) forwards;
    }

    @keyframes demoRippleEffect {
      0% { transform: translate(-50%, -50%) scale(0.8); opacity: 1; }
      100% { transform: translate(-50%, -50%) scale(3.5); opacity: 0; }
    }

    #demo-spotlight {
      position: fixed;
      border: 2px solid #38bdf8;
      box-shadow: 0 0 25px rgba(56, 189, 248, 0.65), inset 0 0 15px rgba(56, 189, 248, 0.25);
      border-radius: 8px;
      pointer-events: none;
      z-index: 2147483640;
      transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
      opacity: 0;
    }

    #demo-spotlight.active {
      opacity: 1;
    }

    #demo-spotlight-label {
      position: absolute;
      top: -28px;
      left: 0;
      background: linear-gradient(135deg, #0284c7, #0369a1);
      color: #ffffff;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
      font-size: 0.72rem;
      font-weight: 700;
      padding: 3px 10px;
      border-radius: 4px;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
      white-space: nowrap;
    }

    #demo-scene-badge {
      position: fixed;
      top: 24px;
      left: 24px;
      background: rgba(15, 23, 42, 0.88);
      border: 1px solid rgba(56, 189, 248, 0.4);
      backdrop-filter: blur(12px);
      padding: 8px 18px;
      border-radius: 8px;
      z-index: 2147483645;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: center;
      gap: 12px;
    }

    #demo-scene-badge .scene-number {
      background: linear-gradient(135deg, #38bdf8, #22c55e);
      color: #0b0f19;
      font-weight: 800;
      font-size: 0.75rem;
      padding: 3px 8px;
      border-radius: 4px;
      letter-spacing: 0.05em;
    }

    #demo-scene-badge .scene-title {
      color: #f1f5f9;
      font-weight: 600;
      font-size: 0.9rem;
      letter-spacing: 0.02em;
    }

    #demo-subtitle-container {
      position: fixed;
      bottom: 64px;
      left: 50%;
      transform: translateX(-50%);
      width: 88%;
      max-width: 1240px;
      background: rgba(8, 14, 28, 0.95);
      border: 1px solid rgba(56, 189, 248, 0.45);
      box-shadow: 0 16px 48px rgba(0, 0, 0, 0.9), 0 0 25px rgba(56, 189, 248, 0.25);
      backdrop-filter: blur(16px);
      border-radius: 12px;
      padding: 14px 28px;
      z-index: 2147483645;
      text-align: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      transition: all 0.3s ease;
    }

    #demo-subtitle-container .subtitle-topic {
      color: #38bdf8;
      font-size: 0.8rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      margin-bottom: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }

    #demo-subtitle-container .subtitle-text {
      color: #ffffff;
      font-size: 1.15rem;
      font-weight: 500;
      line-height: 1.45;
      letter-spacing: 0.01em;
      text-shadow: 0 2px 4px rgba(0, 0, 0, 0.5);
    }

    #demo-subtitle-container .subtitle-highlight {
      color: #22c55e;
      font-weight: 700;
    }
  `;
  document.head.appendChild(style);

  // 1. Create Cursor
  const cursor = document.createElement('div');
  cursor.id = 'demo-cursor';
  cursor.innerHTML = `
    <div class="cursor-body">
      <div class="cursor-pulse"></div>
      <svg viewBox="0 0 24 24">
        <path d="M4 2 L20 10 L12 12 L10 20 Z" />
      </svg>
    </div>
  `;
  document.body.appendChild(cursor);

  // 2. Create Spotlight
  const spotlight = document.createElement('div');
  spotlight.id = 'demo-spotlight';
  spotlight.innerHTML = `<div id="demo-spotlight-label"></div>`;
  document.body.appendChild(spotlight);
  const spotlightLabel = document.getElementById('demo-spotlight-label');

  // 3. Create Scene Badge
  const sceneBadge = document.createElement('div');
  sceneBadge.id = 'demo-scene-badge';
  sceneBadge.innerHTML = `
    <span class="scene-number" id="demoSceneNumber">SCENE 1</span>
    <span class="scene-title" id="demoSceneTitle">Problem & Architecture Overview</span>
  `;
  document.body.appendChild(sceneBadge);

  // 4. Create Subtitle Container
  const subtitleContainer = document.createElement('div');
  subtitleContainer.id = 'demo-subtitle-container';
  subtitleContainer.innerHTML = `
    <div class="subtitle-topic" id="demoSubtitleTopic">🛡️ ARCHITECTURE OVERVIEW</div>
    <div class="subtitle-text" id="demoSubtitleText">Sentinel-AI: Offline-First Autonomous Hybrid AI Security Auditor</div>
  `;
  document.body.appendChild(subtitleContainer);

  let curX = 960;
  let curY = 540;

  function setCursorPos(x, y) {
    curX = x;
    curY = y;
    cursor.style.left = `${x}px`;
    cursor.style.top = `${y}px`;
  }

  setCursorPos(960, 540);

  window.__demo = {
    setPos(x, y) {
      setCursorPos(x, y);
    },

    async move(targetX, targetY, durationMs = 600) {
      return new Promise((resolve) => {
        const startX = curX;
        const startY = curY;
        const startTime = performance.now();

        function step(now) {
          const elapsed = now - startTime;
          const t = Math.min(1, elapsed / durationMs);
          // Cubic ease-in-out
          const ease = t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
          const x = startX + (targetX - startX) * ease;
          const y = startY + (targetY - startY) * ease;
          setCursorPos(x, y);

          if (t < 1) {
            requestAnimationFrame(step);
          } else {
            setCursorPos(targetX, targetY);
            resolve();
          }
        }

        requestAnimationFrame(step);
      });
    },

    async moveTo(selector, durationMs = 600, offsetX = 0.5, offsetY = 0.5) {
      const el = typeof selector === 'string' ? document.querySelector(selector) : selector;
      if (!el) {
        console.warn('Cannot find element for cursor move:', selector);
        return;
      }
      const rect = el.getBoundingClientRect();
      const targetX = rect.left + rect.width * offsetX;
      const targetY = rect.top + rect.height * offsetY;
      await this.move(targetX, targetY, durationMs);
    },

    click(x = curX, y = curY) {
      const ripple = document.createElement('div');
      ripple.className = 'demo-ripple';
      ripple.style.left = `${x}px`;
      ripple.style.top = `${y}px`;
      document.body.appendChild(ripple);
      setTimeout(() => ripple.remove(), 600);
    },

    async clickElement(selector, durationMs = 500) {
      const el = typeof selector === 'string' ? document.querySelector(selector) : selector;
      if (!el) return;
      await this.moveTo(el, durationMs);
      this.click(curX, curY);
      el.click();
    },

    spotlight(selector, label = '', padding = 8) {
      const el = typeof selector === 'string' ? document.querySelector(selector) : selector;
      if (!el) {
        this.clearSpotlight();
        return;
      }
      const rect = el.getBoundingClientRect();
      spotlight.style.left = `${rect.left - padding}px`;
      spotlight.style.top = `${rect.top - padding}px`;
      spotlight.style.width = `${rect.width + padding * 2}px`;
      spotlight.style.height = `${rect.height + padding * 2}px`;
      if (label) {
        spotlightLabel.innerText = label;
        spotlightLabel.style.display = 'block';
      } else {
        spotlightLabel.style.display = 'none';
      }
      spotlight.classList.add('active');
    },

    clearSpotlight() {
      spotlight.classList.remove('active');
    },

    setScene(numberText, titleText) {
      document.getElementById('demoSceneNumber').innerText = numberText;
      document.getElementById('demoSceneTitle').innerText = titleText;
    },

    setSubtitle(topicText, mainHtml) {
      document.getElementById('demoSubtitleTopic').innerHTML = topicText;
      document.getElementById('demoSubtitleText').innerHTML = mainHtml;
    },

    sleep(ms) {
      return new Promise((r) => setTimeout(r, ms));
    }
  };

  console.log('⚡ [Sentinel-AI] Demo visual overlay initialized.');
})();
