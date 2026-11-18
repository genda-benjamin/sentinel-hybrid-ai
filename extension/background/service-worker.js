/**
 * Sentinel-AI Extension: Service Worker (Manifest V3)
 * (Google #BuildHybridAI 2026 Hackathon)
 *
 * Ephemeral background event hub:
 * - Manages action badge state (findings count / green shield).
 * - Coordinates message passing between content scripts and popup.
 * - Enforces zero-leakage offline airgap invariants.
 */

chrome.runtime.onInstalled.addListener(async () => {
  console.log('[Sentinel-AI] Extension installed and initialized.');
  await chrome.action.setBadgeText({ text: 'ON' });
  await chrome.action.setBadgeBackgroundColor({ color: '#10b981' });
});

// Tab update listener to manage badges when navigating between PRs
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete' || !tab.url) return;

  const isPR = tab.url.includes('/pull/') || tab.url.includes('/merge_requests/');
  if (!isPR) {
    await chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }

  // Retrieve any stored result for this tab
  const storageKey = `pr_audit_${tabId}`;
  const data = await chrome.storage.local.get(storageKey);
  const audit = data[storageKey];

  if (audit) {
    const count = audit.findingsCount || 0;
    const badgeText = count > 0 ? String(count) : '✓';
    const badgeColor = count > 0 ? '#ef4444' : '#10b981';
    await chrome.action.setBadgeText({ tabId, text: badgeText });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
  } else {
    await chrome.action.setBadgeText({ tabId, text: 'SCAN' });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: '#3b82f6' });
  }
});

// Runtime message listener for content script telemetry and popup queries
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      const tabId = sender.tab ? sender.tab.id : (await getActiveTabId());

      if (message.type === 'AUDIT_COMPLETED') {
        const audit = message.payload;
        if (tabId) {
          const storageKey = `pr_audit_${tabId}`;
          await chrome.storage.local.set({ [storageKey]: audit });

          const count = audit.findingsCount || 0;
          const badgeText = count > 0 ? String(count) : '✓';
          const badgeColor = count > 0 ? '#ef4444' : '#10b981';
          await chrome.action.setBadgeText({ tabId, text: badgeText });
          await chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
        }
        sendResponse({ success: true });
      } else if (message.type === 'GET_PR_STATUS') {
        if (!tabId) {
          sendResponse({ audit: null, error: 'No active tab' });
          return;
        }
        const storageKey = `pr_audit_${tabId}`;
        const data = await chrome.storage.local.get(storageKey);
        sendResponse({ audit: data[storageKey] || null });
      } else if (message.type === 'CLEAR_AUDIT') {
        if (tabId) {
          const storageKey = `pr_audit_${tabId}`;
          await chrome.storage.local.remove(storageKey);
          await chrome.action.setBadgeText({ tabId, text: '' });
        }
        sendResponse({ success: true });
      }
    } catch (err) {
      console.error('[Sentinel-AI SW] Error handling message:', err);
      sendResponse({ error: err.message });
    }
  })();

  return true; // Keep message channel open for async response
});

async function getActiveTabId() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0]?.id;
}
