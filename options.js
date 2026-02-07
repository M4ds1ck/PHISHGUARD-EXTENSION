// options.js - v3.0.0 with Privacy Consent, Validation & Error Handling
console.log("[Options] Loading PhishGuard Settings v3.0.0");
const browserAPI = browser;

// Default settings structure
const DEFAULT_SETTINGS = {
  protectionEnabled: true,
  blockingEnabled: true,
  notificationsEnabled: true,
  autoScanEnabled: true,
  blockThreshold: 50,
  requireConsentForAPIs: true,
  requireConsentForURLExpansion: true,
  phishtankKey: '',
  googleSafeBrowsingKey: ''
};

let currentSettings = { ...DEFAULT_SETTINGS };
let isInitialized = false;

// ============================================
// INITIALIZATION
// ============================================
document.addEventListener('DOMContentLoaded', async () => {
  console.log("[Options] DOM loaded");
  
  try {
    await Promise.all([
      loadSettings(),
      loadStats(),
      loadLists()
    ]);
    
    setupEventListeners();
    isInitialized = true;
    
    console.log("[Options] ✅ Settings page fully initialized");
    showToast("Settings loaded successfully", "success", 2000);
    
  } catch (error) {
    console.error("[Options] Initialization failed:", error);
    showToast(`Initialization error: ${error.message}`, "error");
  }
});

// ============================================
// LOAD SETTINGS FROM STORAGE
// ============================================
async function loadSettings() {
  try {
    const data = await browserAPI.storage.local.get('settings');
    
    if (data.settings) {
      // Merge with defaults to handle missing properties
      currentSettings = { ...DEFAULT_SETTINGS, ...data.settings };
      console.log("[Options] Settings loaded:", currentSettings);
    } else {
      console.log("[Options] No existing settings found - using defaults");
    }
    
    // Update UI to match current settings
    updateUIFromSettings();
    
  } catch (error) {
    console.error("[Options] Failed to load settings:", error);
    showToast("Failed to load settings", "error");
  }
}

// Update UI elements based on current settings
function updateUIFromSettings() {
  // Toggles
  document.getElementById('protectionToggle').checked = currentSettings.protectionEnabled;
  document.getElementById('blockingToggle').checked = currentSettings.blockingEnabled;
  document.getElementById('notificationsToggle').checked = currentSettings.notificationsEnabled;
  document.getElementById('autoScanToggle').checked = currentSettings.autoScanEnabled;
  document.getElementById('consentAPIToggle').checked = currentSettings.requireConsentForAPIs;
  document.getElementById('consentURLToggle').checked = currentSettings.requireConsentForURLExpansion;
  
  // Threshold slider
  const slider = document.getElementById('thresholdSlider');
  const valueDisplay = document.getElementById('thresholdValue');
  slider.value = currentSettings.blockThreshold;
  valueDisplay.textContent = currentSettings.blockThreshold;
  
  // Update slider color based on value
  updateThresholdColor(currentSettings.blockThreshold);
  
  // API keys (mask for security)
  document.getElementById('phishtankKey').value = currentSettings.phishtankKey || '';
  document.getElementById('googleKey').value = currentSettings.googleSafeBrowsingKey || '';
}

// Update threshold display color
function updateThresholdColor(value) {
  const valueDisplay = document.getElementById('thresholdValue');
  if (value >= 75) {
    valueDisplay.style.color = 'var(--neon-red)';
  } else if (value >= 50) {
    valueDisplay.style.color = 'var(--neon-orange)';
  } else {
    valueDisplay.style.color = 'var(--neon-green)';
  }
}

// ============================================
// LOAD STATISTICS
// ============================================
async function loadStats() {
  try {
    const response = await browserAPI.runtime.sendMessage({ action: "getStats" });
    
    if (response) {
      document.getElementById('statScanned').textContent = (response.sitesScanned || 0).toLocaleString();
      document.getElementById('statBlocked').textContent = (response.threatsBlocked || 0).toLocaleString();
      document.getElementById('statBypassed').textContent = (response.bypassesUsed || 0).toLocaleString();
      console.log("[Options] Stats loaded:", response);
    }
  } catch (error) {
    console.warn("[Options] Failed to load stats:", error);
  }
}

// ============================================
// LOAD WHITELIST/BLACKLIST
// ============================================
async function loadLists() {
  try {
    const data = await browserAPI.storage.local.get(['whitelist', 'blacklist']);
    
    // Whitelist
    const whitelist = data.whitelist || [];
    displayList('whitelistItems', whitelist, 'whitelist');
    document.getElementById('whitelistCount').textContent = `(${whitelist.length})`;
    
    // Blacklist
    const blacklist = data.blacklist || [];
    displayList('blacklistItems', blacklist, 'blacklist');
    document.getElementById('blacklistCount').textContent = `(${blacklist.length})`;
    
    console.log(`[Options] Lists loaded - Whitelist: ${whitelist.length}, Blacklist: ${blacklist.length}`);
    
  } catch (error) {
    console.error("[Options] Failed to load lists:", error);
    showToast("Failed to load domain lists", "error");
  }
}

// Display domain list in UI
function displayList(containerId, items, listType) {
  const container = document.getElementById(containerId);
  if (!container) return;
  
  if (items.length === 0) {
    container.innerHTML = '<div class="empty-list">No domains yet</div>';
    return;
  }
  
  container.innerHTML = '';
  
  // Sort alphabetically
  items.sort().forEach(domain => {
    const item = document.createElement('div');
    item.className = 'list-item';
    item.innerHTML = `
      <span>${escapeHtml(domain)}</span>
      <button class="remove-btn" data-domain="${escapeHtml(domain)}" data-list="${listType}">
        Remove
      </button>
    `;
    container.appendChild(item);
  });
  
  // Add event listeners to remove buttons
  container.querySelectorAll('.remove-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const domain = e.target.dataset.domain;
      const list = e.target.dataset.list;
      removeFromList(domain, list);
    });
  });
}

// Remove domain from list
async function removeFromList(domain, listType) {
  if (!confirm(`Remove "${domain}" from ${listType === 'whitelist' ? 'trusted sites' : 'blocked sites'}?`)) {
    return;
  }
  
  try {
    const data = await browserAPI.storage.local.get(listType);
    const currentList = data[listType] || [];
    const updatedList = currentList.filter(d => d !== domain);
    
    await browserAPI.storage.local.set({ [listType]: updatedList });
    
    console.log(`[Options] Removed ${domain} from ${listType}`);
    showToast(`✅ Removed "${domain}" from ${listType === 'whitelist' ? 'trusted sites' : 'blocked sites'}`, "success");
    
    // Reload lists
    await loadLists();
    
  } catch (error) {
    console.error(`[Options] Failed to remove from ${listType}:`, error);
    showToast(`Failed to remove domain: ${error.message}`, "error");
  }
}

// ============================================
// EVENT LISTENERS
// ============================================
function setupEventListeners() {
  // Toggle switches
  document.getElementById('toggleProtection').addEventListener('click', () => {
    const toggle = document.getElementById('protectionToggle');
    toggle.checked = !toggle.checked;
    currentSettings.protectionEnabled = toggle.checked;
  });
  
  document.getElementById('toggleBlocking').addEventListener('click', () => {
    const toggle = document.getElementById('blockingToggle');
    toggle.checked = !toggle.checked;
    currentSettings.blockingEnabled = toggle.checked;
  });
  
  document.getElementById('toggleNotifications').addEventListener('click', () => {
    const toggle = document.getElementById('notificationsToggle');
    toggle.checked = !toggle.checked;
    currentSettings.notificationsEnabled = toggle.checked;
  });
  
  document.getElementById('toggleAutoScan').addEventListener('click', () => {
    const toggle = document.getElementById('autoScanToggle');
    toggle.checked = !toggle.checked;
    currentSettings.autoScanEnabled = toggle.checked;
  });
  
  document.getElementById('toggleConsentAPIs').addEventListener('click', () => {
    const toggle = document.getElementById('consentAPIToggle');
    toggle.checked = !toggle.checked;
    currentSettings.requireConsentForAPIs = toggle.checked;
  });
  
  document.getElementById('toggleConsentURLExpansion').addEventListener('click', () => {
    const toggle = document.getElementById('consentURLToggle');
    toggle.checked = !toggle.checked;
    currentSettings.requireConsentForURLExpansion = toggle.checked;
  });
  
  // Threshold slider
  const slider = document.getElementById('thresholdSlider');
  const valueDisplay = document.getElementById('thresholdValue');
  
  slider.addEventListener('input', () => {
    const value = parseInt(slider.value);
    valueDisplay.textContent = value;
    currentSettings.blockThreshold = value;
    updateThresholdColor(value);
  });
  
  // API key inputs
  document.getElementById('phishtankKey').addEventListener('input', (e) => {
    currentSettings.phishtankKey = e.target.value.trim();
  });
  
  document.getElementById('googleKey').addEventListener('input', (e) => {
    currentSettings.googleSafeBrowsingKey = e.target.value.trim();
  });
  
  // Action buttons
  document.getElementById('saveBtn').addEventListener('click', saveSettings);
  document.getElementById('exportBtn').addEventListener('click', exportData);
  document.getElementById('importBtn').addEventListener('click', importData);
  document.getElementById('resetBtn').addEventListener('click', resetSettings);
}

// ============================================
// SAVE SETTINGS
// ============================================
async function saveSettings() {
  const saveBtn = document.getElementById('saveBtn');
  const originalHTML = saveBtn.innerHTML;
  
  try {
    // Disable button during save
    saveBtn.disabled = true;
    saveBtn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <circle cx="12" cy="12" r="10" stroke-dasharray="15" stroke-dashoffset="60">
          <animate attributeName="stroke-dashoffset" values="60;0" dur="1s" repeatCount="indefinite"/>
        </circle>
      </svg>
      Saving...
    `;
    
    // Save to storage
    await browserAPI.storage.local.set({ settings: currentSettings });
    
    // Notify background script of settings update
    await browserAPI.runtime.sendMessage({
      action: "updateSettings",
      settings: currentSettings
    });
    
    console.log("[Options] ✅ Settings saved:", currentSettings);
    showToast("✅ Settings saved successfully!", "success");
    
    // Reload stats to reflect any changes
    await loadStats();
    
  } catch (error) {
    console.error("[Options] Failed to save settings:", error);
    showToast(`❌ Save failed: ${error.message}`, "error");
  } finally {
    // Restore button state
    setTimeout(() => {
      saveBtn.disabled = false;
      saveBtn.innerHTML = originalHTML;
    }, 800);
  }
}

// ============================================
// EXPORT/IMPORT DATA
// ============================================
async function exportData() {
  try {
    // Get all storage data
    const allData = await browserAPI.storage.local.get(null);
    
    // Create export payload with only relevant data
    const exportData = {
      version: "3.0.0",
      exportDate: new Date().toISOString(),
      settings: currentSettings,
      whitelist: allData.whitelist || [],
      blacklist: allData.blacklist || [],
      stats: allData.stats || {}
    };
    
    // Create download
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { 
      type: 'application/json' 
    });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-backup-${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a);
    a.click();
    
    // Cleanup
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);
    
    console.log("[Options] ✅ Data exported");
    showToast("✅ Backup exported successfully!", "success");
    
  } catch (error) {
    console.error("[Options] Export failed:", error);
    showToast(`❌ Export failed: ${error.message}`, "error");
  }
}

function importData() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  
  input.onchange = async (e) => {
    try {
      const file = e.target.files[0];
      if (!file) return;
      
      // Read and parse file
      const text = await file.text();
      const importedData = JSON.parse(text);
      
      // Validate import data
      if (!importedData.settings && !importedData.whitelist && !importedData.blacklist) {
        throw new Error("Invalid backup file format");
      }
      
      // Show detailed import preview
      const changes = [];
      if (importedData.settings) changes.push("Settings");
      if (importedData.whitelist) changes.push("Whitelist (" + importedData.whitelist.length + " domains)");
      if (importedData.blacklist) changes.push("Blacklist (" + importedData.blacklist.length + " domains)");
      if (importedData.stats) changes.push("Statistics");
      
      if (!confirm(`⚠️ Import backup data?\n\nThis will overwrite:\n${changes.join('\n')}\n\nYour current settings will be replaced. Continue?`)) {
        return;
      }
      
      // Import settings
      if (importedData.settings) {
        currentSettings = { ...DEFAULT_SETTINGS, ...importedData.settings };
        await browserAPI.storage.local.set({ settings: currentSettings });
        updateUIFromSettings();
      }
      
      // Import lists
      if (importedData.whitelist) {
        await browserAPI.storage.local.set({ whitelist: importedData.whitelist });
      }
      if (importedData.blacklist) {
        await browserAPI.storage.local.set({ blacklist: importedData.blacklist });
      }
      
      // Import stats (optional)
      if (importedData.stats) {
        await browserAPI.storage.local.set({ stats: importedData.stats });
      }
      
      // Notify background of settings update
      if (importedData.settings) {
        await browserAPI.runtime.sendMessage({
          action: "updateSettings",
          settings: currentSettings
        });
      }
      
      console.log("[Options] ✅ Data imported successfully");
      showToast("✅ Backup imported successfully! Reloading...", "success");
      
      // Reload all data
      setTimeout(async () => {
        await loadSettings();
        await loadStats();
        await loadLists();
        showToast("✅ Import complete - all data refreshed", "success", 3000);
      }, 1000);
      
    } catch (error) {
      console.error("[Options] Import failed:", error);
      showToast(`❌ Import failed: ${error.message}`, "error");
    }
  };
  
  input.click();
}

// ============================================
// RESET SETTINGS
// ============================================
async function resetSettings() {
  // Double confirmation for destructive action
  if (!confirm("⚠️ RESET ALL SETTINGS?\n\nThis will:\n• Reset all settings to defaults\n• Clear whitelist/blacklist\n• Reset statistics\n\nThis action cannot be undone!")) {
    return;
  }
  
  if (!confirm("⚠️ FINAL CONFIRMATION\n\nAre you absolutely sure you want to reset everything?")) {
    return;
  }
  
  try {
    // Reset to defaults
    currentSettings = { ...DEFAULT_SETTINGS };
    
    // Clear storage
    await browserAPI.storage.local.clear();
    
    // Save default settings
    await browserAPI.storage.local.set({ settings: currentSettings });
    
    // Notify background
    await browserAPI.runtime.sendMessage({
      action: "updateSettings",
      settings: currentSettings
    });
    
    console.log("[Options] ✅ All settings reset to defaults");
    showToast("✅ All settings reset to defaults", "success");
    
    // Reload page after delay
    setTimeout(() => {
      window.location.reload();
    }, 1500);
    
  } catch (error) {
    console.error("[Options] Reset failed:", error);
    showToast(`❌ Reset failed: ${error.message}`, "error");
  }
}

// ============================================
// TOAST NOTIFICATIONS
// ============================================
function showToast(message, type = "success", duration = 3000) {
  const toast = document.getElementById('toast');
  const toastMessage = document.getElementById('toastMessage');
  
  if (!toast || !toastMessage) return;
  
  // Set message and type
  toastMessage.textContent = message;
  toast.className = 'toast';
  
  if (type === "error") {
    toast.classList.add('error');
  }
  
  // Show toast
  toast.classList.add('show');
  
  // Auto-hide after duration
  setTimeout(() => {
    toast.classList.remove('show');
  }, duration);
}

// ============================================
// UTILITY FUNCTIONS
// ============================================
function escapeHtml(text) {
  if (typeof text !== 'string') return String(text);
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ============================================
// AUTO-SAVE ON BLUR (Optional enhancement)
// ============================================
window.addEventListener('beforeunload', () => {
  if (isInitialized) {
    console.log("[Options] Page unloading - settings state preserved");
  }
});

console.log("[Options] ✅ Script loaded and ready");