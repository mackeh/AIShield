// Settings Panel for API Configuration

export function createSettingsPanel() {
  const panel = document.createElement('div');
  panel.id = 'settings-panel';
  panel.className = 'settings-panel hidden';
  
  panel.innerHTML = `
    <div class="settings-overlay" id="settings-overlay"></div>
    <div class="settings-content">
      <div class="settings-header">
        <h2>Analytics API Settings</h2>
        <button id="settings-close" class="close-btn">✕</button>
      </div>

      <div class="settings-body">
        <div class="setting-group">
          <label for="api-url">API URL</label>
          <input type="url" id="api-url" placeholder="http://localhost:8080" />
          <small>Analytics API endpoint</small>
        </div>

        <div class="setting-group">
          <label for="api-key">API Key</label>
          <input type="password" id="api-key" placeholder="Enter API key" />
          <small>Authentication key (stored locally)</small>
        </div>

        <div class="setting-group">
          <button id="test-connection" class="btn-secondary">Test Connection</button>
          <span id="connection-status"></span>
        </div>
      </div>

      <div class="settings-footer">
        <button id="settings-save" class="btn-primary">Save Settings</button>
        <button id="settings-cancel" class="btn-secondary">Cancel</button>
      </div>
    </div>
  `;

  document.body.appendChild(panel);

  // Event listeners
  document.getElementById('settings-close').onclick = () => hideSettings();
  document.getElementById('settings-overlay').onclick = () => hideSettings();
  document.getElementById('settings-cancel').onclick = () => hideSettings();
  
  document.getElementById('settings-save').onclick = () => {
    const url = document.getElementById('api-url').value;
    const key = document.getElementById('api-key').value;
    
    if (url) localStorage.setItem('AISHIELD_API_URL', url);
    if (key) localStorage.setItem('AISHIELD_API_KEY', key);
    
    showNotification('Settings saved successfully');
    hideSettings();
    window.location.reload(); // Reload to apply new settings
  };

  document.getElementById('test-connection').onclick = async () => {
    const url = document.getElementById('api-url').value;
    const statusEl = document.getElementById('connection-status');
    
    if (!url) {
      statusEl.textContent = '❌ Please enter API URL';
      statusEl.className = 'status-error';
      return;
    }

    statusEl.textContent = '⏳ Testing...';
    statusEl.className = 'status-pending';

    try {
      const response = await fetch(`${url}/api/health`);
      if (response.ok) {
        statusEl.textContent = '✅ Connection successful';
        statusEl.className = 'status-success';
      } else {
        statusEl.textContent = `❌ Failed (${response.status})`;
        statusEl.className = 'status-error';
      }
    } catch (error) {
      statusEl.textContent = `❌ Connection failed: ${error.message}`;
      statusEl.className = 'status-error';
    }
  };

  // Load existing settings
  const existingUrl = localStorage.getItem('AISHIELD_API_URL');
  const existingKey = localStorage.getItem('AISHIELD_API_KEY');
  
  if (existingUrl) document.getElementById('api-url').value = existingUrl;
  if (existingKey) document.getElementById('api-key').value = existingKey;
}

export function showSettings() {
  const panel = document.getElementById('settings-panel');
  if (panel) {
    panel.classList.remove('hidden');
  }
}

export function hideSettings() {
  const panel = document.getElementById('settings-panel');
  if (panel) {
    panel.classList.add('hidden');
  }
}

function showNotification(message) {
  const notification = document.createElement('div');
  notification.className = 'notification';
  notification.textContent = message;
  document.body.appendChild(notification);
  
  setTimeout(() => {
    notification.remove();
  }, 3000);
}
