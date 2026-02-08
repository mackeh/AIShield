// AIShield Analytics API Client
// Usage: Import this in your dashboard app.js

export class AnalyticsAPIClient {
  constructor(baseUrl, apiKey) {
    this.baseUrl = baseUrl || localStorage.getItem('AISHIELD_API_URL') || '';
    this.apiKey = apiKey || localStorage.getItem('AISHIELD_API_KEY') || '';
  }

  isConfigured() {
    return this.baseUrl && this.apiKey;
  }

  async request(endpoint, options = {}) {
    if (!this.isConfigured()) {
      throw new Error('API client not configured');
    }

    const url = `${this.baseUrl}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      'x-api-key': this.apiKey,
      ...options.headers,
    };

    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`API Error (${response.status}): ${error}`);
    }

    return response.json();
  }

  async fetchScans(filters = {}) {
    const params = new URLSearchParams();
    if (filters.org_id) params.append('org_id', filters.org_id);
    if (filters.team_id) params.append('team_id', filters.team_id);
    if (filters.repo_id) params.append('repo_id', filters.repo_id);
    if (filters.branch) params.append('branch', filters.branch);
    if (filters.limit) params.append('limit', filters.limit);
    if (filters.offset) params.append('offset', filters.offset);

    return this.request(`/api/v1/scans?${params}`);
  }

  async fetchSummary(filters = {}) {
    const params = new URLSearchParams();
    if (filters.org_id) params.append('org_id', filters.org_id);
    if (filters.team_id) params.append('team_id', filters.team_id);
    if (filters.repo_id) params.append('repo_id', filters.repo_id);
    if (filters.days) params.append('days', filters.days);
   
    return this.request(`/api/v1/analytics/summary?${params}`);
  }

  async checkHealth() {
    try {
      const response = await fetch(`${this.baseUrl}/api/health`);
      return response.ok;
    } catch {
      return false;
    }
  }

  static fromLocalStorage() {
    return new AnalyticsAPIClient();
  }

  saveToLocalStorage() {
    if (this.baseUrl) localStorage.setItem('AISHIELD_API_URL', this.baseUrl);
    if (this.apiKey) localStorage.setItem('AISHIELD_API_KEY', this.apiKey);
  }

  static clearLocalStorage() {
    localStorage.removeItem('AISHIELD_API_URL');
    localStorage.removeItem('AISHIELD_API_KEY');
  }

  /**
   * Fetch AI metrics (tool breakdown, patterns, confidence)
   */
  async fetchAIMetrics(filters = {}) {
    const params = new URLSearchParams();
    if (filters.org_id) params.append('org_id', filters.org_id);
    if (filters.team_id) params.append('team_id', filters.team_id);
    if (filters.days) params.append('days', filters.days);
    
    const url = `/api/v1/analytics/ai-metrics?${params}`;
    console.log(`[API Client] Fetching AI metrics: ${url}`);
    
    return this.request(url);
  }

  /**
   * Generate compliance report
   */
  async generateReport(params) {
    if (!this.isConfigured()) {
      throw new Error('API client not configured');
    }

    const query = new URLSearchParams(params);
    
    // We fetch as blob to handle file download
    const response = await fetch(`${this.baseUrl}/api/v1/reports/compliance?${query}`, {
      headers: {
        'x-api-key': this.apiKey,
      }
    });

    if (!response.ok) {
        const text = await response.text();
        throw new Error(`Report generation failed: ${text}`);
    }

    return response.blob();
  }
}
