import axios from 'axios';
import { useAppStore } from '../store/useAppStore';

export const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

export const apiClient = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor to attach JWT token
apiClient.interceptors.request.use((config) => {
  const token = useAppStore.getState().authToken;
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => Promise.reject(error));

// Interceptor to handle 401 Unauthorized
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      useAppStore.getState().clearAuth();
      if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/app/login')) {
        window.location.href = '/app';
      }
    }
    return Promise.reject(error);
  }
);

// --- API Functions ---
export const authAPI = {
  login: async (data: any) => {
    const res = await axios.post(`${API_BASE}/auth/login`, data);
    return res.data;
  },
  createAdmin: async (data: any) => {
    const res = await apiClient.post('/auth/create-admin', data);
    return res.data;
  }
};

export const modelAPI = {
  getModelInfo: async () => {
    // Route: GET /model_info (root)
    const res = await apiClient.get('/model_info');
    return res.data;
  },
  predict: async (features: Record<string, any>) => {
    // Route: POST /api/v1/predict/records
    const res = await apiClient.post('/api/v1/predict/records', { records: [features] });
    const pred = res.data?.predictions?.[0];
    if (!pred) throw new Error('No prediction returned');
    return {
      prediction: pred.predicted_label,
      probabilities: pred.all_probs || {},
      shap_values: pred.shap_values || {},
      risk_level: pred.recommendation_severity,
      features: features,
      timestamp: new Date().toISOString()
    };
  },
  predictBatch: async (formData: FormData) => {
    // Route: POST /api/v1/predict/csv — multipart with field "file"
    const res = await apiClient.post('/api/v1/predict/csv', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });

    const data = res.data;
    const mappedResults = data.predictions?.map((p: any) => ({
      prediction: p.predicted_label,
      probabilities: p.all_probs || {},
      shap_values: p.shap_values || {},
      risk_level: p.recommendation_severity,
      features: {},
      timestamp: new Date().toISOString()
    })) || [];

    return {
      total: data.summary?.prediction_count || 0,
      normal: data.summary?.labels?.Normal || 0,
      anomalies: (data.summary?.prediction_count || 0) - (data.summary?.labels?.Normal || 0),
      results: mappedResults,
      summary: data.summary || {}
    };
  },
  getStats: async () => {
    // Route: GET /api/v1/monitoring/stats
    const res = await apiClient.get('/api/v1/monitoring/stats');
    return res.data;
  },
  explainPrediction: async (data: any) => {
    const res = await apiClient.post('/api/v1/predict/records', { records: [data] });
    return res.data;
  }
};

export const scanAPI = {
  activeScan: async (target: string) => {
    const res = await apiClient.post('/api/v1/recon/scan', { target }, { timeout: 120000 });
    return res.data;
  },
  deepScan: async (target: string) => {
    const res = await apiClient.post('/api/v1/recon/deep-scan', { target }, { timeout: 120000 });
    return res.data;
  },
  analyzeScan: async (scanResult: any) => {
    const res = await apiClient.post('/api/v1/recon/analyze-scan', { scan_result: scanResult });
    return res.data;
  },
  exportReport: async (target: string, scanResult: any, analysis: any) => {
    const res = await apiClient.post('/api/v1/recon/export-report', { target, scan_result: scanResult, analysis });
    return res.data;
  }
};

export const captureAPI = {
  getStats: async () => {
    const res = await apiClient.get('/api/v1/capture/stats');
    return res.data;
  },
  start: async (interfaceName?: string) => {
    const res = await apiClient.post('/api/v1/capture/start', { interface: interfaceName || null });
    return res.data;
  },
  stop: async () => {
    const res = await apiClient.post('/api/v1/capture/stop');
    return res.data;
  },
};

export const alertsAPI = {
  getAlerts: async () => {
    // Route: GET /api/v1/alerts/
    const res = await apiClient.get('/api/v1/alerts/');
    return res.data;
  },
  acknowledgeAlert: async (id: string) => {
    const res = await apiClient.post(`/api/v1/alerts/${id}/acknowledge`);
    return res.data;
  },
  getAlertAnalysis: async (alertId: string) => {
    const res = await apiClient.get(`/api/v1/alerts/${alertId}/ai-analysis`);
    return res.data;
  }
};

export const logsAPI = {
  getLogs: async (limit: number = 100) => {
    const res = await apiClient.get(`/api/v1/monitoring/logs?limit=${limit}`);
    return res.data;
  },
};

export const chatAPI = {
  // Route: POST /chat (root level)
  chat: async (message: string, context: any, history: any[]) => {
    const res = await apiClient.post('/chat', { message, context, history });
    return res.data;
  }
};
