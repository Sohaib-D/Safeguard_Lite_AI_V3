// store/useAppStore.ts
import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { 
  ModelInfo, PredictionResult, BatchPredictionResult, 
  DeepScanResult, AnalysisResult, ActiveScanResult, 
  ScanHistoryEntry, LiveEvent, Alert 
} from '../types';

interface AppState {
  // Auth
  authToken: string | null;
  authUser: string | null;
  authRole: 'admin' | 'user' | null;
  authExpiry: number | null;
  
  // Model
  modelInfoCache: ModelInfo | null;
  
  // Predictions
  latestPredictionResult: PredictionResult | null;
  latestUploadResult: BatchPredictionResult | null;
  liveHistory: LiveEvent[];
  liveRecentEvents: LiveEvent[];
  liveAlerts: Alert[];
  
  // Deep Scanner
  deepScanResult: DeepScanResult | null;
  deepScanAnalysis: AnalysisResult | null;
  deepScanTarget: string;
  deepScanHistory: ScanHistoryEntry[];
  totalVulnsFound: number;
  totalCriticalFound: number;
  
  // Active Scanner
  scanResult: ActiveScanResult | null;
  scanTarget: string;
  
  // Actions
  setAuth: (token: string, user: string, role: 'admin' | 'user') => void;
  clearAuth: () => void;
  appendLiveEvent: (event: LiveEvent) => void;
  appendScanHistory: (entry: ScanHistoryEntry) => void;
  setModelInfo: (info: ModelInfo) => void;
  setLatestPrediction: (result: PredictionResult) => void;
  setDeepScanResult: (result: DeepScanResult, target: string) => void;
  setActiveScanResult: (result: ActiveScanResult, target: string) => void;
}

const checkAuthExpiry = (state: AppState) => {
  if (state.authExpiry && Date.now() > state.authExpiry) {
    return { authToken: null, authUser: null, authRole: null, authExpiry: null };
  }
  return state;
};

export const useAppStore = create<AppState>()(
  persist(
    (set) => ({
      authToken: null,
      authUser: null,
      authRole: null,
      authExpiry: null,
      
      modelInfoCache: null,
      
      latestPredictionResult: null,
      latestUploadResult: null,
      liveHistory: [],
      liveRecentEvents: [],
      liveAlerts: [],
      
      deepScanResult: null,
      deepScanAnalysis: null,
      deepScanTarget: '',
      deepScanHistory: [],
      totalVulnsFound: 0,
      totalCriticalFound: 0,
      
      scanResult: null,
      scanTarget: '',

      setAuth: (token, user, role) => set({
        authToken: token,
        authUser: user,
        authRole: role,
        authExpiry: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
      }),
      clearAuth: () => set({ authToken: null, authUser: null, authRole: null, authExpiry: null }),
      
      appendLiveEvent: (event) => set((state) => ({
        liveHistory: [...state.liveHistory, event].slice(-1000),
        liveRecentEvents: [...state.liveRecentEvents, event].slice(-50),
      })),
      
      appendScanHistory: (entry) => set((state) => {
        const deepResult = entry.result as DeepScanResult;
        const isCritical = entry.type === 'deep' && ["D", "F"].includes(deepResult.risk_grade);
        const findingCount = entry.type === 'deep' ? (deepResult.total_findings || 0) : 0;
        return {
          deepScanHistory: [entry, ...state.deepScanHistory],
          totalVulnsFound: state.totalVulnsFound + findingCount,
          totalCriticalFound: state.totalCriticalFound + (isCritical ? 1 : 0)
        };
      }),
      
      setModelInfo: (info) => set({ modelInfoCache: info }),
      setLatestPrediction: (result) => set({ latestPredictionResult: result }),
      setDeepScanResult: (result, target) => set({ deepScanResult: result, deepScanTarget: target }),
      setActiveScanResult: (result, target) => set({ scanResult: result, scanTarget: target }),
    }),
    {
      name: 'safeguard-ai-storage',
      partialize: (state) => ({
        authToken: state.authToken,
        authUser: state.authUser,
        authRole: state.authRole,
        authExpiry: state.authExpiry,
        totalVulnsFound: state.totalVulnsFound,
        totalCriticalFound: state.totalCriticalFound,
      }),
      onRehydrateStorage: () => (state) => {
        if (state) {
          const validState = checkAuthExpiry(state);
          if (validState.authToken === null && state.authToken !== null) {
             state.clearAuth();
          }
        }
      }
    }
  )
);
