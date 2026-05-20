import { useAppStore } from '../store/useAppStore';

export function useScanHistory() {
  const { deepScanHistory, totalVulnsFound, totalCriticalFound } = useAppStore();

  return {
    history: deepScanHistory,
    totalScans: deepScanHistory.length,
    totalVulnsFound,
    totalCriticalFound
  };
}
