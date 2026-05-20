"use client";

import { AuthGuard } from "../../../components/layout/AuthGuard";
import { useAppStore } from "../../../store/useAppStore";
import { BarChart } from "../../../components/ui/BarChart";
import { DataTable } from "../../../components/ui/DataTable";
import { AlertCircle, BrainCircuit } from "lucide-react";

export default function ExplanationsPage() {
  const { latestPredictionResult } = useAppStore();

  const getShapData = () => {
    if (!latestPredictionResult || !latestPredictionResult.shap_values) return [];
    
    return Object.entries(latestPredictionResult.shap_values).map(([feature, impact]) => ({
      feature, impact: Number(impact)
    })).sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact)).slice(0, 10);
  };

  const shapData = getShapData();

  return (
    <AuthGuard>
      <div className="p-4 md:p-8 space-y-8">
        <div>
          <h1 className="text-2xl font-bold text-text-primary mb-2">AI Explanations</h1>
          <p className="text-text-secondary">Understand how the Machine Learning model makes its decisions.</p>
        </div>

        {!latestPredictionResult ? (
          <div className="bg-bg-secondary border border-border-subtle rounded-xl p-12 text-center flex flex-col items-center">
            <AlertCircle className="w-12 h-12 text-text-secondary mb-4 opacity-50" />
            <h2 className="text-lg font-medium text-text-primary mb-2">No Prediction Data</h2>
            <p className="text-text-secondary">Run a prediction in the Live Predictions or Upload tabs first.</p>
          </div>
        ) : (
          <div className="space-y-6">
            
            <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6">
              <div className="flex items-center gap-3 mb-6">
                <BrainCircuit className="w-6 h-6 text-accent-violet" />
                <h2 className="text-lg font-bold text-text-primary">Decision Explanation</h2>
              </div>
              
              <div className="mb-6">
                <span className="text-text-secondary">The model classified the input as: </span>
                <span className="text-xl font-bold text-accent-cyan ml-2">{latestPredictionResult.prediction}</span>
              </div>

              {shapData.length > 0 ? (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                  <div>
                    <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-4">Feature Impact (Approximation)</h3>
                    <BarChart 
                      data={shapData}
                      xKey="feature"
                      yKey="impact"
                      layout="vertical"
                      colors={shapData.map(d => d.impact > 0 ? '#fb7185' : '#38bdf8')}
                    />
                    <p className="text-xs text-text-secondary mt-4">
                      * Red bars indicate features pushing towards the predicted class. Blue bars push away.
                    </p>
                  </div>
                  
                  <div>
                    <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-4">Top Influencing Features</h3>
                    <DataTable 
                      data={shapData.slice(0, 5)}
                      columns={[
                        { header: "Feature Name", accessorKey: "feature", className: "font-mono text-xs" },
                        { header: "Impact Score", cell: (r) => r.impact.toFixed(4), className: "text-right" }
                      ]}
                    />
                  </div>
                </div>
              ) : (
                <div className="p-8 border border-dashed border-border-subtle rounded-lg text-center text-text-secondary bg-bg-primary/50">
                  Feature impact explanations are not available for this prediction.
                </div>
              )}
            </div>

          </div>
        )}
      </div>
    </AuthGuard>
  );
}
