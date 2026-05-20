"use client";

import { useState, useRef } from "react";
import { AuthGuard } from "../../../components/layout/AuthGuard";
import { DataTable } from "../../../components/ui/DataTable";
import { AlertBadge } from "../../../components/ui/AlertBadge";
import { modelAPI } from "../../../lib/api";
import { useAppStore } from "../../../store/useAppStore";
import { UploadCloud, FileType, CheckCircle2, AlertTriangle, Download } from "lucide-react";
import { cn } from "../../../lib/utils";

export default function UploadPage() {
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  
  const { latestUploadResult, setAuth } = useAppStore();
  const setLatestUpload = (res: any) => useAppStore.setState({ latestUploadResult: res });

  const handleDragOver = (e: React.DragEvent) => { e.preventDefault(); setIsDragging(true); };
  const handleDragLeave = (e: React.DragEvent) => { e.preventDefault(); setIsDragging(false); };
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleSubmit = async () => {
    if (!file) return;
    setIsUploading(true);
    setError(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await modelAPI.predictBatch(formData);
      setLatestUpload(res);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to process file.");
    } finally {
      setIsUploading(false);
    }
  };

  const handleDownload = () => {
    if (!latestUploadResult) return;
    // Simple CSV generation from results
    const headers = ["Index", "Prediction", "Risk Level"];
    const rows = latestUploadResult.results.map((r, i) => [i, r.prediction, r.risk_level || "N/A"]);
    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "scan_results.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <AuthGuard>
      <div className="p-4 md:p-8 space-y-8">
        <div>
          <h1 className="text-2xl font-bold text-text-primary mb-2">Upload PCAP / CSV</h1>
          <p className="text-text-secondary">Upload network logs for batch intrusion detection analysis.</p>
        </div>

        {/* Drag and Drop Zone */}
        <div 
          className={cn(
            "border-2 border-dashed rounded-2xl p-12 text-center transition-all cursor-pointer",
            isDragging ? "border-accent-cyan bg-accent-cyan/10" : "border-border-subtle bg-bg-secondary hover:bg-bg-tertiary",
            file ? "border-emerald-500 bg-emerald-500/5" : ""
          )}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleFileChange} 
            className="hidden" 
            accept=".csv,.pcap"
          />
          <div className="flex flex-col items-center gap-4 pointer-events-none">
            {file ? (
              <FileType className="w-12 h-12 text-emerald-400" />
            ) : (
              <UploadCloud className="w-12 h-12 text-text-secondary" />
            )}
            
            <div>
              <p className="text-lg font-medium text-text-primary">
                {file ? file.name : "Click or drag file to this area"}
              </p>
              <p className="text-sm text-text-secondary mt-1">
                {file ? `${(file.size / 1024 / 1024).toFixed(2)} MB` : "Supported formats: .csv, .pcap"}
              </p>
            </div>
          </div>
        </div>

        {error && (
          <div className="p-4 bg-rose-500/10 border border-rose-500/20 text-rose-500 rounded-xl flex gap-3">
            <AlertTriangle className="w-5 h-5 shrink-0" />
            <p className="text-sm">{error}</p>
          </div>
        )}

        {/* Action Button */}
        {file && (
          <div className="flex justify-end">
            <button
              onClick={handleSubmit}
              disabled={isUploading}
              className="px-6 py-3 bg-accent-cyan hover:bg-accent-cyan/90 text-bg-primary font-bold rounded-xl shadow-lg shadow-accent-cyan/20 disabled:opacity-50 transition-all flex items-center gap-2"
            >
              {isUploading ? (
                <><div className="w-4 h-4 rounded-full border-2 border-bg-primary border-t-transparent animate-spin" /> Processing...</>
              ) : (
                <><CheckCircle2 className="w-5 h-5" /> Analyze File</>
              )}
            </button>
          </div>
        )}

        {/* Results */}
        {latestUploadResult && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold text-text-primary">Analysis Results</h2>
              <button 
                onClick={handleDownload}
                className="px-4 py-2 bg-bg-tertiary hover:bg-bg-secondary text-text-primary text-sm font-medium rounded-lg border border-border-subtle flex items-center gap-2 transition-colors"
              >
                <Download className="w-4 h-4" /> Download CSV
              </button>
            </div>
            
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-bg-secondary border border-border-subtle p-4 rounded-xl text-center">
                <div className="text-2xl font-bold text-text-primary">{latestUploadResult.total}</div>
                <div className="text-xs text-text-secondary uppercase">Total Records</div>
              </div>
              <div className="bg-emerald-500/10 border border-emerald-500/20 p-4 rounded-xl text-center">
                <div className="text-2xl font-bold text-emerald-400">{latestUploadResult.normal}</div>
                <div className="text-xs text-emerald-500 uppercase">Normal Traffic</div>
              </div>
              <div className="bg-rose-500/10 border border-rose-500/20 p-4 rounded-xl text-center">
                <div className="text-2xl font-bold text-rose-500">{latestUploadResult.anomalies}</div>
                <div className="text-xs text-rose-500 uppercase">Anomalies Detected</div>
              </div>
            </div>

            <DataTable 
              data={latestUploadResult.results.slice(0, 50)} // Show first 50
              columns={[
                { header: "Index", cell: (_, i) => i + 1, className: "w-16 text-text-secondary" },
                { header: "Prediction", cell: (r) => r.prediction === "Normal" ? <span className="text-emerald-400">{r.prediction}</span> : <span className="text-rose-500 font-medium">{r.prediction}</span> },
                { header: "Risk", cell: (r) => <AlertBadge severity={r.risk_level || "low"} /> },
              ]}
            />
          </div>
        )}
      </div>
    </AuthGuard>
  );
}
