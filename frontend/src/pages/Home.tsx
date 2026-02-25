import { useState } from 'react';
import axios from 'axios';
import { Upload, Shield, Cpu, FileSearch } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export default function Home() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const nextFile = event.target.files?.[0] || null;
    setSelectedFile(nextFile);
    setErrorMessage(null);
  };

  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    const nextFile = event.dataTransfer.files?.[0] || null;
    setSelectedFile(nextFile);
    setErrorMessage(null);
  };

  const handleDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
  };

  const uploadFile = async () => {
    if (!selectedFile) return;
    setIsUploading(true);
    setErrorMessage(null);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const res = await axios.post(`${API_BASE}/analyze`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      navigate(`/task/${res.data.task_id}`);
    } catch (err) {
      console.error(err);
      setErrorMessage("Upload failed. Please try again.");
      setIsUploading(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto">
      {/* Header */}
      <header className="mb-12 text-center">
        <h1 className="text-5xl font-extrabold mb-4 bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-500">
          ThreatScope
        </h1>
        <p className="text-xl text-slate-400">AI-Powered Malware Analysis Framework</p>
      </header>

      {/* Error Message */}
      {errorMessage && (
        <div className="mb-8 bg-red-900/20 p-4 rounded-xl border border-red-800 text-center text-red-400">
          {errorMessage}
        </div>
      )}

      {/* Features Grid */}
      <div className="grid md:grid-cols-3 gap-6 mb-12">
        <div className="bg-slate-800/50 p-6 rounded-xl border border-slate-700">
          <FileSearch className="w-10 h-10 text-emerald-400 mb-4" />
          <h3 className="text-lg font-bold text-white mb-2">Static Analysis</h3>
          <p className="text-slate-400 text-sm">Deep inspection of binary structure, strings, imports, and security features.</p>
        </div>
        <div className="bg-slate-800/50 p-6 rounded-xl border border-slate-700">
          <Cpu className="w-10 h-10 text-cyan-400 mb-4" />
          <h3 className="text-lg font-bold text-white mb-2">Dynamic Analysis</h3>
          <p className="text-slate-400 text-sm">Sandbox execution with syscall tracing and behavior monitoring.</p>
        </div>
        <div className="bg-slate-800/50 p-6 rounded-xl border border-slate-700">
          <Shield className="w-10 h-10 text-purple-400 mb-4" />
          <h3 className="text-lg font-bold text-white mb-2">AI Report</h3>
          <p className="text-slate-400 text-sm">Intelligent threat assessment with MITRE ATT&CK mapping.</p>
        </div>
      </div>

      {/* Upload Card */}
      <div className="max-w-2xl mx-auto">
        <div className="bg-slate-800 p-8 rounded-xl border border-slate-700 shadow-xl">
          <h2 className="text-2xl font-bold mb-6 flex items-center text-white">
            <Upload className="mr-3 text-emerald-400" /> Upload Binary
          </h2>
          
          <div 
            className="border-2 border-dashed border-slate-600 rounded-lg p-12 text-center hover:border-emerald-500 transition-colors cursor-pointer relative"
            onDrop={handleDrop}
            onDragOver={handleDragOver}
          >
            <input 
              type="file" 
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              onChange={handleFileChange}
            />
            {selectedFile ? (
              <div>
                <div className="text-emerald-400 font-semibold text-lg">{selectedFile.name}</div>
                <div className="text-slate-500 text-sm mt-1">
                  {(selectedFile.size / 1024).toFixed(2)} KB
                </div>
              </div>
            ) : (
              <div className="text-slate-400">
                <Upload className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p className="text-lg">Drag & drop or click to select</p>
                <p className="text-sm mt-2 opacity-60">Supports ELF, PE, Mach-O, APK</p>
              </div>
            )}
          </div>
          
          <button 
            onClick={uploadFile}
            disabled={!selectedFile || isUploading}
            className="mt-6 w-full bg-emerald-600 hover:bg-emerald-700 text-white font-bold py-4 rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer text-lg"
          >
            {isUploading ? (
              <span className="flex items-center justify-center">
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Uploading...
              </span>
            ) : (
              'Start Analysis'
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
