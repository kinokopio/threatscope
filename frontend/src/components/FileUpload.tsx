import { useCallback, useState } from 'react';
import { Upload, FileWarning, Loader2 } from 'lucide-react';

interface FileUploadProps {
  onUpload: (file: File) => void;
  isUploading: boolean;
}

export function FileUpload({ onUpload, isUploading }: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) {
        onUpload(file);
      }
    },
    [onUpload]
  );

  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) {
        onUpload(file);
      }
    },
    [onUpload]
  );

  return (
    <div
      className={`
        relative border-2 border-dashed rounded-xl p-8 text-center transition-all duration-300
        ${isDragging 
          ? 'border-accent-cyan bg-accent-cyan/10' 
          : 'border-cyber-600 hover:border-cyber-500 bg-cyber-800/50'
        }
        ${isUploading ? 'pointer-events-none opacity-60' : 'cursor-pointer'}
      `}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      <input
        type="file"
        className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
        onChange={handleFileSelect}
        disabled={isUploading}
      />
      
      <div className="flex flex-col items-center gap-4">
        {isUploading ? (
          <Loader2 className="w-12 h-12 text-accent-cyan animate-spin" />
        ) : isDragging ? (
          <FileWarning className="w-12 h-12 text-accent-cyan" />
        ) : (
          <Upload className="w-12 h-12 text-cyber-500" />
        )}
        
        <div>
          <p className="text-lg font-medium text-gray-200">
            {isUploading 
              ? 'Uploading...' 
              : isDragging 
                ? 'Drop file here' 
                : 'Drop malware sample here'
            }
          </p>
          <p className="text-sm text-gray-400 mt-1">
            or click to browse
          </p>
        </div>
        
        <div className="flex items-center gap-2 text-xs text-gray-500">
          <span className="px-2 py-1 bg-cyber-700 rounded">ELF</span>
          <span className="px-2 py-1 bg-cyber-700 rounded">PE</span>
          <span className="px-2 py-1 bg-cyber-700 rounded">APK</span>
          <span className="px-2 py-1 bg-cyber-700 rounded">Any Binary</span>
        </div>
      </div>
    </div>
  );
}
