import { useState, useCallback, useRef } from 'react';
import { Upload, Image, Music, X } from 'lucide-react';
import type { MediaType } from '../../types';

interface FileUploadProps {
  onFileSelected: (file: File, mediaType: MediaType) => void;
  disabled?: boolean;
}

const ACCEPTED_IMAGE = ['image/png', 'image/jpeg', 'image/jpg'];
const ACCEPTED_AUDIO = ['audio/wav', 'audio/wave', 'audio/x-wav'];

export function FileUpload({ onFileSelected, disabled }: FileUploadProps) {
  const [dragOver, setDragOver] = useState(false);
  const [preview, setPreview] = useState<{ url: string; type: MediaType; name: string } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const processFile = useCallback((file: File) => {
    let mediaType: MediaType;

    if (ACCEPTED_IMAGE.includes(file.type)) {
      mediaType = 'image';
      const url = URL.createObjectURL(file);
      setPreview({ url, type: 'image', name: file.name });
    } else if (ACCEPTED_AUDIO.includes(file.type) || file.name.endsWith('.wav')) {
      mediaType = 'audio';
      const url = URL.createObjectURL(file);
      setPreview({ url, type: 'audio', name: file.name });
    } else {
      alert('Unsupported file type. Please upload a PNG, JPG, or WAV file.');
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      alert('File too large. Max 10MB for the demo.');
      return;
    }

    onFileSelected(file, mediaType);
  }, [onFileSelected]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (disabled) return;
    const file = e.dataTransfer.files[0];
    if (file) processFile(file);
  }, [processFile, disabled]);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) processFile(file);
  }, [processFile]);

  const clearFile = () => {
    setPreview(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="w-full">
      {!preview ? (
        <div
          className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all
            ${dragOver ? 'border-primary bg-primary/5' : 'border-base-300 hover:border-primary/50'}
            ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => !disabled && fileInputRef.current?.click()}
        >
          <Upload className="w-12 h-12 mx-auto mb-4 text-base-content/40" />
          <p className="text-lg font-medium mb-2">Drop your file here or click to browse</p>
          <p className="text-sm text-base-content/60">
            Supports PNG, JPG (images) and WAV (audio) - Max 10MB
          </p>
          <div className="flex gap-4 justify-center mt-4">
            <div className="badge badge-outline gap-1">
              <Image className="w-3 h-3" /> Images
            </div>
            <div className="badge badge-outline gap-1">
              <Music className="w-3 h-3" /> Audio
            </div>
          </div>
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            accept=".png,.jpg,.jpeg,.wav"
            onChange={handleFileInput}
          />
        </div>
      ) : (
        <div className="card bg-base-200">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {preview.type === 'image' ? (
                  <Image className="w-5 h-5 text-primary" />
                ) : (
                  <Music className="w-5 h-5 text-secondary" />
                )}
                <span className="font-medium">{preview.name}</span>
                <span className="badge badge-sm">{preview.type}</span>
              </div>
              {!disabled && (
                <button className="btn btn-ghost btn-sm btn-circle" onClick={clearFile}>
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>
            <div className="mt-4">
              {preview.type === 'image' ? (
                <img
                  src={preview.url}
                  alt="Preview"
                  className="max-h-64 mx-auto rounded-lg shadow"
                />
              ) : (
                <audio controls className="w-full">
                  <source src={preview.url} type="audio/wav" />
                </audio>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
