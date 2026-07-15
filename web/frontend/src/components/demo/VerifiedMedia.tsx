import { ShieldCheck, ShieldX, Loader2, XCircle } from 'lucide-react';

type VerificationStatus = 'pending' | 'checking' | 'verified' | 'failed';

interface VerifiedMediaProps {
  src: string;
  mediaType: 'image' | 'audio';
  status: VerificationStatus;
  alt?: string;
}

export function VerifiedMedia({ src, mediaType, status, alt }: VerifiedMediaProps) {
  const isImage = mediaType === 'image';

  return (
    <div className="relative">
      {/* Status badge - top right */}
      <div className="absolute top-2 right-2 z-10">
        <StatusBadge status={status} />
      </div>

      {/* Media content */}
      {status === 'failed' ? (
        <FailedOverlay isImage={isImage} />
      ) : (
        <div className={`
          ${status === 'checking' ? 'opacity-50 animate-pulse' : ''}
          ${status === 'verified' ? 'ring-2 ring-success rounded-lg' : ''}
        `}>
          {isImage ? (
            <img src={src} alt={alt || 'Media'} className="rounded-lg max-h-64 mx-auto" />
          ) : (
            <audio controls className="w-full">
              <source src={src} type="audio/wav" />
            </audio>
          )}
        </div>
      )}

      {/* Checking overlay spinner */}
      {status === 'checking' && (
        <div className="absolute inset-0 flex items-center justify-center">
          <Loader2 className="w-8 h-8 animate-spin text-primary" />
        </div>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: VerificationStatus }) {
  switch (status) {
    case 'checking':
      return (
        <div className="badge badge-ghost gap-1">
          <Loader2 className="w-3 h-3 animate-spin" />
          Verifying
        </div>
      );
    case 'verified':
      return (
        <div className="badge badge-success gap-1">
          <ShieldCheck className="w-3 h-3" />
          Verified
        </div>
      );
    case 'failed':
      return (
        <div className="badge badge-error gap-1">
          <ShieldX className="w-3 h-3" />
          Failed
        </div>
      );
    default:
      return null;
  }
}

function FailedOverlay({ isImage }: { isImage: boolean }) {
  return (
    <div className={`
      flex flex-col items-center justify-center gap-3
      bg-error/10 border-2 border-error rounded-lg p-8
      ${isImage ? 'min-h-48' : 'min-h-24'}
    `}>
      <XCircle className="w-12 h-12 text-error" />
      <div className="text-center">
        <p className="font-semibold text-error">Integrity Verification Failed</p>
        <p className="text-sm text-error/70">
          This {isImage ? 'image' : 'audio'} may have been tampered with
        </p>
      </div>
    </div>
  );
}
