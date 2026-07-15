import { CheckCircle, Loader, AlertCircle, FileText, Cpu, ShieldCheck } from 'lucide-react';
import { useJobStatus } from '../../hooks/useJobStatus';
import type { JobStatus } from '../../types';

interface ProofStatusProps {
  jobId: string;
  onComplete: () => void;
}

const steps: { status: JobStatus; label: string; icon: React.ReactNode }[] = [
  { status: 'pending', label: 'Queued', icon: <FileText className="w-5 h-5" /> },
  { status: 'converting', label: 'Converting', icon: <Loader className="w-5 h-5" /> },
  { status: 'proving', label: 'Generating Proof', icon: <Cpu className="w-5 h-5" /> },
  { status: 'completed', label: 'Complete', icon: <ShieldCheck className="w-5 h-5" /> },
];

const statusOrder: JobStatus[] = ['pending', 'converting', 'proving', 'completed'];

export function ProofStatus({ jobId, onComplete }: ProofStatusProps) {
  const { data: job, error } = useJobStatus(jobId);

  if (error) {
    return (
      <div className="alert alert-error">
        <AlertCircle className="w-5 h-5" />
        <span>Error checking job status: {error.message}</span>
      </div>
    );
  }

  if (!job) {
    return (
      <div className="flex items-center gap-2 p-4">
        <span className="loading loading-spinner loading-sm"></span>
        <span>Loading job status...</span>
      </div>
    );
  }

  if (job.status === 'failed') {
    return (
      <div className="alert alert-error">
        <AlertCircle className="w-5 h-5" />
        <div>
          <div className="font-medium">Proof generation failed</div>
          <div className="text-sm">{job.errorMessage || 'Unknown error'}</div>
        </div>
      </div>
    );
  }

  if (job.status === 'completed') {
    // Notify parent once
    setTimeout(onComplete, 0);
  }

  const currentIdx = statusOrder.indexOf(job.status);

  return (
    <div className="py-4">
      <ul className="steps steps-vertical lg:steps-horizontal w-full">
        {steps.map((step, idx) => {
          const isActive = idx === currentIdx;
          const isDone = idx < currentIdx || job.status === 'completed';

          return (
            <li
              key={step.status}
              className={`step ${isDone ? 'step-primary' : ''} ${isActive && job.status !== 'completed' ? 'step-primary' : ''}`}
            >
              <div className={`flex items-center gap-2 ${isActive ? 'font-semibold' : ''}`}>
                {isDone ? (
                  <CheckCircle className="w-4 h-4 text-primary" />
                ) : isActive ? (
                  <span className="loading loading-spinner loading-xs"></span>
                ) : (
                  <span className="w-4 h-4" />
                )}
                {step.label}
              </div>
            </li>
          );
        })}
      </ul>

      {job.status === 'proving' && (
        <div className="text-center mt-6">
          <span className="loading loading-dots loading-lg text-primary"></span>
          <p className="text-sm text-base-content/60 mt-2">
            Running the ZK prover (size 2^{job.sizeParam})...
          </p>
          <p className="text-xs text-base-content/40">
            This may take a few seconds to several minutes depending on input size
          </p>
        </div>
      )}
    </div>
  );
}
