import useSWR from 'swr';
import { getJobStatus } from '../services/api';
import type { Job } from '../types';

const fetcher = (jobId: string) => getJobStatus(jobId).then(r => r.job);

export function useJobStatus(jobId: string | null) {
  return useSWR<Job>(
    jobId ? jobId : null,
    fetcher,
    {
      refreshInterval: (data) => {
        if (!data) return 2000;
        if (data.status === 'completed' || data.status === 'failed') return 0;
        return 2000;
      },
      revalidateOnFocus: false,
    }
  );
}
