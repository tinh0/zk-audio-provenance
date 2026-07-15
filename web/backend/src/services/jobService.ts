import { Job, JobStatus } from '@hyperveritas-web/shared/types';

// In-memory job store for local development
// In production, this would be DynamoDB
const jobs = new Map<string, Job>();

export function createJob(job: Job): void {
  jobs.set(job.jobId, job);
}

export function getJob(jobId: string): Job | undefined {
  return jobs.get(jobId);
}

export function updateJob(jobId: string, updates: Partial<Job>): Job | undefined {
  const job = jobs.get(jobId);
  if (!job) return undefined;
  const updated = { ...job, ...updates, updatedAt: new Date().toISOString() };
  jobs.set(jobId, updated);
  return updated;
}

export function updateJobStatus(jobId: string, status: JobStatus): Job | undefined {
  return updateJob(jobId, { status });
}

export function listJobs(): Job[] {
  return Array.from(jobs.values()).sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );
}
