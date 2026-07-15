import { Request, Response } from 'express';
import * as jobService from '../services/jobService';

/**
 * GET /api/status/:jobId
 * Poll job status and metrics.
 */
export function statusHandler(req: Request, res: Response) {
  const jobId = String(req.params.jobId);
  const job = jobService.getJob(jobId);

  if (!job) {
    res.status(404).json({ error: 'Job not found' });
    return;
  }

  res.json({ job });
}
