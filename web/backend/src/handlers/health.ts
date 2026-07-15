import { Request, Response } from 'express';

export function healthHandler(_req: Request, res: Response) {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
}
