import { Request, Response } from 'express';
import path from 'path';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config';

/**
 * POST /api/upload
 * Accepts a file upload via multipart form data.
 * In local mode, saves to filesystem. In prod, would use S3 presigned URLs.
 */
export function uploadHandler(req: Request, res: Response) {
  if (!req.file) {
    res.status(400).json({ error: 'No file uploaded' });
    return;
  }

  const fileId = uuidv4();
  const ext = path.extname(req.file.originalname);
  const uploadDir = path.join(config.uploadsPath, fileId);
  fs.mkdirSync(uploadDir, { recursive: true });

  const filePath = path.join(uploadDir, `original${ext}`);
  fs.writeFileSync(filePath, req.file.buffer);

  res.json({
    fileId,
    fileName: req.file.originalname,
  });
}
