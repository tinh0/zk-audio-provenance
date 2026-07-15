// Lambda handler wrapper for production deployment
// Uses serverless-http to wrap the Express app
// Not used in local development

import app from './app';

let handler: any;

export async function lambdaHandler(event: any, context: any) {
  if (!handler) {
    // Lazy import serverless-http only when running on Lambda
    const serverlessHttp = require('serverless-http');
    handler = serverlessHttp(app);
  }
  return handler(event, context);
}
