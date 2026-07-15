#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { HyperVerITASWebStack } from '../lib/hyperveritas-web-stack';

const app = new cdk.App();

new HyperVerITASWebStack(app, 'HyperVerITASWebStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION || 'us-east-1',
  },
});
