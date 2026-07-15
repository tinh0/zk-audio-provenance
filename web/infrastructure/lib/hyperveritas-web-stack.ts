import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

export class HyperVerITASWebStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ============================================================
    // S3 Bucket - file storage
    // ============================================================
    const bucket = new s3.Bucket(this, 'FilesBucket', {
      bucketName: `hyperveritas-web-files-${this.account}`,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      cors: [{
        allowedMethods: [s3.HttpMethods.GET, s3.HttpMethods.PUT, s3.HttpMethods.POST],
        allowedOrigins: ['*'],
        allowedHeaders: ['*'],
        maxAge: 3600,
      }],
      lifecycleRules: [{
        expiration: cdk.Duration.days(7),
      }],
    });

    // ============================================================
    // DynamoDB Table - job tracking
    // ============================================================
    const jobsTable = new dynamodb.Table(this, 'JobsTable', {
      tableName: 'HyperVerITAS-Jobs',
      partitionKey: { name: 'jobId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      timeToLiveAttribute: 'expiresAt',
    });

    // ============================================================
    // ECR Repository - prover Docker image
    // ============================================================
    const proverRepo = new ecr.Repository(this, 'ProverRepo', {
      repositoryName: 'hyperveritas-prover',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      emptyOnDelete: true,
    });

    // ============================================================
    // VPC for ECS
    // ============================================================
    const vpc = new ec2.Vpc(this, 'ProverVpc', {
      maxAzs: 2,
      natGateways: 1,
    });

    // ============================================================
    // ECS Cluster + Fargate Task Definition
    // ============================================================
    const cluster = new ecs.Cluster(this, 'ProverCluster', {
      clusterName: 'hyperveritas-prover',
      vpc,
    });

    const taskDefinition = new ecs.FargateTaskDefinition(this, 'ProverTaskDef', {
      memoryLimitMiB: 8192,  // 8GB for demo sizes (10-14)
      cpu: 4096,             // 4 vCPU
    });

    taskDefinition.addContainer('prover', {
      image: ecs.ContainerImage.fromEcrRepository(proverRepo, 'latest'),
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'hyperveritas-prover',
        logRetention: logs.RetentionDays.ONE_WEEK,
      }),
      environment: {
        S3_BUCKET: bucket.bucketName,
        DYNAMODB_TABLE: jobsTable.tableName,
      },
    });

    // Grant ECS task access to S3 and DynamoDB
    bucket.grantReadWrite(taskDefinition.taskRole);
    jobsTable.grantReadWriteData(taskDefinition.taskRole);

    // ============================================================
    // Lambda Function - API
    // ============================================================
    const apiFunction = new lambda.Function(this, 'ApiFunction', {
      functionName: 'hyperveritas-api',
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'lambda.lambdaHandler',
      code: lambda.Code.fromAsset('../backend/dist'),
      memorySize: 512,
      timeout: cdk.Duration.seconds(30),
      environment: {
        NODE_ENV: 'production',
        S3_BUCKET: bucket.bucketName,
        DYNAMODB_TABLE: jobsTable.tableName,
        ECS_CLUSTER: cluster.clusterArn,
        ECS_TASK_DEFINITION: taskDefinition.taskDefinitionArn,
        ECS_SUBNETS: vpc.privateSubnets.map(s => s.subnetId).join(','),
      },
    });

    // Grant Lambda access to resources
    bucket.grantReadWrite(apiFunction);
    jobsTable.grantReadWriteData(apiFunction);

    // Grant Lambda permission to run ECS tasks
    apiFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ecs:RunTask', 'ecs:DescribeTasks'],
      resources: ['*'],
    }));
    apiFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: ['iam:PassRole'],
      resources: [
        taskDefinition.taskRole.roleArn,
        taskDefinition.executionRole!.roleArn,
      ],
    }));

    // ============================================================
    // API Gateway
    // ============================================================
    const api = new apigateway.LambdaRestApi(this, 'ApiGateway', {
      restApiName: 'HyperVerITAS-Web-API',
      handler: apiFunction,
      proxy: true,
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
      },
    });

    // ============================================================
    // Outputs
    // ============================================================
    new cdk.CfnOutput(this, 'ApiUrl', { value: api.url });
    new cdk.CfnOutput(this, 'BucketName', { value: bucket.bucketName });
    new cdk.CfnOutput(this, 'EcsCluster', { value: cluster.clusterArn });
    new cdk.CfnOutput(this, 'ProverRepoUri', { value: proverRepo.repositoryUri });
  }
}
