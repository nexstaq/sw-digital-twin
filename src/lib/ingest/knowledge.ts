/** Known libraries -> what they imply. Deterministic knowledge beats guessing. */

export const DATASTORE_LIBS: Record<string, { label: string; kind: "datastore" | "queue" }> = {
  pg: { label: "PostgreSQL", kind: "datastore" }, postgres: { label: "PostgreSQL", kind: "datastore" },
  "@neondatabase/serverless": { label: "PostgreSQL", kind: "datastore" }, psycopg2: { label: "PostgreSQL", kind: "datastore" },
  psycopg: { label: "PostgreSQL", kind: "datastore" }, asyncpg: { label: "PostgreSQL", kind: "datastore" },
  sqlalchemy: { label: "SQL database", kind: "datastore" }, sqlmodel: { label: "SQL database", kind: "datastore" },
  prisma: { label: "SQL database (Prisma)", kind: "datastore" }, "@prisma/client": { label: "SQL database (Prisma)", kind: "datastore" },
  "drizzle-orm": { label: "SQL database (Drizzle)", kind: "datastore" }, typeorm: { label: "SQL database", kind: "datastore" },
  sequelize: { label: "SQL database", kind: "datastore" }, knex: { label: "SQL database", kind: "datastore" },
  mysql: { label: "MySQL", kind: "datastore" }, mysql2: { label: "MySQL", kind: "datastore" }, pymysql: { label: "MySQL", kind: "datastore" },
  "better-sqlite3": { label: "SQLite", kind: "datastore" }, sqlite3: { label: "SQLite", kind: "datastore" },
  mongoose: { label: "MongoDB", kind: "datastore" }, mongodb: { label: "MongoDB", kind: "datastore" }, pymongo: { label: "MongoDB", kind: "datastore" },
  motor: { label: "MongoDB", kind: "datastore" },
  redis: { label: "Redis", kind: "datastore" }, ioredis: { label: "Redis", kind: "datastore" }, "@upstash/redis": { label: "Redis", kind: "datastore" },
  "@elastic/elasticsearch": { label: "Elasticsearch", kind: "datastore" }, elasticsearch: { label: "Elasticsearch", kind: "datastore" },
  "@aws-sdk/client-s3": { label: "Object storage (S3)", kind: "datastore" }, boto3: { label: "AWS (boto3)", kind: "datastore" },
  "@vercel/blob": { label: "Object storage (Blob)", kind: "datastore" },
  "@aws-sdk/client-dynamodb": { label: "DynamoDB", kind: "datastore" },
  bullmq: { label: "Redis job queue (BullMQ)", kind: "queue" }, bull: { label: "Redis job queue (Bull)", kind: "queue" },
  amqplib: { label: "RabbitMQ", kind: "queue" }, pika: { label: "RabbitMQ", kind: "queue" },
  kafkajs: { label: "Kafka", kind: "queue" }, "confluent-kafka": { label: "Kafka", kind: "queue" }, kafka: { label: "Kafka", kind: "queue" },
  "@aws-sdk/client-sqs": { label: "SQS queue", kind: "queue" }, "@aws-sdk/client-sns": { label: "SNS topics", kind: "queue" },
  celery: { label: "Celery task queue", kind: "queue" }, nats: { label: "NATS", kind: "queue" },
  "@vercel/queue": { label: "Vercel Queues", kind: "queue" }, "@google-cloud/pubsub": { label: "Pub/Sub", kind: "queue" },
};

export const EXTERNAL_LIBS: Record<string, string> = {
  stripe: "Stripe", "@stripe/stripe-js": "Stripe", "@sendgrid/mail": "SendGrid", sendgrid: "SendGrid", twilio: "Twilio",
  resend: "Resend", nodemailer: "SMTP email", postmark: "Postmark", mailgun: "Mailgun", "mailgun.js": "Mailgun",
  openai: "OpenAI", "@anthropic-ai/sdk": "Anthropic", anthropic: "Anthropic", "@google/generative-ai": "Google Gemini",
  ai: "AI SDK", langchain: "LangChain", "@sentry/node": "Sentry", "@sentry/nextjs": "Sentry", "sentry-sdk": "Sentry",
  "@slack/web-api": "Slack", slack_sdk: "Slack", "@octokit/rest": "GitHub API", octokit: "GitHub API", pygithub: "GitHub API",
  "@clerk/nextjs": "Clerk", "next-auth": "Auth.js", auth0: "Auth0", "@auth0/nextjs-auth0": "Auth0", "firebase-admin": "Firebase",
  firebase: "Firebase", "@supabase/supabase-js": "Supabase", algoliasearch: "Algolia", "posthog-node": "PostHog", "posthog-js": "PostHog",
  "@datadog/browser-rum": "Datadog", "dd-trace": "Datadog", "@opentelemetry/api": "OpenTelemetry", "@shopify/shopify-api": "Shopify",
  "@paypal/checkout-server-sdk": "PayPal", plaid: "Plaid", contentful: "Contentful", "@sanity/client": "Sanity", cloudinary: "Cloudinary",
  "@aws-sdk/client-ses": "AWS SES", "@aws-sdk/client-lambda": "AWS Lambda", "@vercel/analytics": "Vercel Analytics",
};

export const FRAMEWORK_DEPS: Record<string, string> = {
  next: "Next.js", react: "React", vue: "Vue", nuxt: "Nuxt", svelte: "Svelte", "@sveltejs/kit": "SvelteKit", astro: "Astro",
  express: "Express", fastify: "Fastify", hono: "Hono", koa: "Koa", "@nestjs/core": "NestJS", "@remix-run/node": "Remix",
  fastapi: "FastAPI", flask: "Flask", django: "Django", starlette: "Starlette", uvicorn: "Uvicorn", gunicorn: "Gunicorn",
  vite: "Vite", expo: "Expo", electron: "Electron", trpc: "tRPC", "@trpc/server": "tRPC", graphql: "GraphQL",
  "apollo-server": "Apollo Server", "@apollo/server": "Apollo Server", "spring-boot": "Spring Boot", rails: "Rails",
  gin: "Gin", "github.com/gin-gonic/gin": "Gin", "github.com/labstack/echo": "Echo", "github.com/gofiber/fiber": "Fiber",
};

/** docker image / terraform resource -> datastore */
export const IMAGE_DATASTORES: [RegExp, string, "datastore" | "queue"][] = [
  [/postgres|timescale|pgvector|supabase\/postgres/i, "PostgreSQL", "datastore"],
  [/mysql|mariadb/i, "MySQL", "datastore"], [/mongo/i, "MongoDB", "datastore"], [/redis|valkey|keydb/i, "Redis", "datastore"],
  [/elasticsearch|opensearch/i, "Elasticsearch", "datastore"], [/minio|localstack/i, "Object storage", "datastore"],
  [/clickhouse/i, "ClickHouse", "datastore"], [/cassandra|scylla/i, "Cassandra", "datastore"],
  [/rabbitmq/i, "RabbitMQ", "queue"], [/kafka|redpanda/i, "Kafka", "queue"], [/nats/i, "NATS", "queue"],
];

export const TF_RESOURCES: [RegExp, string, "datastore" | "queue" | "service" | "external"][] = [
  [/^aws_(db_instance|rds_cluster)$/, "RDS database", "datastore"], [/^aws_dynamodb_table$/, "DynamoDB table", "datastore"],
  [/^aws_s3_bucket$/, "S3 bucket", "datastore"], [/^aws_elasticache/, "ElastiCache", "datastore"],
  [/^aws_sqs_queue$/, "SQS queue", "queue"], [/^aws_sns_topic$/, "SNS topic", "queue"],
  [/^aws_lambda_function$/, "Lambda function", "service"], [/^aws_(ecs_service|eks_cluster|apprunner_service)$/, "Container service", "service"],
  [/^aws_(lb|alb|api_gateway_rest_api|apigatewayv2_api)$/, "Load balancer / API gateway", "service"],
  [/^google_sql_database_instance$/, "Cloud SQL", "datastore"], [/^google_storage_bucket$/, "GCS bucket", "datastore"],
  [/^google_cloud_run/, "Cloud Run service", "service"], [/^google_pubsub_topic$/, "Pub/Sub topic", "queue"],
  [/^azurerm_(postgresql|mysql|mssql|cosmosdb)/, "Azure database", "datastore"], [/^azurerm_storage_account$/, "Azure storage", "datastore"],
  [/^azurerm_(linux|windows)_web_app$|^azurerm_container_app$/, "Azure app", "service"],
  [/^vercel_project$/, "Vercel project", "service"], [/^cloudflare_(worker|pages)/, "Cloudflare app", "service"],
];
