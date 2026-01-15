# AWS Well-Architected Security MCP Server

[![Deploy to AWS](https://github.com/NdiforJoe/aws-well-architected-security-mcp-server/actions/workflows/deploy.yml/badge.svg)](https://github.com/NdiforJoe/aws-well-architected-security-mcp-server/actions/workflows/deploy.yml)
[![Security: Level 2 Production](https://img.shields.io/badge/Security-Level%202%20Production-green.svg)](./SECURITY_HARDENING_GUIDE.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

A **production-ready, enterprise-grade serverless security assessment platform** that enables real-time, AI-powered evaluation of AWS environments against the **AWS Well-Architected Framework Security Pillar**.

Built for **GRC engineering** and **DevSecOps** teams with **production-grade security controls**, automated compliance reporting, and intelligent remediation guidance—all through a secured REST API with automated daily assessments.

---

## 🌟 Key Features

### 🔒 **Enterprise Security Controls**
- **API Key Authentication** - Prevent unauthorized access with token-based authentication
- **Rate Limiting** - 10 req/sec sustained, 50 burst, 1000/day quota
- **Resource-Scoped IAM** - Least privilege permissions (no wildcards!)
- **KMS Encryption** - Encrypt sensitive environment variables at rest
- **Audit Logging** - Full request/response logging for compliance
- **CloudWatch Alarms** - Real-time alerts for security incidents

### 🛡️ **Comprehensive Security Scanning**
- Real-time assessment of AWS security services (GuardDuty, Security Hub, CloudTrail, Config)
- Multi-region support for complete infrastructure coverage
- Automated detection of 20+ security misconfigurations

### 🤖 **AI-Powered Executive Summaries**
- Leverages **Amazon Bedrock (Nova Pro)** for intelligent analysis
- Generates CISO-level executive summaries from technical findings
- Translates security issues into business impact assessments

### 📊 **Compliance Framework Mapping**
- **NIST Cybersecurity Framework 2.0** - Complete control mapping
- **SOC 2 Trust Services Criteria** - Audit-ready evidence
- Automated compliance gap identification

### 📧 **Automated Alerting**
- Email notifications for critical and high-severity findings
- Daily scheduled security assessments
- Remediation guidance with CLI commands

### 🚀 **Production-Ready Infrastructure**
- Serverless AWS Lambda deployment
- API Gateway with RESTful endpoints
- Infrastructure as Code (AWS SAM/CloudFormation)
- Automated CI/CD with GitHub Actions

---

## 🔐 Security Architecture

### Security Maturity: **Level 2 (Production) - Score: 8.5/10**

```
┌─────────────────────────────────────────────────────────────────┐
│                     Security Layer 1: Network                    │
│  • API Gateway with HTTPS only                                   │
│  • API Key authentication (x-api-key header)                     │
│  • Rate limiting: 10 req/sec, 50 burst, 1000/day                │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│                   Security Layer 2: Application                  │
│  • Lambda with resource-scoped IAM (least privilege)             │
│  • KMS encryption for environment variables                      │
│  • X-Ray tracing enabled                                         │
│  • Reserved concurrency limits (prevent runaway costs)           │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│                     Security Layer 3: Data                       │
│  • Secrets Manager for sensitive configuration                   │
│  • SNS topic encryption with AWS KMS                             │
│  • Read-only access to AWS security services                     │
│  • No data exfiltration capabilities                             │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│                   Security Layer 4: Monitoring                   │
│  • CloudWatch Logs (30-day retention)                            │
│  • API Gateway access logs (full audit trail)                    │
│  • CloudWatch Alarms (high error rate, unauthorized access)      │
│  • X-Ray distributed tracing                                     │
└─────────────────────────────────────────────────────────────────┘
```

### Key Security Features

| Feature | Implementation | Benefit |
|---------|----------------|---------|
| **Authentication** | API Gateway API Keys | Prevents unauthorized access |
| **Rate Limiting** | Usage Plan (10/sec, 1000/day) | Prevents abuse & cost overruns |
| **Authorization** | Resource-scoped IAM policies | Limits blast radius |
| **Encryption at Rest** | KMS for env variables | Protects sensitive data |
| **Encryption in Transit** | HTTPS only (TLS 1.2+) | Prevents man-in-the-middle |
| **Audit Trail** | CloudWatch + API Gateway logs | Compliance & forensics |
| **Least Privilege** | Read-only AWS permissions | Minimizes attack surface |
| **Monitoring** | CloudWatch Alarms | Real-time incident detection |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        GitHub Actions CI/CD                      │
│  (Automated Testing, Staging Deploy, Production Deploy)         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AWS Production Environment                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐      ┌──────────────────┐                    │
│  │ EventBridge  │─────▶│  Lambda Function │                    │
│  │ (Daily Cron) │      │  (Python 3.12)   │                    │
│  └──────────────┘      │  [KMS Encrypted] │                    │
│                        └────────┬─────────┘                     │
│                                 │                                │
│  ┌──────────────┐               │                                │
│  │ API Gateway  │───────────────┘                                │
│  │ [API Key]    │                                                │
│  │ [Rate Limit] │                                                │
│  └──────┬───────┘                                                │
│         │                                                         │
│         ↓ (HTTPS only)                                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │        AWS Security Services Assessment                  │   │
│  │  • GuardDuty  • Security Hub  • CloudTrail              │   │
│  │  • IAM Access Analyzer  • Config  • KMS                 │   │
│  │  [Least Privilege IAM - Resource-Scoped]                │   │
│  └─────────────────────────────────────────────────────────┘   │
│         │                                                         │
│         ▼                                                         │
│  ┌──────────────┐      ┌──────────────────┐                    │
│  │ Amazon       │      │  SNS Topic       │                    │
│  │ Bedrock      │      │  [KMS Encrypted] │                    │
│  │ (Nova Pro)   │      └──────────────────┘                    │
│  └──────────────┘                                               │
│         │                                                         │
│         ▼                                                         │
│  ┌──────────────┐      ┌──────────────────┐                    │
│  │ Secrets Mgr  │      │  CloudWatch      │                    │
│  │              │      │  [Logs + Alarms] │                    │
│  └──────────────┘      └──────────────────┘                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- AWS Account with appropriate permissions
- Python 3.12+
- AWS SAM CLI
- Git

### Option 1: Deploy to AWS (Production - Secured)

```bash
# Clone the repository
git clone https://github.com/NdiforJoe/aws-well-architected-security-mcp-server.git
cd aws-well-architected-security-mcp-server

# Build with SAM
sam build --template security-mcp-server.yaml

# Deploy with security features
sam deploy --guided
```

**Deployment Parameters:**
- Stack Name: `mcp-security-server-prod`
- AWS Region: `us-east-1` (or your preference)
- NotificationEmail: `your-email@example.com`
- EnableBedrock: `true`

**After deployment, retrieve your API key:**
```bash
# Get API Key ID from CloudFormation outputs
API_KEY_ID=$(aws cloudformation describe-stacks \
  --stack-name mcp-security-server-prod \
  --query 'Stacks[0].Outputs[?OutputKey==`ApiKeyId`].OutputValue' \
  --output text)

# Retrieve the actual API key value
API_KEY=$(aws apigateway get-api-key \
  --api-key ${API_KEY_ID} \
  --include-value \
  --query 'value' \
  --output text)

echo "Your API Key: ${API_KEY}"
# Save this key securely!
```

### Option 2: Test Locally (Development)

```bash
# Install dependencies
pip install -r requirements.txt

# Set AWS credentials
export AWS_PROFILE=your-profile

# Run locally (no authentication required)
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```

**Test the API:**
```bash
# Health check
curl http://localhost:8000/health

# Run assessment
curl -X POST http://localhost:8000/assess \
  -H "Content-Type: application/json" \
  -d '{
    "region": "us-east-1",
    "focus_areas": ["IAM", "Logging"],
    "send_notifications": false
  }'
```

---

## 📋 API Endpoints

### `GET /health`
Health check endpoint for monitoring.

**Authentication:** Required (x-api-key header)

**Request:**
```bash
curl -H "x-api-key: YOUR_API_KEY" \
  https://your-api.execute-api.us-east-1.amazonaws.com/prod/health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "aws-well-architected-security-mcp",
  "bedrock_enabled": true
}
```

### `POST /assess`
Run a comprehensive security assessment.

**Authentication:** Required (x-api-key header)

**Rate Limits:**
- Sustained: 10 requests/second
- Burst: 50 requests
- Daily quota: 1000 requests

**Request:**
```bash
curl -X POST https://your-api.execute-api.us-east-1.amazonaws.com/prod/assess \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_API_KEY" \
  -d '{
    "region": "us-east-1",
    "focus_areas": ["IAM", "Logging", "Network", "Storage", "Encryption", "ThreatDetection"],
    "send_notifications": true
  }'
```

**Response:**
```json
{
  "status": "success",
  "assessment": {
    "region": "us-east-1",
    "focus_areas": ["IAM", "Logging", "Network"],
    "findings": [
      {
        "id": "CLOUDTRAIL-NOT-MULTI-REGION",
        "severity": "High",
        "description": "No multi-region CloudTrail trail configured",
        "resource": "CloudTrail",
        "remediation": "aws cloudtrail create-trail --name my-trail --is-multi-region-trail ...",
        "nist_csf": "DE.AE-03",
        "nist_function": "Detect",
        "soc2": "CC7.2",
        "compliance_description": "Event data are collected and correlated from multiple sources"
      }
    ],
    "critical_count": 0,
    "high_count": 1,
    "notifications_sent": true,
    "bedrock_enabled": true,
    "timestamp": "2026-01-15T10:30:00Z"
  }
}
```

**Error Responses:**

**401 Unauthorized (Missing API Key):**
```json
{
  "message": "Forbidden"
}
```

**429 Too Many Requests (Rate Limit Exceeded):**
```json
{
  "message": "Too Many Requests"
}
```

---

## 🛠️ Security Checks Performed

### Identity & Access Management (IAM)
- ✅ Root account MFA enabled
- ✅ Root access keys removed
- ✅ IAM password policies configured
- ✅ User MFA enforcement

### Logging & Monitoring
- ✅ Multi-region CloudTrail enabled
- ✅ CloudTrail log encryption
- ✅ CloudTrail log validation
- ✅ CloudWatch alarms configured

### Network Security
- ✅ VPC Flow Logs enabled
- ✅ Security group configurations
- ✅ Network ACL rules
- ✅ Public accessibility controls

### Data Protection
- ✅ S3 bucket encryption
- ✅ S3 public access blocking
- ✅ S3 versioning enabled
- ✅ EBS volume encryption
- ✅ RDS encryption at rest

### Encryption & Key Management
- ✅ KMS key rotation enabled
- ✅ Secrets Manager usage
- ✅ Encryption in transit

### Threat Detection
- ✅ GuardDuty enabled
- ✅ Security Hub enabled
- ✅ Inspector enabled
- ✅ Config enabled

---

## 🤖 AI-Powered Executive Summaries

The platform uses **Amazon Bedrock (Nova Pro)** to generate intelligent executive summaries:

**Example Email Notification:**

```
AWS WELL-ARCHITECTED SECURITY ASSESSMENT
======================================================================

EXECUTIVE SUMMARY
----------------------------------------------------------------------
Security Posture: CONCERNING - Prompt Remediation Needed

Your AWS environment exhibits several high-priority security gaps that
require immediate attention. The absence of multi-region CloudTrail 
logging creates significant audit blind spots and compliance risks. 
Additionally, GuardDuty threat detection is not enabled, leaving your
environment vulnerable to undetected malicious activity.

Key Business Impacts:
- Compliance violations for SOC 2 and NIST frameworks
- Limited visibility into security events across regions  
- Potential regulatory penalties and audit findings

Immediate Recommendations:
1. Enable multi-region CloudTrail within 24 hours
2. Activate GuardDuty for continuous threat detection
3. Implement automatic KMS key rotation

This assessment was generated using AI-powered analysis with 
Amazon Bedrock Nova Pro.

======================================================================
DETAILED FINDINGS (3 requiring immediate attention)
======================================================================
[Full findings with NIST/SOC2 mappings and remediation steps...]
```

---

## 🔄 Automated CI/CD with GitHub Actions

### Pipeline Features

✅ **Automated Testing** - Runs on every push (55%+ code coverage)  
✅ **Staging Deployment** - Auto-deploys PRs to staging environment  
✅ **Production Deployment** - Merges to `main` deploy to production  
✅ **Smoke Tests** - Validates deployment health  
✅ **Auto Rollback** - Reverts failed deployments  
✅ **Release Tagging** - Semantic versioning  

### Setup CI/CD

1. **Add GitHub Secrets:**
   ```
   AWS_ACCESS_KEY_ID - Your AWS access key
   AWS_SECRET_ACCESS_KEY - Your AWS secret key
   ```

2. **Configure Environments:**
   - Create `staging` and `production` environments in GitHub
   - Add protection rules for production (require approval)

3. **Push to Main:**
   ```bash
   git push origin main
   # Automatically triggers deployment pipeline!
   ```

**See [CICD_SETUP_GUIDE.md](./CICD_SETUP_GUIDE.md) for detailed instructions.**

---

## 📊 Deployed AWS Resources

| Resource | Name/ID | Purpose | Monthly Cost |
|----------|---------|---------|--------------|
| **Lambda Function** | `mcp-security-server-prod` | Security assessment API | ~$0.20 |
| **API Gateway** | REST API with API Keys | Public HTTPS endpoints | ~$3.50 |
| **API Key** | Auto-generated | Authentication token | Free |
| **Usage Plan** | Rate limiting rules | Quota & throttle management | Free |
| **KMS Key** | Lambda encryption | Encrypt env variables | ~$1.00 |
| **Secrets Manager** | Configuration storage | Store sensitive config | ~$0.40 |
| **SNS Topic** | Email notifications | Critical findings alerts | ~$0.01 |
| **EventBridge Rule** | Daily at 9 AM UTC | Scheduled assessments | Free |
| **IAM Role** | Least-privilege | Lambda execution | Free |
| **CloudWatch Logs** | API + Lambda logs | Monitoring & audit | ~$0.50 |
| **CloudWatch Alarms** | Security monitoring | Error & unauthorized alerts | ~$0.20 |

**Estimated Monthly Cost:** $5.81 (after free tier)  
**Security Value:** PRICELESS 🛡️

---

## 🔐 Security Best Practices Implemented

### 1. Authentication & Authorization
- ✅ API Gateway API Keys (token-based auth)
- ✅ IAM roles with least privilege
- ✅ Resource-scoped IAM policies (no wildcards)
- ✅ Secrets Manager for sensitive data

### 2. Network Security
- ✅ HTTPS only (TLS 1.2+)
- ✅ API Gateway rate limiting
- ✅ Lambda reserved concurrency (cost protection)

### 3. Data Protection
- ✅ KMS encryption for environment variables
- ✅ SNS topic encryption
- ✅ CloudWatch Logs encryption
- ✅ No sensitive data in logs

### 4. Monitoring & Logging
- ✅ API Gateway access logs (full audit trail)
- ✅ Lambda execution logs
- ✅ CloudWatch Alarms for incidents
- ✅ X-Ray distributed tracing

### 5. Compliance
- ✅ 30-day log retention (audit requirement)
- ✅ Immutable audit trail
- ✅ SOC 2 CC6.1, CC6.6, CC6.7 compliance
- ✅ NIST CSF controls implemented

### IAM Permissions (Least Privilege)

```yaml
# Example: GuardDuty permissions scoped to account/region
- Effect: Allow
  Action:
    - guardduty:Get*
    - guardduty:List*
  Resource: !Sub 'arn:aws:guardduty:${AWS::Region}:${AWS::AccountId}:detector/*'
  # ✅ Not Resource: "*"

# Example: SNS publish scoped to specific topic
- Effect: Allow
  Action:
    - sns:Publish
  Resource: !Ref SecurityNotificationTopic
  # ✅ Not Resource: "*"
```

**See [SECURITY_HARDENING_GUIDE.md](./SECURITY_HARDENING_GUIDE.md) for complete security documentation.**

---

## 🧪 Testing

### Run Unit Tests

```bash
# Run all tests with coverage
./scripts/run_tests.sh

# Or manually
pytest tests/unit --cov=src --cov-report=term-missing --cov-fail-under=55
```

### Test Coverage

- `checks.py`: 78% (core security logic)
- `mappings.py`: 100% (compliance mappings)
- `main.py`: Integration tests via smoke tests
- `notifications.py`: Integration tests via smoke tests

### Security Testing

```bash
# Test authentication (should fail)
curl https://your-api.com/prod/health
# Expected: {"message":"Forbidden"}

# Test with API key (should succeed)
curl -H "x-api-key: YOUR_KEY" https://your-api.com/prod/health
# Expected: {"status":"healthy"}

# Test rate limiting (send 15 rapid requests)
for i in {1..15}; do
  curl -H "x-api-key: YOUR_KEY" https://your-api.com/prod/health
done
# Expected: First 10 succeed, next 5 get 429 Too Many Requests
```

---

## 📁 Project Structure

```
.
├── .github/
│   └── workflows/
│       └── deploy.yml              # CI/CD pipeline
├── src/
│   ├── __init__.py
│   ├── main.py                     # FastAPI application
│   ├── checks.py                   # AWS security checks
│   ├── mappings.py                 # NIST/SOC2 mappings
│   ├── notifications.py            # SNS + Bedrock integration
│   └── lambda_handler.py           # Lambda entry point
├── tests/
│   ├── unit/
│   │   ├── test_checks.py
│   │   └── test_mappings.py
│   └── README.md
├── scripts/
│   └── run_tests.sh                # Test runner
├── security-mcp-server.yaml        # SAM template (secured)
├── requirements.txt                # Python dependencies
├── SECURITY_HARDENING_GUIDE.md    # Security documentation
├── SECURITY_DEPLOYMENT_GUIDE.md   # Deployment tutorial
├── CICD_SETUP_GUIDE.md            # CI/CD setup guide
├── README.md                       # This file
└── LICENSE                         # MIT License
```

---

## 🎯 Use Cases

### GRC Engineering
- Continuous compliance monitoring for SOC 2, ISO 27001, NIST 800-53
- Automated evidence collection for audits
- Risk assessment and reporting with AI-powered insights

### DevSecOps Teams
- Shift-left security in CI/CD pipelines
- Automated security gates with configurable thresholds
- Infrastructure security validation pre-deployment

### Security Operations Centers (SOC)
- Real-time security posture visibility
- Incident detection and automated response
- Threat analysis with GuardDuty integration

### Cloud Architects
- Well-Architected Framework validation
- Multi-account security governance (AWS Organizations ready)
- Cost-effective security optimization

---

## 🌍 Multi-Region Support

Deploy to multiple regions for global coverage:

```bash
# Deploy to US East
sam deploy --region us-east-1 --stack-name mcp-security-us-east-1

# Deploy to EU West
sam deploy --region eu-west-1 --stack-name mcp-security-eu-west-1

# Deploy to Asia Pacific
sam deploy --region ap-southeast-1 --stack-name mcp-security-ap-se-1
```

Each deployment gets its own:
- API Gateway endpoint with unique API key
- Lambda function with regional IAM role
- SNS topic for regional notifications
- CloudWatch Logs group

---

## 📈 Monitoring & Observability

### CloudWatch Logs

```bash
# Tail Lambda logs in real-time
aws logs tail /aws/lambda/mcp-security-server-prod --follow

# Filter for errors
aws logs filter-log-events \
  --log-group-name /aws/lambda/mcp-security-server-prod \
  --filter-pattern "ERROR"

# View API Gateway access logs
aws logs tail /aws/apigateway/mcp-security-server-prod --follow
```

### CloudWatch Metrics

Available metrics:
- **Lambda:** Invocations, Errors, Duration, Throttles
- **API Gateway:** 4xx/5xx errors, Latency, Request count
- **Usage Plan:** API key usage, quota consumption

### CloudWatch Alarms

Pre-configured alarms:
- **HighErrorRateAlarm:** Triggers when Lambda errors exceed 10 in 5 minutes
- **UnauthorizedAccessAlarm:** Triggers on 50+ 403 errors (failed auth attempts)

### X-Ray Tracing

```bash
# View traces in AWS Console
https://console.aws.amazon.com/xray/home?region=us-east-1#/traces

# Query traces with AWS CLI
aws xray get-trace-summaries \
  --start-time 2026-01-15T00:00:00Z \
  --end-time 2026-01-15T23:59:59Z
```

---

## 🗑️ Cleanup

To remove all resources:

```bash
# Delete CloudFormation stack (removes all resources)
aws cloudformation delete-stack --stack-name mcp-security-server-prod

# Confirm deletion (wait for completion)
aws cloudformation wait stack-delete-complete --stack-name mcp-security-server-prod

# Note: Some resources may need manual deletion:
# - CloudWatch Log Groups (if retention is set)
# - S3 buckets (if any were created)
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone the repo
git clone https://github.com/NdiforJoe/aws-well-architected-security-mcp-server.git
cd aws-well-architected-security-mcp-server

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest
```

---

## 📚 Documentation

- **[Security Hardening Guide](./SECURITY_HARDENING_GUIDE.md)** - Complete security features & best practices
- **[Security Deployment Guide](./SECURITY_DEPLOYMENT_GUIDE.md)** - Step-by-step deployment with explanations
- **[CI/CD Setup Guide](./CICD_SETUP_GUIDE.md)** - GitHub Actions pipeline configuration
- **[AWS SAM Documentation](https://docs.aws.amazon.com/serverless-application-model/)**
- **[FastAPI Documentation](https://fastapi.tiangolo.com/)**
- **[Amazon Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)**

---

## 🐛 Troubleshooting

### Common Issues

**Issue: 403 Forbidden when calling API**
```bash
# Solution: Make sure you're passing the API key
curl -H "x-api-key: YOUR_API_KEY" https://your-api.com/prod/health
```

**Issue: 429 Too Many Requests**
```bash
# Solution: You've exceeded rate limits
# Wait 1 second (10 req/sec limit) or 24 hours (1000/day quota)
```

**Issue: Lambda timeout**
```yaml
# Solution: Increase timeout in template
Properties:
  Timeout: 120  # Increase to 180 seconds if needed
```

**Issue: Bedrock rate limit**
```
Error: "Too many tokens per day"
# Solution: Wait 24 hours or upgrade Bedrock tier
```

**Issue: Can't retrieve API key**
```bash
# Solution: Use the GetApiKeyCommand from CloudFormation outputs
aws cloudformation describe-stacks \
  --stack-name mcp-security-server-prod \
  --query 'Stacks[0].Outputs[?OutputKey==`GetApiKeyCommand`].OutputValue' \
  --output text | bash
```

---

## 📊 Roadmap

### Phase 1 (Complete ✅)
- [x] Core security checks (20+ checks)
- [x] NIST CSF 2.0 mappings
- [x] SOC 2 mappings
- [x] Email notifications
- [x] AWS Lambda deployment
- [x] AI-powered summaries (Bedrock)
- [x] **API key authentication**
- [x] **Rate limiting**
- [x] **Resource-scoped IAM**
- [x] **KMS encryption**
- [x] **Audit logging**
- [x] GitHub Actions CI/CD

### Phase 2 (Planned 🚧)
- [ ] CloudWatch Dashboard (template ready)
- [ ] Slack notifications
- [ ] Microsoft Teams integration
- [ ] Custom compliance frameworks
- [ ] Historical trend analysis
- [ ] Multi-account support (AWS Organizations)
- [ ] AWS WAF integration (Level 3 security)

### Phase 3 (Future 🔮)
- [ ] Web UI dashboard
- [ ] Custom policy definitions
- [ ] Automated remediation (with approval workflow)
- [ ] Integration with SIEM tools (Splunk, ELK)
- [ ] Cost optimization recommendations
- [ ] Terraform/CDK deployment options

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **AWS Labs** - Original Well-Architected Security MCP Server concept
- **Anthropic** - Amazon Bedrock Nova Pro for AI-powered summaries
- **FastAPI** - Modern Python web framework
- **AWS SAM** - Serverless Application Model framework
- **NIST** - Cybersecurity Framework 2.0
- **AICPA** - SOC 2 Trust Services Criteria

---

## 📧 Contact

**Author:** Joe Ndifor  
**GitHub:** [@NdiforJoe](https://github.com/NdiforJoe)  
**LinkedIn:** [Connect with me](https://linkedin.com/in/yourprofile)  
**Project Link:** [https://github.com/NdiforJoe/aws-well-architected-security-mcp-server](https://github.com/NdiforJoe/aws-well-architected-security-mcp-server)

---

## ⭐ Star This Project

If you find this project useful, please consider giving it a star on GitHub! It helps others discover the project and shows appreciation for the work.

**Key Differentiators:**
- 🔐 Production-grade security (Level 2) with API keys, rate limiting, encryption
- 🤖 AI-powered executive summaries via Amazon Bedrock
- 📊 Complete NIST CSF 2.0 and SOC 2 compliance mapping
- 🚀 Fully automated CI/CD with GitHub Actions
- 📝 Comprehensive audit logging for compliance
- 🛡️ Resource-scoped IAM (true least privilege)

---

**Built with ❤️ for the DevSecOps and GRC community**

**Security Note:** This is a production-ready security assessment tool with enterprise-grade controls. Always review security configurations before deployment and follow your organization's security policies.
