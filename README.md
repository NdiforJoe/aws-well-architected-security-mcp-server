# AWS Well-Architected Security MCP Server

A **production-ready Model Context Protocol (MCP) server** that enables AI assistants (such as Claude) to perform real-time, automated assessments of AWS environments against the **AWS Well-Architected Framework Security Pillar**.

Built for **GRC engineering** (governance, risk, compliance) and **DevSecOps** professionals, this server provides continuous security posture monitoring, compliance evidence generation, operational risk reporting, and cost-effective security optimization — all accessible via natural language queries.

## Why This Tool Matters

Manual security reviews are infrequent, time-consuming, and audit-heavy. This MCP server transforms them into **continuous, automated, agent-driven processes**:

- Delivers **operational excellence** in production environments
- Supports **ongoing compliance monitoring** for SOC 2 Type 2, ISO 27001, NIST SP 800-53, and CIS Benchmarks
- Integrates with **Security Operations Centers (SOC)** for real-time visibility and incident response
- Enables **cost-effective security** by monitoring service usage and recommending optimizations
- Provides **structured, audit-ready evidence** for compliance teams and stakeholders

## Core MCP Tools & Operational Benefits

The server exposes powerful tools for security operations:

- **CheckSecurityServices**  
  Monitors operational status of AWS security services (GuardDuty, Security Hub, Inspector, IAM Access Analyzer) across regions. Identifies coverage gaps and provides recommendations.

- **GetSecurityFindings**  
  Retrieves and analyzes security findings from Security Hub, GuardDuty, and Inspector. Filters by severity/resource/service with cost-effective remediation guidance.

- **GetResourceComplianceStatus**  
  Continuously monitors resource compliance against security standards. Identifies non-compliant resources for remediation.

- **GetStoredSecurityContext**  
  Accesses historical security data for trend analysis and posture comparison over time.

- **ExploreAwsResources**  
  Discovers and inventories AWS resources across services/regions for complete visibility and cost optimization.

- **AnalyzeSecurityPosture**  
  Comprehensive evaluation against the Well-Architected Security Pillar. Delivers prioritized action items, metrics, and operational recommendations.

These tools support:
- Production security monitoring
- Compliance & audit reporting
- SOC integration
- Cost optimization
- Operational dashboards

## Example Prompts for Real-World Use

### Security Operations Monitoring
- "Monitor the operational status of AWS security services across my account"
- "Generate an operational security report against the Well-Architected Security Pillar"
- "Show me current security findings that require operational attention"
- "Monitor encryption compliance across my S3 buckets for operational reporting"
- "Verify network encryption compliance for operational security standards"

### Operational Resource Management
- "Provide an operational inventory of all resources in my AWS account"
- "Identify resources with security issues that need operational attention"
- "List all EC2 instances across regions for security operations review"
- "Monitor which resources are not compliant with operational security standards"

### Security Operations Analysis
- "Analyze operational security posture against Well-Architected best practices"
- "What security improvements should operations prioritize for cost optimization?"
- "Compare current security operations metrics with last month's operational baseline"
- "Generate an operational security dashboard for management reporting"
- "Monitor security service costs and recommend optimization opportunities"

## Security Controls & IAM Best Practices

**Critical: Always use least-privilege permissions.**

The server accesses sensitive AWS security services (GuardDuty, Security Hub, Inspector, Access Analyzer, Macie, etc.). To minimize risk and align with compliance (NIST CSF PR.AC-6, SOC 2 CC6.1), follow these best practices:

1. Create a **dedicated IAM role** specifically for security assessment operations
2. Apply **least-privilege permissions** — attach only read-only policies
3. Use **scoped-down resource policies** wherever possible
4. Apply a **permission boundary** to limit the maximum permissions

### Step-by-Step: Create the Least-Privilege IAM Role

1. **Log in to AWS IAM Console**  
   https://console.aws.amazon.com/iam/

2. **Create a Read-Only Policy**  
   - Policies → Create policy → JSON tab  
   - Paste this policy:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Effect": "Allow",
           "Action": [
             "guardduty:Get*",
             "guardduty:List*",
             "securityhub:Describe*",
             "securityhub:Get*",
             "securityhub:List*",
             "inspector2:Describe*",
             "inspector2:Get*",
             "inspector2:List*",
             "accessanalyzer:Get*",
             "accessanalyzer:List*",
             "macie2:Describe*",
             "macie2:Get*",
             "macie2:List*",
             "support:Describe*",
             "ec2:Describe*",
             "s3:GetBucket*",
             "s3:List*",
             "kms:Describe*",
             "kms:Get*",
             "kms:List*",
             "cloudtrail:Describe*",
             "cloudtrail:Get*",
             "cloudtrail:List*",
             "config:Describe*",
             "config:Get*",
             "config:List*",
             "iam:Get*",
             "iam:List*"
           ],
           "Resource": "*"
         }
       ]
     }

Name: MCP-SecurityAssessment-ReadOnlyPolicy


Create the IAM Role
Roles → Create role
Trusted entity: AWS service (Lambda recommended)
Attach the policy
Name: MCP-SecurityAssessment-Role

(Optional) Add Permission Boundary
Create a boundary policy with Deny for write/modify actions
Attach to the role

Use the Role
Local: AWS_PROFILE=mcp-assessment uvx awslabs.well-architected-security-mcp-server@latest
Lambda: Attach the role to the function


Never use AdministratorAccess or root credentials.

Project Structure

.
├── src/
│   ├── __init__.py
│   ├── main.py               # FastAPI MCP server entrypoint
│   ├── checks.py             # AWS security check logic
│   └── mappings.py           # NIST CSF 2.0 & SOC 2 mapping logic
├── tests/
│   ├── unit/
│   │   ├── __init__.py
│   │   ├── test_checks.py
│   │   └── test_mappings.py
│   └── README.md             # Testing guide
├── scripts/
│   ├── run_tests.sh          # Run full test suite
│   └── deploy.sh             # Optional deployment helper
├── templates/
│   └── security-mcp-server.yaml   # CloudFormation template for Lambda + API Gateway
├── .github/workflows/
│   └── ci-cd.yml             # GitHub Actions: tests & deployment
├── Dockerfile                # Containerized local/testing
├── requirements.txt
├── .gitignore
└── LICENSE (MIT)

Requirements

Python 3.10+
AWS credentials with read-only permissions (use the role above)
uv (from Astral): https://astral.sh/uv

Testing
Comprehensive test suite using pytest + mocks (no real AWS calls).
Run tests:

chmod +x scripts/run_tests.sh
./scripts/run_tests.sh

See tests/README.md for details.

Quick Start
1. Local Run
   
   Bash
   uvx awslabs.well-architected-security-mcp-server@latest
2. Connect in Claude Code

   text
   /mcp add aws-security http://localhost:8000

3. Run Assessment

   text
   Using the aws-security MCP server, run a full AWS Well-Architected Security Pillar assessment on my account. Focus on IAM, logging, and network security.

License
MIT

Credits
Original core tools and concept by AWS Labs (Well-Architected Security MCP Server).
Enhanced for GRC engineering and DevSecOps use cases.
