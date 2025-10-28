# AppSec-Sentinel Setup

AI-powered security scanner for any programming language. Detects vulnerabilities and can create fix PRs.

## Quick Setup (3 steps)

### 1. Add Workflow
```bash
cp security-scan.yml .github/workflows/
```

### 2. Configure Credentials

**AWS Bedrock (Recommended)**

Go to **Settings → Secrets → Actions** and add:
- `AWS_ACCESS_KEY_ID` - Your AWS access key
- `AWS_SECRET_ACCESS_KEY` - Your AWS secret key
- `AWS_REGION` - e.g., `us-east-1` (must match inference profile region)
- `INFERENCE_PROFILE_ID` - Bedrock model ARN (e.g., `arn:aws:bedrock:us-east-2:...`)

> ⚠️ **AWS_REGION must match the region in INFERENCE_PROFILE_ID** or AI fixes will fail

**OpenAI (Alternative)** - Less recommended for client data

Add secret `OPENAI_API_KEY`, then edit `security-scan.yml`:
```yaml
ai-provider: 'openai'
openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

### 3. Commit and Push
```bash
git add .github/workflows/security-scan.yml
git commit -m "Add AppSec-Sentinel security scanning"
git push
```

## What You Get

- ✅ **Automated scans** on every PR
- ✅ **AI-generated fixes** for code vulnerabilities
- ✅ **Separate PRs** for code fixes vs dependency updates
- ✅ **HTML reports** with business impact analysis
- ✅ **Auto SBOM** (CycloneDX & SPDX) for compliance
- ✅ **Artifacts** - Reports and SBOM files (90-day retention)

## Configuration Options

Default settings (customize in `security-scan.yml`):
```yaml
with:
  ai-provider: 'aws_bedrock'     # Or 'openai'
  scan-level: 'critical-high'    # Or 'all' (affects security findings only)
  auto-fix: 'true'               # Generate fix PRs
  auto-fix-mode: '3'             # 1=SAST, 2=deps, 3=both, 4=none
  fail-on-critical: 'false'      # Don't break CI by default

# Note: Code quality findings are ALWAYS shown regardless of scan-level
```

## Supported Languages & Frameworks

**Languages**: JavaScript, Python, Java, Go, Rust, C#, Ruby, PHP, Swift, Kotlin, TypeScript

**Frameworks**: Express, Spring, Django, Rails, Laravel, ASP.NET, React, Vue, Angular

**Scanners**: Semgrep (SAST + code quality), Gitleaks (secrets), Trivy (dependencies)

**Code Quality**: Always reported regardless of scan level - continuous value from every scan

**Cross-File Analysis**: Multi-file vulnerability analysis and attack chain detection

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No PR created | Verify `contents: write` and `pull-requests: write` in Settings → Actions → Workflow permissions |
| AI fix failed | Check AWS_REGION matches INFERENCE_PROFILE_ID region |
| Scan timeout | Large repo? Try `scan-level: 'critical-high'` to reduce findings |
| No artifacts | Check Actions tab → workflow run → Artifacts section (90-day retention) |

## Support

For issues and contributions, visit the GitHub repository.

---

**MIT Licensed - Open Source Security Scanner**
