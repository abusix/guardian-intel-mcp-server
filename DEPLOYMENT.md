# Deployment Guide

This document describes the automated deployment and CI/CD processes for the Guardian Intel MCP Server.

## 🚀 GitHub Actions Workflows

### 1. **CI Workflow** (`.github/workflows/ci.yml`)

**Triggers:** Push to `main`/`develop`, Pull Requests to `main`

**Jobs:**
- **Multi-platform Testing** - Tests on Ubuntu, Windows, macOS
- **Multi-version Testing** - Node.js 18.x, 20.x, 22.x
- **Security Auditing** - npm audit and vulnerability scanning
- **Package Testing** - NPX installation and functionality tests
- **Coverage Reporting** - Codecov integration

### 2. **Release Workflow** (`.github/workflows/release.yml`)

**Triggers:** Git tags matching `v*` (e.g., `v1.0.0`)

**Process:**
1. Run comprehensive tests
2. Build and validate package
3. Publish to NPM with production tag
4. Create GitHub release with detailed changelog
5. Upload package artifacts

### 3. **Deploy Workflow** (`.github/workflows/deploy.yml`)

**Triggers:** Manual dispatch with environment selection

**Environments:**
- **Staging** - Publishes with `@beta` tag for testing
- **Production** - Publishes to latest tag after full validation

### 4. **Quality Gate** (`.github/workflows/quality-gate.yml`)

**Triggers:** Pull Requests and pushes to `main`

**Checks:**
- Code quality (ESLint, TypeScript strict mode)
- Test coverage thresholds
- Security scanning
- Performance benchmarks
- Cross-platform compatibility

### 5. **Nightly Build** (`.github/workflows/nightly.yml`)

**Triggers:** Daily at 2 AM UTC, manual dispatch

**Purpose:**
- Continuous integration health monitoring
- Dependency compatibility testing
- Performance regression detection

### 6. **Dependency Updates** (`.github/workflows/dependency-update.yml`)

**Triggers:** Weekly on Mondays, manual dispatch

**Features:**
- Automated patch/minor version updates
- Full test suite validation
- Auto-merge for safe updates
- Manual review alerts for major updates

## 📋 Prerequisites

### Required GitHub Secrets

Set these in your GitHub repository settings (`Settings > Secrets and variables > Actions`):

| Secret | Purpose | How to Get |
|--------|---------|------------|
| `NPM_TOKEN` | NPM package publishing | [Generate at npmjs.com](https://www.npmjs.com/settings/tokens) |
| `CODECOV_TOKEN` | Code coverage reporting | [Sign up at codecov.io](https://codecov.io/) |
| `CC_TEST_REPORTER_ID` | CodeClimate integration | [Get from codeclimate.com](https://codeclimate.com/) |
| `SNYK_TOKEN` | Security vulnerability scanning | [Generate at snyk.io](https://snyk.io/) |

### NPM Publishing Setup

1. **Create NPM Account:** Sign up at [npmjs.com](https://www.npmjs.com/)
2. **Generate Access Token:**
   ```bash
   npm login
   npm token create --type=automation
   ```
3. **Add Token to GitHub Secrets** as `NPM_TOKEN`
4. **Verify Package Scope:** Ensure `@abusix/guardian-intel-mcp-server` is available

## 🔄 Deployment Process

### Automated Release (Recommended)

1. **Create a Release Tag:**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. **GitHub Actions will automatically:**
   - Run full test suite
   - Build the package
   - Publish to NPM
   - Create GitHub release
   - Notify completion

### Manual Deployment

For staging or custom deployments:

1. **Go to GitHub Actions**
2. **Select "Deploy" workflow**
3. **Click "Run workflow"**
4. **Choose environment:** staging or production
5. **Optional:** Specify version number

### Emergency Deployment

For urgent fixes:

```bash
# Quick patch release
npm version patch
git push origin main --tags

# The release workflow will trigger automatically
```

## 📊 Deployment Verification

### Automated Checks

Each deployment includes automatic verification:

- ✅ Package installation via NPX
- ✅ CLI functionality testing
- ✅ Help command validation
- ✅ Error handling verification

### Manual Verification

After deployment, verify:

```bash
# Test NPX installation
npx @abusix/guardian-intel-mcp-server --help

# Test with API key
export ABUSIX_API_KEY="your-key"
npx @abusix/guardian-intel-mcp-server --debug

# Verify NPM package page
open https://www.npmjs.com/package/@abusix/guardian-intel-mcp-server
```

## 🔍 Monitoring & Alerts

### Automated Monitoring

- **Nightly builds** ensure continuous health
- **Dependency scanning** alerts for vulnerabilities
- **Performance benchmarks** track regression
- **Quality gates** prevent broken deployments

### Manual Monitoring

Monitor these metrics:

1. **NPM Download Stats:** https://npmjs.com/package/@abusix/guardian-intel-mcp-server
2. **GitHub Actions:** Check workflow success rates
3. **Issue Reports:** Monitor GitHub issues for deployment problems
4. **Security Alerts:** Review Dependabot and Snyk reports

## 🚨 Troubleshooting

### Common Deployment Issues

**NPM Publish Fails:**
```bash
# Check if version already exists
npm view @abusix/guardian-intel-mcp-server versions --json

# Increment version
npm version patch
```

**Tests Fail in CI:**
- Check dependency compatibility
- Verify Node.js version requirements
- Review test environment differences

**Security Audit Failures:**
```bash
# Update vulnerable dependencies
npm audit fix

# For breaking changes, update manually
npm update package-name
```

### Rollback Process

If a deployment needs rollback:

1. **Unpublish problematic version** (within 72 hours):
   ```bash
   npm unpublish @abusix/guardian-intel-mcp-server@1.0.1
   ```

2. **Or deprecate the version:**
   ```bash
   npm deprecate @abusix/guardian-intel-mcp-server@1.0.1 "Use version 1.0.0 instead"
   ```

3. **Publish fixed version:**
   ```bash
   npm version patch
   git push origin main --tags
   ```

## 📈 Deployment Metrics

Track these KPIs:

- **Deployment Frequency:** Target weekly releases
- **Lead Time:** Commit to production < 1 hour
- **Failure Rate:** < 5% deployment failures
- **Recovery Time:** < 30 minutes for rollbacks

## 🔐 Security Considerations

### Deployment Security

- All secrets are stored in GitHub Secrets (encrypted)
- NPM tokens have automation-only permissions
- Release signatures verify package integrity
- Dependencies are regularly audited and updated

### Access Controls

- Only repository maintainers can trigger manual deployments
- Automated deployments require passing quality gates
- Production deployments require successful staging validation

---

## 📞 Support

For deployment issues:

1. **Check GitHub Actions logs** for detailed error information
2. **Review this documentation** for common solutions
3. **Create GitHub issue** for persistent problems
4. **Contact maintainers** for urgent deployment needs

The automated deployment system is designed to be reliable and self-healing, with multiple validation layers to ensure quality and security.