# Publishing Guide

This document explains how to publish the Guardian Intel MCP Server to NPM.

## Prerequisites

Before publishing, ensure you have:

1. **NPM Token**: Add `NPM_TOKEN` to GitHub repository secrets
   - Go to [NPM Access Tokens](https://www.npmjs.com/settings/tokens)
   - Create a new "Automation" token
   - Add it to GitHub repository secrets as `NPM_TOKEN`

2. **Package Access**: Ensure the NPM account has access to publish under the `@abusix` scope

## Publishing Methods

### Method 1: Automatic Publishing via GitHub Release

1. **Create a new release** on GitHub:
   ```bash
   # This will trigger automatic publishing
   gh release create v1.0.1 --title "Release v1.0.1" --notes "Bug fixes and improvements"
   ```

2. **Or use the Version Bump workflow**:
   - Go to Actions → Version Bump → Run workflow
   - Select bump type (patch/minor/major/prerelease)
   - This will create a tag and release, triggering automatic publishing

### Method 2: Manual Publishing via Workflow Dispatch

1. **Go to GitHub Actions** → Publish to NPM → Run workflow
2. **Options**:
   - Version: Leave empty to use current package.json version
   - Dry run: Check this to test without actually publishing

### Method 3: Local Publishing (Not Recommended)

```bash
# Build and test
npm run build
npm test

# Login to NPM
npm login

# Publish
npm publish --access public
```

## Publishing Workflow

The automated publishing process:

1. **Quality Checks**:
   - Runs all tests
   - Performs linting
   - Builds the project
   - Runs security audit

2. **Version Validation**:
   - Checks if version already exists on NPM
   - Prevents duplicate publishes

3. **Publishing**:
   - Publishes with `--access public`
   - Verifies the published package
   - Tests NPX installation

4. **Post-Publishing**:
   - Creates GitHub release (if triggered manually)
   - Provides usage instructions

## Version Management

### Semantic Versioning

- **Patch** (1.0.1): Bug fixes, security patches
- **Minor** (1.1.0): New features, backward compatible
- **Major** (2.0.0): Breaking changes
- **Prerelease** (1.1.0-beta.1): Pre-release versions

### Version Bump Workflow

Use the Version Bump workflow to:
- Automatically increment version numbers
- Update CHANGELOG.md
- Create Git tags
- Trigger publishing via release

## Testing the Published Package

After publishing, test the package:

```bash
# Test NPX usage
npx @abusix/guardian-intel-mcp-server --help

# Test with API key
ABUSIX_API_KEY=your-key npx @abusix/guardian-intel-mcp-server

# Test global installation
npm install -g @abusix/guardian-intel-mcp-server
guardian-intel-mcp-server --help
```

## Troubleshooting

### Common Issues

1. **NPM_TOKEN not set**:
   - Add the token to GitHub repository secrets
   - Ensure it's an "Automation" token with publish permissions

2. **Version already exists**:
   - Update version in package.json
   - Or use the Version Bump workflow

3. **Package access denied**:
   - Ensure NPM account has access to @abusix scope
   - Contact organization admin if needed

4. **Build failures**:
   - Check that all tests pass locally
   - Ensure TypeScript compilation succeeds
   - Verify all required files are in dist/

### Security Considerations

- **Never commit NPM tokens** to the repository
- **Use scoped packages** (@abusix/package-name) for organization packages
- **Run security audits** before publishing
- **Review package contents** to avoid including sensitive files

## Package Distribution

Once published, users can access the package via:

```bash
# Direct NPX execution
npx @abusix/guardian-intel-mcp-server

# Global installation
npm install -g @abusix/guardian-intel-mcp-server

# In Claude Desktop config
{
  "mcpServers": {
    "guardian-intel": {
      "command": "npx",
      "args": ["@abusix/guardian-intel-mcp-server"],
      "env": {
        "ABUSIX_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

## Monitoring

After publishing:
- Monitor [NPM package page](https://www.npmjs.com/package/@abusix/guardian-intel-mcp-server)
- Check download statistics
- Watch for security alerts
- Review user feedback and issues