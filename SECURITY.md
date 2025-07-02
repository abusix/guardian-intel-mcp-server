# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability, please report it to us as follows:

### How to Report

1. **Email**: Send details to [security@abusix.com](mailto:security@abusix.com)
2. **GitHub**: Use GitHub Security Advisories for this repository
3. **Include**: 
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Response Time**: We aim to respond within 48 hours
- **Updates**: We'll provide regular updates on our progress
- **Timeline**: Most vulnerabilities are fixed within 90 days
- **Credit**: We'll acknowledge your contribution (unless you prefer anonymity)

## Security Best Practices

### API Key Management

- **Never commit API keys** to version control
- **Use environment variables** for configuration
- **Rotate keys regularly** through the Abusix portal
- **Use separate keys** for development and production

### Usage Guidelines

- **Validate inputs** when using the MCP server
- **Monitor API usage** through the Abusix portal
- **Keep dependencies updated** regularly
- **Use HTTPS** for all API communications

### Environment Security

```bash
# Good - using environment variables
export ABUSIX_API_KEY="your-api-key"
npx @abusix/guardian-intel-mcp-server

# Bad - hardcoding in scripts
# npx @abusix/guardian-intel-mcp-server --api-key "hardcoded-key"
```

### Claude Desktop Configuration

When configuring with Claude Desktop, ensure your API key is properly secured:

```json
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

## Dependency Security

This project uses automated security scanning:

- **npm audit**: Checks for known vulnerabilities
- **Dependabot**: Automated dependency updates
- **Snyk**: Additional security scanning (when configured)

## License Compliance

This project is licensed under MIT. See [LICENSE](LICENSE) for details.

## Security Updates

Security updates will be published as GitHub releases and NPM package updates. Subscribe to repository notifications to stay informed.