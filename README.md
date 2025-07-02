# Abusix Guardian Intel MCP Server

[![npm version](https://badge.fury.io/js/@abusix%2Fguardian-intel-mcp-server.svg)](https://badge.fury.io/js/@abusix%2Fguardian-intel-mcp-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Model Context Protocol (MCP) server that provides AI assistants with access to [Abusix Guardian Intel](https://abusix.com/guardian-intel/) threat intelligence data. This server enables AI models to perform IP reputation lookups, analyze threat intelligence tags, and access comprehensive security data with high-fidelity and low false positives.

## Features

- 🔍 **IP Threat Intelligence Lookup** - Comprehensive threat analysis for any IP address
- 🏷️ **Threat Intelligence Tags** - Access to categorized threat intelligence taxonomy
- 📊 **Tag-based IP Enumeration** - Find IP addresses associated with specific threat types
- ⚡ **High Performance** - Built with TypeScript and optimized for speed
- 🛡️ **Low False Positives** - Leverages Abusix's industry-leading 0.284% false positive rate
- 🚀 **Easy Distribution** - Available via NPX for instant usage

## Quick Start

### Prerequisites

- Node.js 18+ 
- Abusix Guardian Intel API key ([Get yours here](https://portal.abusix.com/))

### Installation & Usage

The easiest way to use this MCP server is with NPX:

```bash
# Set your API key
export ABUSIX_API_KEY="your-api-key-here"

# Run the MCP server
npx @abusix/guardian-intel-mcp-server
```

### Alternative: Global Installation

```bash
npm install -g @abusix/guardian-intel-mcp-server
guardian-intel-mcp-server
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `ABUSIX_API_KEY` | Your Abusix Guardian Intel API key | ✅ Yes |
| `ABUSIX_BASE_URL` | Custom API endpoint (default: https://threat-intel-api.abusix.com/beta) | ❌ No |

### Command Line Options

```bash
npx @abusix/guardian-intel-mcp-server [options]

Options:
  --api-key <key>   Abusix Guardian Intel API key
  --base-url <url>  Base URL for Guardian Intel API
  --debug           Enable debug logging
  --help-usage      Show detailed usage examples
  -h, --help        Display help for command
```

## MCP Tools

This server provides 4 MCP tools for comprehensive threat intelligence analysis:

### 1. `guardian_intel_lookup`

Look up threat intelligence for an IP address.

**Parameters:**
- `ip` (string, required): IPv4 or IPv6 address to analyze

**Returns:**
- IP classification (malicious/suspicious/unknown)
- Threat level assessment
- First/last seen timestamps
- Abuse contact information
- ASN details
- Blocklist presence
- Observed malicious activities

### 2. `guardian_intel_tags_list`

Retrieve all available threat intelligence tags.

**Parameters:**
- `includeDescriptions` (boolean, optional): Include detailed tag descriptions

**Returns:**
- Complete list of available tags
- Tag categories and intent classification
- Statistical breakdown by category and intent

### 3. `guardian_intel_tag_details`

Get detailed information about a specific threat intelligence tag.

**Parameters:**
- `tagName` (string, required): Name of the tag (e.g., "credentials:brute-force")

**Returns:**
- Tag metadata (name, intent, category)
- Detailed description
- Reference links
- Historical timeline

### 4. `guardian_intel_tag_ips`

Retrieve IP addresses associated with a specific threat intelligence tag.

**Parameters:**
- `tagName` (string, required): Name of the tag
- `offset` (number, optional): Starting offset for pagination (default: 0)
- `limit` (number, optional): Maximum IPs to return (default: 1000, max: 10000)
- `snapshot` (string, optional): Snapshot ID for consistent pagination

**Returns:**
- List of IP addresses
- Pagination metadata
- Last update timestamp
- Total count and snapshot information

## Integration Examples

### Claude Desktop

Add to your Claude Desktop configuration file:

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

### Continue.dev

Add to your `config.json`:

```json
{
  "mcpServers": [
    {
      "name": "guardian-intel",
      "command": "npx",
      "args": ["@abusix/guardian-intel-mcp-server"],
      "env": {
        "ABUSIX_API_KEY": "your-api-key-here"
      }
    }
  ]
}
```

### Generic MCP Client

```bash
mcp-client connect stdio -- npx @abusix/guardian-intel-mcp-server
```

## API Classifications

Guardian Intel uses three main IP classifications:

- **Malicious**: IPs with confirmed malicious activity or carrying malicious tags
- **Suspicious**: IPs involved in systematic probing, scanning, or enumeration activities
- **Unknown**: IPs that don't meet malicious or suspicious criteria

## Data Sources

Abusix Guardian Intel aggregates data from multiple high-quality sources:

- 🍯 **Honeypots** - Deceptive systems designed to attract malicious activity
- 📧 **Spamtraps** - Email addresses that should never receive legitimate mail
- 🕳️ **Sinkholes** - Network resources capturing malicious traffic
- 📨 **SMTP Transaction Feeds** - Real-time mail server interaction data
- 🛡️ **Policy Blocklist Scanners** - Active server behavior validation
- 🤝 **Partner Contributions** - Trusted data from ISPs and security partners

## Development

### Local Development

```bash
# Clone the repository
git clone https://github.com/abusix/guardian-intel-mcp-server.git
cd guardian-intel-mcp-server

# Install dependencies
npm install

# Set up your API key
export ABUSIX_API_KEY="your-api-key-here"

# Run in development mode
npm run dev

# Build for production
npm run build

# Test the built version
npm start
```

### Testing

```bash
# Test API connection without API key (should fail gracefully)
node dist/cli.js --debug

# Test with API key
ABUSIX_API_KEY="your-key" node dist/cli.js --debug
```

## Error Handling

The server includes comprehensive error handling for:

- Invalid API keys or authentication failures
- Network connectivity issues
- Invalid IP address formats
- Non-existent threat intelligence tags
- API rate limiting and service availability
- Request timeouts

## Security Considerations

- API keys are handled securely and never logged
- All API communication uses HTTPS
- Input validation prevents injection attacks
- Rate limiting is respected to prevent API abuse

## Troubleshooting

### Common Issues

**"ABUSIX_API_KEY environment variable is required"**
- Solution: Set your API key using `export ABUSIX_API_KEY="your-key"` or use the `--api-key` option

**"Unable to connect to Guardian Intel API"**
- Check your internet connection
- Verify your API key is valid
- Check if there are firewall restrictions

**"Guardian Intel API Error (401)"**
- Your API key is invalid or has expired
- Contact Abusix support to verify your account status

**"Guardian Intel API Error (503)"**
- The Guardian Intel service is temporarily unavailable
- Try again in a few minutes

### Debug Mode

Enable debug mode for detailed logging:

```bash
npx @abusix/guardian-intel-mcp-server --debug
```

## Support

- 📚 **Documentation**: [Abusix Guardian Intel Docs](https://docs.abusix.com/docs/guardian-intel/)
- 🎫 **Support Portal**: [portal.abusix.com](https://portal.abusix.com/)
- 🐛 **Issues**: [GitHub Issues](https://github.com/abusix/guardian-intel-mcp-server/issues)
- 🌐 **Website**: [abusix.com/guardian-intel](https://abusix.com/guardian-intel/)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

**Made with ❤️ by [Abusix](https://abusix.com/) - Making the digital world safer**