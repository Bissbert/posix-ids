# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

This is a defensive security tool designed to detect intrusions. If you discover a security vulnerability in the IDS itself:

### Do:
- Report privately via GitHub Security Advisories
- Provide detailed information about the vulnerability
- Include steps to reproduce if possible
- Allow time for a fix before public disclosure

### Don't:
- Disclose publicly before a fix is available
- Exploit the vulnerability on systems you don't own

## Security Considerations

### Deployment Security
- Always review scripts before running with sudo
- Use Ansible Vault for sensitive configuration
- Restrict access to IDS logs and configuration
- Monitor the IDS system itself for tampering

### Detection Capabilities
This IDS detects but does not prevent:
- Network-based attacks
- File system changes
- Authentication anomalies
- Process irregularities
- Configuration modifications

### Limitations
- Requires root access for full functionality
- Cannot detect kernel-level rootkits
- No packet inspection capabilities
- Dependent on system log integrity

## Best Practices

1. **Regular Updates**
   - Keep detection patterns current
   - Update baselines after authorized changes
   - Review and tune thresholds

2. **Defense in Depth**
   - Use alongside preventive controls
   - Implement log forwarding to secure systems
   - Maintain incident response procedures

3. **Monitoring**
   - Review alerts daily
   - Investigate all critical alerts
   - Maintain audit trail of responses

## Contact

For security concerns, please use GitHub Security Advisories or contact the maintainers directly.
