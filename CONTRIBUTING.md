# Contributing to POSIX IDS

We welcome contributions to the POSIX IDS project! This document provides guidelines for contributing.

## How to Contribute

### Reporting Issues
- Check existing issues first
- Provide clear description and steps to reproduce
- Include system information (OS, shell version)
- Add relevant log outputs

### Submitting Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Test thoroughly on multiple systems
5. Commit with clear messages
6. Push to your fork
7. Create a Pull Request

### Code Standards
- Maintain POSIX compliance (no bashisms)
- Test with dash/ash/BusyBox
- Keep resource usage minimal
- Document any new detection patterns
- Update tests for new features

### Testing
```bash
# Run tests
./tests/test.sh

# Test Ansible playbooks
ansible-playbook playbooks/site.yml --syntax-check
ansible-playbook playbooks/site.yml --check
```

### Detection Patterns
When adding new detection patterns:
1. Document the threat being detected
2. Provide IoCs (Indicators of Compromise)
3. Test for false positives
4. Update documentation

## Development Setup

```bash
# Clone repository
git clone https://github.com/Bissbert/posix-ids.git
cd posix-ids

# Run in test mode
sudo ./bin/monitor.sh -1

# Test Ansible deployment
ansible-playbook -i inventory/staging playbooks/site.yml --check
```

## Communication
- Open an issue for discussion before major changes
- Be respectful and constructive
- Help others in issues when possible

Thank you for contributing to POSIX IDS!
