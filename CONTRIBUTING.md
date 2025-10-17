# Contributing to POSIX IDS

Thank you for your interest in contributing to the POSIX-compliant Intrusion Detection System! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Security Issues](#security-issues)

## Code of Conduct

This project adheres to the Contributor Covenant Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- Clear and descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- System information (OS, shell version, etc.)
- Relevant log snippets

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- Clear and descriptive title
- Detailed description of the proposed enhancement
- Use cases and examples
- Potential implementation approach

### Pull Requests

1. Fork the repository and create your branch from `main`
2. Follow the coding standards outlined below
3. Add tests for any new functionality
4. Ensure all tests pass
5. Update documentation as needed
6. Submit a pull request with a clear description

## Development Setup

### Prerequisites

- POSIX-compliant shell (bash, sh, dash)
- Basic Unix utilities (grep, sed, awk, find)
- Git for version control
- (Optional) Splunk for integration testing

### Setting Up Your Environment

```bash
# Clone your fork
git clone git@github.com:your-username/posix-ids.git
cd posix-ids

# Run setup script
./bin/setup.sh

# Run tests to verify setup
./tests/test.sh
```

## Coding Standards

### Shell Script Standards

1. **POSIX Compliance**: All scripts must be POSIX-compliant
   - Use `#!/bin/sh` shebang
   - Avoid bash-specific features
   - Test with dash or other minimal shells

2. **Code Style**:
   - Use 4 spaces for indentation (no tabs)
   - Maximum line length of 80 characters
   - Functions should be lowercase with underscores
   - Variables should be uppercase with underscores
   - Always quote variables: `"$VAR"`
   - Use `[ ]` for tests, not `[[ ]]`

3. **Error Handling**:
   - Check return codes for critical commands
   - Use `set -e` for scripts that should exit on error
   - Provide meaningful error messages
   - Clean up temporary files on exit

4. **Documentation**:
   - Add header comments to all scripts
   - Document functions with purpose and parameters
   - Include usage examples for complex functions

### Example Script Header

```bash
#!/bin/sh
#
# Script: monitor.sh
# Purpose: Real-time monitoring for intrusion detection
# Author: [Your Name]
# Date: [Date]
# Version: 1.0
#
# Usage: ./monitor.sh [-c config_file] [-d]
#
# Options:
#   -c config_file  Path to configuration file
#   -d              Enable debug mode
#
```

## Testing

### Running Tests

```bash
# Run all tests
./tests/test.sh

# Run specific test suite
./tests/test.sh baseline

# Run with verbose output
./tests/test.sh -v
```

### Writing Tests

- Create test files in the `tests/` directory
- Name test files with `test_` prefix
- Each test should be independent and idempotent
- Clean up any test artifacts
- Document expected outcomes

### Test Coverage Areas

- Configuration parsing
- Baseline generation
- Alert detection logic
- File monitoring
- Process monitoring
- Network monitoring
- Splunk integration

## Submitting Changes

### Commit Messages

Follow the Conventional Commits specification:

```
type(scope): subject

body

footer
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions or changes
- `chore`: Maintenance tasks

Example:
```
feat(monitor): add support for custom alert thresholds

Implement configurable thresholds for different alert types.
This allows users to customize sensitivity levels based on
their environment requirements.

Closes #42
```

### Pull Request Process

1. Update the README.md with details of changes if applicable
2. Update the CHANGELOG.md following Keep a Changelog format
3. Ensure your PR description clearly describes the problem and solution
4. Link any related issues
5. Request review from maintainers
6. Address review feedback promptly

## Security Issues

### Reporting Security Vulnerabilities

**DO NOT** report security vulnerabilities through public GitHub issues.

Instead, please report them via:
1. GitHub Security Advisories (preferred)
2. Direct email to project maintainers

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

### Security Best Practices

When contributing security-related code:

1. Validate all inputs
2. Avoid command injection vulnerabilities
3. Use proper file permissions
4. Don't store sensitive data in logs
5. Follow principle of least privilege
6. Test for common security issues

## Development Workflow

### Branch Naming

- `feat/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring
- `test/description` - Test additions

### Code Review Checklist

Before requesting review, ensure:

- [ ] Code follows POSIX standards
- [ ] All tests pass
- [ ] Documentation is updated
- [ ] No sensitive data in commits
- [ ] Commit messages are clear
- [ ] Code is properly commented

## Getting Help

- Check the [documentation](docs/)
- Review existing [issues](https://github.com/your-org/posix-ids/issues)
- Ask questions in [discussions](https://github.com/your-org/posix-ids/discussions)
- Contact maintainers for clarification

## Recognition

Contributors will be recognized in:
- The AUTHORS file
- Release notes
- Project documentation

Thank you for helping make POSIX IDS better!