# Contributing to IoT-Scan

First off, thank you for considering contributing to IoT-Scan! It's people like you that make IoT-Scan such a great tool.

## Code of Conduct

By participating in this project, you are expected to uphold our Code of Conduct:
- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples**
- **Describe the behavior you observed and what you expected**
- **Include screenshots if applicable**
- **Include your environment details** (OS, Python version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **A clear and descriptive title**
- **A detailed description of the proposed functionality**
- **Explain why this enhancement would be useful**
- **List any alternative solutions you've considered**

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Install dependencies**: `pip install -r requirements.txt`
3. **Make your changes**
4. **Add tests** if applicable
5. **Ensure the code follows PEP 8** style guidelines
6. **Update documentation** if needed
7. **Test your changes thoroughly**
8. **Commit your changes** with clear, descriptive messages
9. **Push to your fork** and submit a pull request

#### Pull Request Guidelines

- Keep changes focused - one feature/fix per PR
- Update the README.md if needed
- Add docstrings to new functions/classes
- Include type hints
- Follow existing code style
- Write clear commit messages

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/iot-scan.git
cd iot-scan

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .

# Install development dependencies (if any)
pip install pytest pytest-cov black flake8
```

## Code Style

- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Add docstrings to all public functions and classes
- Include type hints where appropriate
- Keep functions focused and concise
- Comment complex logic

### Example Function

```python
def scan_device(ip: str, timeout: int = 3) -> Dict[str, Any]:
    """Scan a device for vulnerabilities.
    
    Args:
        ip: Target IP address
        timeout: Connection timeout in seconds
        
    Returns:
        Dictionary containing scan results
        
    Raises:
        ConnectionError: If device is unreachable
    """
    # Implementation here
    pass
```

## Testing

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=src tests/

# Run specific test
pytest tests/test_scanner.py
```

## Adding New Features

### Adding a New Vulnerability Check

1. Create a new file in `src/scanner/` (e.g., `new_check.py`)
2. Implement your checker class
3. Add it to `src/scanner/__init__.py`
4. Import and use it in `src/cli.py`
5. Update documentation
6. Add tests

### Adding New Device Signatures

1. Edit `mac-vendors.json` to add MAC prefixes
2. Update `src/scanner/fingerprint.py` if needed
3. Add signature patterns to device identification logic

### Adding New Vulnerable Endpoints

1. Edit `src/scanner/http_check.py`
2. Add endpoints to `VULNERABLE_ENDPOINTS` list
3. Update severity assessment logic if needed

## Documentation

- Update README.md for user-facing changes
- Update docstrings for code changes
- Add comments for complex logic
- Update examples if applicable

## Commit Messages

Write clear, concise commit messages:

```
Add MQTT authentication bypass check

- Implement anonymous login detection
- Add severity rating for unencrypted MQTT
- Update documentation with new check
```

### Commit Message Format

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit first line to 72 characters
- Reference issues and pull requests when applicable

## Security

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email security@example.com with details
3. Allow time for the issue to be addressed
4. Coordinate public disclosure

## Questions?

Feel free to open an issue with the "question" label or reach out to the maintainers.

## Recognition

Contributors will be recognized in:
- The README.md file
- Release notes
- The project's contributors page

Thank you for contributing to IoT-Scan! 🎉
