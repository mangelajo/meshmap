# meshmap

## Project Overview
meshmap is a Python tool for scanning and mapping meshcore networks. It builds a network graph by:
- Discovering nearby nodes
- Accessing guest pages of repeaters to find adjacent nodes
- Collecting map coordinates for each node

## Tech Stack
- Python 3.12+
- uv for package management and tooling

## Development Setup
- Use `uv` for dependency management
- Run commands via the Makefile for consistency
- Follow PEP 8 style guidelines

## Project Structure
```
meshmap/
├── meshmap/          # Main package directory
├── tests/            # Test files
├── pyproject.toml    # Project configuration
└── Makefile          # Development commands
```

## Key Considerations
- Network scanning should be done responsibly
- Handle connection errors gracefully
- Consider rate limiting when accessing guest pages
- Store graph data efficiently
