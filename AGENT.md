# AGENT.md
<!-- cspell:ignore GOPATH golangci pnpx codecov -->
<!-- cspell:ignore GOTEST languagetool shellcheck -->

This file provides guidance to AI agents when working with code in this
repository. For developers and general project information, please refer to
[README.md](README.md) first.

## Related Documentation

- [README.md](README.md) - Package overview and API reference
- [pkg/client/README.md](pkg/client/README.md) - DNS client implementations
- [pkg/errors/README.md](pkg/errors/README.md) - Error handling utilities
- [pkg/exdns/README.md](pkg/exdns/README.md) - Extended DNS functionality
- [pkg/reflect/README.md](pkg/reflect/README.md) - Logging middleware
- [pkg/server/README.md](pkg/server/README.md) - DNS server handlers

## Repository Overview

`darvaza.org/resolver` is a DNS resolver library that provides flexible and
composable DNS resolution functionality. It implements standard Go interfaces
while offering advanced features like iterative resolution, middleware patterns,
and comprehensive error handling.

## Prerequisites

Before starting development, ensure you have:

- Go 1.23 or later installed (check with `go version`).
- `make` command available (usually pre-installed on Unix systems).
- `$GOPATH` configured correctly (typically `~/go`).
- Git configured for proper line endings.

## Common Development Commands

```bash
# Full build cycle (get deps, generate, tidy, build)
make all

# Run tests
make test

# Run tests with coverage
make test GOTEST_FLAGS="-cover"

# Run tests with verbose output and coverage
make test GOTEST_FLAGS="-v -cover"

# Build test binaries without running (useful for debugging)
make test GOTEST_FLAGS="-c"

# Generate coverage reports
make coverage

# Generate Codecov configuration and upload scripts
make codecov

# Format code and tidy dependencies (run before committing)
make tidy

# Clean build artifacts
make clean

# Update dependencies
make up

# Run go:generate directives
make generate

# Run race detector tests
make race

# Check grammar only (without formatting)
make check-grammar

# Check spelling
make check-spelling

# Check shell scripts
make check-shell
```

## Build System Features

### Whitespace and EOF Handling

The `internal/build/fix_whitespace.sh` script automatically:

- Removes trailing whitespace from all text files.
- Ensures files end with a newline.
- Excludes binary files and version control directories.
- Integrates with `make fmt` for non-Go files.
- Supports both directory scanning and explicit file arguments.

### Markdownlint Integration

The build system includes automatic Markdown linting:

- Detects markdownlint-cli via pnpx.
- Configuration in `internal/build/markdownlint.json`.
- 80-character line limits and strict formatting rules.
- Selective HTML allowlist (comments, br, kbd, etc.).
- Runs automatically with `make fmt` when available.

### LanguageTool Integration

Grammar and style checking for Markdown files:

- Detects LanguageTool via pnpx.
- British English configuration in `internal/build/languagetool.cfg`.
- Available via `make check-grammar` target.
- Not integrated into `make tidy` due to false positives.
- Checks for missing articles, punctuation, and proper hyphenation.

### CSpell Integration

Spell checking for both Markdown and Go source files:

- Detects cspell via pnpx.
- British English configuration in `internal/build/cspell.json`.
- New `check-spelling` target.
- Integrated into `make tidy`.
- Custom word list for project-specific terminology.
- Checks both documentation and code comments.

### ShellCheck Integration

Shell script analysis for all `.sh` files:

- Detects shellcheck via pnpx.
- New `check-shell` target.
- Integrated into `make tidy`.
- Uses inline disable directives for SC1007 (empty assignments) and SC3043
  (`local` usage).
- Checks for common shell scripting issues and best practices.

### Coverage Collection

The build system includes automated coverage report generation:

- `make coverage` target runs tests with coverage flags.
- `internal/build/make_coverage.sh` handles test execution.
- Generates coverage reports in multiple formats (text, HTML).
- Coverage artifacts stored in `.tmp/coverage/` directory.
- Integrated with CI/CD workflows for automated reporting.

### Codecov Integration

Enhanced coverage reporting with monorepo support:

- `make codecov` target generates Codecov configuration.
- `internal/build/make_codecov.sh` creates:
  - `codecov.yml`: Dynamic configuration with per-module flags.
  - `codecov.sh`: Upload script for bulk submission.
- Module-specific coverage targets (80% default).
- Path mappings for accurate coverage attribution.
- GitHub Actions workflow automatically uploads coverage data.
- PR comments show coverage changes per module.
- See [internal/build/README-coverage.md](internal/build/README-coverage.md)
  for details.

## Code Architecture

### Key Design Principles

- **Interface-driven design**: Core functionality defined through interfaces
  (`Resolver`, `Lookuper`, `Exchanger`, `Client`).
- **Minimal dependencies**: Primarily darvaza.org packages and the miekg/dns
  library.
- **Middleware pattern**: Composable components for features like caching,
  logging, and rate limiting.
- **Standards compliance**: Implements standard `net.Resolver` interface.

### Package Structure

```text
resolver/
├── *.go                    # Core resolver implementations
├── pkg/
│   ├── client/            # DNS client implementations
│   ├── errors/            # Error handling and transformations
│   ├── exdns/             # Extended DNS functionality
│   ├── reflect/           # Logging and debugging middleware
│   └── server/            # DNS server handler implementation
└── pkg/internal/build/    # Build configuration and scripts
```

### Core Interfaces

1. **Resolver**: Standard DNS resolution interface compatible with
   `net.Resolver`.
2. **Lookuper**: Simplified interface for INET queries.
3. **Exchanger**: Lower-level interface using pre-assembled DNS messages.
4. **Client**: Interface for DNS client implementations.

### Code Quality Standards

The project enforces strict linting rules via revive (configuration in
`pkg/internal/build/revive.toml`):

- Max function length: 40 lines.
- Max function results: 3.
- Max arguments: 5.
- Cognitive complexity: 7.
- Cyclomatic complexity: 10.

Always run `make tidy` before committing to ensure proper formatting.

### Testing Patterns

- Table-driven tests are preferred.
- Mock implementations for interfaces.
- Comprehensive coverage for error conditions.
- Integration tests for client-server interactions.

## Important Notes

- Go 1.23 is the minimum required version.
- The Makefile dynamically generates rules via scripts in `internal/build/`.
- Tool versions (golangci-lint, revive) are selected based on Go version.
- Always use `pnpm` instead of `npm` for any JavaScript/TypeScript tooling.
- British English spelling is used throughout documentation.
- This is a library - focus on clean APIs and reusability.

## Working with DNS

### Key Dependencies

- `github.com/miekg/dns`: Core DNS functionality.
- `darvaza.org/core`: Basic utilities and error handling.
- `darvaza.org/slog`: Structured logging interface.
- `darvaza.org/cache/x/simplelru`: LRU caching for responses.

### Common Patterns

1. **Error Handling**: Use `net.DNSError` for all errors. Convert between
   errors and DNS messages using `errors.MsgAsError()` and
   `errors.ErrorAsMsg()`.

2. **Context Usage**: All operations should respect context cancellation and
   timeouts.

3. **Logging**: Use `reflect.Lookuper` and `reflect.Client` for debugging
   and monitoring.

4. **Caching**: Implement caching at appropriate layers, respecting TTLs.

## Linting and Code Quality

### Documentation Standards

When editing markdown files, ensure compliance with:

- **LanguageTool**: Check for missing articles ("a", "an", "the"), punctuation,
  and proper hyphenation of compound modifiers.
- **Markdownlint**: Follow standard Markdown formatting rules.

### Common Documentation Issues to Check

1. **Missing Articles**: Ensure proper use of "a", "an", and "the".
   - ❌ "implements resolver interface"
   - ✅ "implements the resolver interface"

2. **Missing Punctuation**: End all list items consistently.
   - ❌ "Comprehensive error handling"
   - ✅ "Comprehensive error handling."

3. **Compound Modifiers**: Hyphenate when used as modifiers.
   - ❌ "well known resolvers"
   - ✅ "well-known resolvers"

### Writing Documentation Guidelines

When creating or editing documentation files:

1. **File Structure**:
   - Always include a link to related documentation (e.g., AGENT.md should
     link to README.md).
   - Add prerequisites or setup instructions before diving into commands.
   - Include paths to configuration files when mentioning tools
     (e.g., revive.toml).

2. **Formatting Consistency**:
   - End all bullet points with periods for consistency.
   - Capitalise proper nouns correctly (Go, DNS, TCP, UDP).
   - Use consistent punctuation in examples and lists.
   - Use British English spelling (e.g., "capitalise" not "capitalize").

3. **Clarity and Context**:
   - Provide context for AI agents and developers alike.
   - Include "why" explanations, not just "what" descriptions.
   - Add examples for complex concepts or common pitfalls.

4. **Maintenance**:
   - Update documentation when adding new tools or changing workflows.
   - Keep the pre-commit checklist current with project practices.
   - Review documentation changes for the issues listed above.

### Pre-commit Checklist

1. Run `make tidy` for Go code formatting.
2. Check markdown files with LanguageTool and markdownlint.
3. Verify all tests pass with `make test`.
4. Ensure no linting violations remain.
5. Update `AGENT.md` to reflect any changes in development workflow or
   standards.
6. Update `README.md` to reflect significant changes in functionality or API.
7. Verify all DNS operations handle errors correctly.
8. Check that context cancellation is properly propagated.
