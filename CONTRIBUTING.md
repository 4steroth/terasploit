# Contributing to Terasploit Framework

Thank you for your interest in contributing. This document covers the development
workflow, code standards, and submission process for both framework changes and
new modules.

## Table of Contents

- [Before You Start](#before-you-start)
- [Development Setup](#development-setup)
- [Code Standards](#code-standards)
- [Submitting Framework Changes](#submitting-framework-changes)
- [Submitting a New Module](#submitting-a-new-module)
- [Commit Style](#commit-style)

## Before You Start

- Open an issue before starting work on significant changes. This prevents
  duplicate effort and allows the direction to be agreed on before code is written.
- Small fixes (typos, documentation, single-file bug fixes) do not need a prior issue.
- All contributions must be for **authorized security testing and educational
  research** purposes. See [SECURITY.md](SECURITY.md) for the project's scope policy.

## Development Setup

**Requirements:** Python 3,14 or later.

```bash
git clone https://github.com/4steroth/terasploit.git
cd terasploit

# Install optional runtime dependencies
pip install -r data/requirements/reqs-extra.txt

# Install development tools
pip install ruff pyright

# Make entry points executable
chmod +x teraconsole terax

# Verify the framework starts
./teraconsole -v
```

No package installation step is required for development. The framework adds
its own root to `sys.path` at startup.

## Code Standards

All Python code in `teralibs/` and `modules/` must pass both checks before
submission.

### Linting and formatting — Ruff

```bash
ruff check .           # lint
ruff check --fix .     # auto-fix safe issues
ruff format .          # format
```

The Ruff configuration is in `pyproject.toml`. Do not suppress warnings with
`# noqa` unless the suppression is genuinely necessary and includes a comment
explaining why.

### Type checking — Pyright

```bash
pyright
```

Pyright runs in `standard` mode. New code should not introduce new
`reportMissingImports` or `reportUndefinedVariable` errors.

## Submitting Framework Changes

Framework changes are modifications to anything under `teralibs/`, the entry
point scripts (`teraconsole`, `terax`), `pyproject.toml`, or `data/`.

1. Fork the repository and create a branch from `master`.
2. Make your changes incrementally. Avoid large rewrites of unrelated systems
   in a single pull request.
3. Ensure `ruff check .` and `pyright` both pass with no new errors.
4. Open a pull request against `master` with a clear description of what
   changed and why.

Breaking backward compatibility — for example, changing a base class interface
that all modules inherit from — requires explicit discussion in the linked issue
before the PR is opened.

## Submitting a New Module

New modules go under `modules/` and are discovered automatically at startup —
no registration step is needed.

1. Place the file in the correct category subdirectory under `modules/`.
2. Name the class exactly `TerasploitModule`.
3. Fill in all required attributes: `NAME`, `DESCRIPTION`, `AUTHOR`,
   `LICENSE`, `VERSION`, `RANK`, `ARCH`, `PLATFORM`.
4. Use the platform and architecture constants from the base class — do not
   use raw strings.
5. Verify the module loads cleanly:
   ```
   ./teraconsole -q -x "use <your/module/path>; show options"
   ```
6. Ensure `ruff check .` passes.
7. Open a pull request. Include a brief description of what the module does
   and any relevant references (CVE, advisory, original research).

Modules that are templates or incomplete stubs will not be merged.

## Commit Style

Use short, imperative subject lines:

```
Add linux/x64 bind_tcp stager
Fix option registry key collision in encoder loader
```

Keep commits focused on a single logical change. Avoid committing unrelated
fixes in the same commit.
