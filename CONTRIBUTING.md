# Contributing to Linux-Patch-Manager

Thank you for your interest in contributing to Linux-Patch-Manager! We appreciate every contribution — from bug reports and documentation improvements to new features and security fixes.

## Code of Conduct

This project follows the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) code of conduct. By participating, you are expected to uphold this standard. Please report unacceptable behavior to the maintainers.

## How to Contribute

1. **Fork** the repository
2. Create a **feature branch** from `master`:
   ```bash
   git checkout -b feat/my-feature
   ```
3. Make your changes
4. Ensure all CI checks pass:
   ```bash
   # Rust backend
   cargo fmt --check --all
   cargo clippy --all-targets --all-features
   cargo test --workspace --all-features --lib --bins --tests

   # TypeScript/React frontend
   cd frontend
   npx eslint src/ --ext .ts,.tsx --max-warnings 0
   npx tsc --noEmit
   ```
5. **Commit** using conventional commit format (see below)
6. Open a **Pull Request** against `master`

## Development Setup

### Prerequisites

- **Rust toolchain** (stable) — [rustup](https://rustup.rs/)
- **Node.js** 20+ (for the frontend) — [nvm](https://github.com/nvm-sh/nvm) recommended
- **System dependencies**:
  ```bash
  sudo apt-get install build-essential pkg-config libssl-dev libfontconfig1-dev
  ```

### Build & Run

```bash
# Backend
cargo build
cargo test

# Frontend
cd frontend
npm install
npm run build
npm test
```

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix   | Usage                  |
|----------|------------------------|
| `feat:`  | New feature            |
| `fix:`   | Bug fix                |
| `docs:`  | Documentation changes  |
| `chore:` | Maintenance tasks      |
| `refactor:` | Code refactoring    |
| `test:`  | Adding or updating tests |
| `ci:`    | CI configuration changes |

Example:
```
feat: add patch scheduling to manager dashboard
```

## Pull Request Requirements

- All CI checks must pass (fmt, clippy, test, audit, build)
- One feature or fix per PR — keep changes focused
- Include a clear description of what changed and why
- Update documentation if your change affects behavior

## Reporting Issues

Use [GitHub Issues](https://github.com/Draco-Lunaris/Linux-Patch-Manager/issues) to report bugs, request features, or ask questions. Please include:

- Steps to reproduce (for bugs)
- Expected vs. actual behavior
- Relevant logs or error messages

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), the same license as this project.
