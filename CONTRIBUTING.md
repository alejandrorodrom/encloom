# Contributing

Thanks for helping improve **encloom**.

## Development setup

```bash
git clone https://github.com/alejandrorodrom/encloom.git
cd encloom
npm ci
npm run build
```

Requirements: Node.js `>= 20.19.0`.

## Scripts

| Command | Purpose |
|---------|---------|
| `npm run build` | Compile the library to `dist/` |
| `npm test` | Run the Vitest suite |
| `npm run test:coverage` | Run tests with coverage |
| `npm run test:watch` | Vitest in watch mode |
| `npm run lint` | ESLint |
| `npm run lint:fix` | ESLint with auto-fix |

CI runs `npm run build`, lint, and tests as required checks.

## Pull requests

1. Fork the repo and create a branch from `main`.
2. Keep changes focused (one concern per PR when possible).
3. Run `npm run build`, `npm run lint`, and `npm test` before opening the PR.
4. Update the root [README](README.md) when public API or usage docs change.
5. If you add or change behavior, add or update tests under `tests/`.

Use the [pull request template](.github/PULL_REQUEST_TEMPLATE.md) when opening a PR.

## Reporting bugs / ideas

- Bugs and features: [GitHub Issues](https://github.com/alejandrorodrom/encloom/issues)
- Security vulnerabilities: see [SECURITY.md](SECURITY.md) (do not open a public issue with exploit details)

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
