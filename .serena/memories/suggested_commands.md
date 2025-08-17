# Development Commands for Saorsa MLS

## Build and Test
```bash
# Build the project
cargo build

# Run tests
cargo test

# Run with all features
cargo test --all-features

# Run specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture
```

## Quality Checks
```bash
# Format code
cargo fmt

# Check formatting
cargo fmt -- --check

# Run clippy linter
cargo clippy -- -D warnings

# Check for compilation errors
cargo check

# Build documentation
cargo doc --no-deps --open
```

## Benchmarks
```bash
# Run benchmarks
cargo bench

# Run specific benchmark
cargo bench benchmark_name
```

## Security Audit
```bash
# Audit dependencies for vulnerabilities
cargo audit

# Update dependencies
cargo update
```

## Git Commands
```bash
# Check status
git status

# Stage changes
git add -A

# Commit changes
git commit -m "feat: migrate to saorsa-pqc"

# Push changes
git push origin main
```