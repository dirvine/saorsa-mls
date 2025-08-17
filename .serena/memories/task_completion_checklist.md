# Task Completion Checklist

Before marking any task as complete, ensure:

## Code Quality
- [ ] Code compiles with ZERO errors and warnings: `cargo build --release`
- [ ] All tests pass: `cargo test`
- [ ] Clippy passes with no warnings: `cargo clippy -- -D warnings`
- [ ] Code is formatted: `cargo fmt`

## Documentation
- [ ] All public APIs have doc comments
- [ ] Examples updated if API changed
- [ ] README updated if features changed
- [ ] CHANGELOG.md updated for significant changes

## Security
- [ ] No `unwrap()`, `expect()`, `panic!()`, `todo!()`, or `unimplemented!()`
- [ ] No unsafe code without justification
- [ ] Sensitive data is zeroized
- [ ] Input validation complete

## Testing
- [ ] Unit tests written for new code
- [ ] Integration tests updated if needed
- [ ] Property tests added where appropriate
- [ ] Code coverage >85%

## Final Verification
- [ ] Run full test suite: `cargo test --all-features`
- [ ] Check for security issues: `cargo audit`
- [ ] Verify documentation builds: `cargo doc --no-deps`

## Git
- [ ] Changes committed with descriptive message
- [ ] Code ready for review