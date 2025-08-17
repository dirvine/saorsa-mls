# Code Style and Conventions

## Rust Style Guidelines
- Use `rustfmt` for consistent formatting
- Follow Rust naming conventions:
  - `snake_case` for functions, variables, modules
  - `PascalCase` for types and traits
  - `SCREAMING_SNAKE_CASE` for constants

## Error Handling
- **NEVER use `unwrap()` or `expect()`** - use `?` operator or proper error handling
- **NEVER use `panic!()`, `todo!()`, or `unimplemented!()`**
- Return `Result<T, MlsError>` for fallible operations
- Use `anyhow` for flexible error handling
- Use `thiserror` for custom error types

## Documentation
- All public items must have doc comments (`///`)
- Include examples in doc comments where appropriate
- Document safety requirements and invariants
- Update CHANGELOG.md for significant changes

## Testing
- Write tests for all new functionality
- Use `proptest` for property-based testing
- Use `criterion` for benchmarks
- Maintain >85% code coverage

## Security Requirements
- Zero unsafe code without justification
- Zeroize sensitive data on drop
- Use constant-time operations for crypto
- No debug prints or logging of sensitive data
- Input validation on all external data

## Performance Standards
- Profile before optimizing
- Document performance characteristics
- No significant performance regressions
- Benchmark critical paths