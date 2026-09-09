# Contributing to KMTO

Thank you for your interest in contributing to KMTO (Kernel Mitigation
Telemetry Observatory). This document outlines the contribution
expectations for a defensive observation framework.

## Scope and Ethics

KMTO is a defensive observation tool. Contributions must preserve that
posture:

- The framework observes mitigation behavior; it does not exploit or
  bypass mitigations.
- New tests should add observation coverage — e.g., a new mitigation
  surface (CET shadow stacks, IBT, KCFI), a new fault-classification
  path, or a new telemetry signal — not new offensive primitives.
- Responsible-disclosure practice applies if a contribution surfaces a
  defect in a vendor's mitigation enforcement: coordinate with the
  affected vendor before any public write-up.

## Development Guidelines

### Code Style

- C11 standard
- Follow existing formatting and naming conventions (snake_case for
  functions, MACRO_CASE for constants, `kmto_` prefix for protocol
  symbols and CLI helpers)
- Keep functions focused; module boundaries are: detector, telemetry,
  test_harness, config_manager, reporting
- Comments only where intent is non-obvious

### Testing

- Verify build on Windows (MSVC + WDK for the driver) and Linux (gcc)
- New test scenarios should produce deterministic outcomes under the
  documented mitigation matrix
- Telemetry output must remain machine-parseable (text-line and JSON
  formats)

### Documentation

- Update `README.md` when adding a CLI flag, test type, or output file
- Document new public functions in their header
- Update `TECHNICAL_DEEP_DIVE.md` only for substantive architectural
  changes

## Pull Request Process

1. Fork the repository
2. Create a feature branch named after the surface (`feat/cet-observer`,
   `fix/telemetry-flush`)
3. Make your changes; keep commits scoped
4. Open a pull request describing the motivation, the observation
   coverage added, and any platform-specific notes

## Questions

Open an issue for discussion before large changes. Threat-model
clarifications and mitigation-surface proposals are welcome.
