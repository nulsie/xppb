# changelog

changelog for xppb project.

## [v1.1.0] - 2026-10-04

### Added

- Bytecode optimization & source stripping(`xppb.py`)

- Tightened extension preservations & pruning heavy directories

- Zips the pure-python `stdlib`

- Binary symbol stripping & UPX compression

- Upgrade final archive compression to use LZMA/XZ.

### Fixed

- The race conditions in `ProcessPoolExecutor`

- The unbound local variable in `generate_runtime_whitelist()`

- Package false negatives in binary scanner(also in `generate_runtime_whitelist()`)

### Changed

- The launcher_stub has been re-written from C to Nim(`launcher_stub.nim`) with new EOF tech

- The `generate_window_launcher` method has been refactored for new EOF tech

## [v1.0.0] - 2026-08-19

### Added

- Project files

### Fixed

- None

### Changed

- None
