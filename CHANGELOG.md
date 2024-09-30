# Changelog

## v1.4.0 - 2024-09-30

- Add support for streaming hash digest calculation.

## v1.3.0 - 2024-02-15

- Added the MD5 hash algorithm. This algorithm is broken and  not recommended
  for security purposes, but may be useful for interoperability with systems
  that use MD5.
- Fixed a bug where signing and verifying messages would not work correctly with
  the md5 hash algorithm.

## v1.2.0 - 2024-02-15

- Added the MD5 hash algorithm. This algorithm is broken and  not recommended
  for security purposes, but may be useful for interoperability with systems
  that use MD5.

## v1.1.0 - 2024-02-15

- This library now supports the JavaScript target too.

## v1.0.0 - 2024-01-15

- Updated for Gleam v0.33.0.

## v0.5.1 - 2023-11-13

- Updated for Gleam v0.32.0.

## v0.5.0 - 2023-11-06

- Updated for Gleam v0.31.0.

## v0.4.0 - 2023-08-03

- Updated for Gleam v0.30.0.

## v0.3.1 - 2022-01-29

- Updated for Gleam v0.27.0.

## v0.3.0 - 2022-01-29

- Converted to use the Gleam build tool.
- The `sign_message` and `verify_signed_message` functions have been added.

## v0.2.0 - 2020-12-02

- Added `hmac` function.

## v0.1.1 - 2020-06-30

- Corrected package name in gleam.toml

## v0.1.0 - 2020-06-30

- Initial release
