# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2023-10-11

This is the first release of the module after a fork from [yawn/ykoath](https://github.com/yawn/ykoath).
The code has been forked into the [cunicu organization](https://github.com/cunicu/go-ykoath) for updating
it to the latest coding standards, upadting code quality and implementing changes for its use by
the [cunicu/hawkes](https://github.com/cunicu/hawkes) package.

### Added

- A `CODEOWNERS` file.
- A CI pipeline for checking [REUSE](https://reuse.software/) compliancy.
- A CI pipeline for linting the code with [`golangci-lint`](https://golangci-lint.run)
- A configuration file for [Mend Renovate](https://www.mend.io/renovate/).

### Changed

- Go module path to `cunicu.li/go-ykoath`.
- Go version in `go.mod` to `1.21`.
- Updated third-party Go dependencies to their latest versions.

### Fixed

- Code-style using `go fmt` tool across full code-base.
- Formatting of this changelog.

### Removed

- Removed unused `internal` package and `debugger` interface

## [1.0.4] - 2020-02-26

### Changed

- Support name without issuer like [ykman](https://support.yubico.com/support/solutions/articles/15000012643-yubikey-manager-cli-ykman-user-manual) (#12, thanks @j0hnsmith)

## [1.0.3] - 2019-10-13

### Fixed

- Fixed wrong datastructure bug, manifesting in scenarios with mixed touch/no-touch configurations (#8, thanks @asiragusa and @j0hnsmith)
- Fixed Catalina naming issue (#11, thanks @nauxliu)

## [1.0.2] - 2018-09-05

### Changed

- Updated `scard` dependencies (#7, thanks @akerl)

### Fixed

- Fixed wrong error messages (#5, thanks @brotbert)

## [1.0.1] - 2018-09-05

### Changed

- Made `Clock` public again
- Simplified `debugger` interface
- Added Windows test

### Fixed

- Fixed iteration order over tags, leading to parsing errors
