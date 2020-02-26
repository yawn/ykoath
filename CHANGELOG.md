# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## 1.0.4

### Changed

- Support name without issuer like [ykman](https://support.yubico.com/support/solutions/articles/15000012643-yubikey-manager-cli-ykman-user-manual) (#12, thanks @j0hnsmith)

## 1.0.3

### Fixed

- Fixed wrong datastructure bug, manifesting in scenarios with mixed touch/no-touch configurations (#8, thanks @asiragusa and @j0hnsmith)
- Fixed Catalina naming issue (#11, thanks @nauxliu)

## 1.0.2

### Changed

- Updated `scard` dependencies (#7, thanks @akerl)

### Fixed

- Fixed wrong error messages (#5, thanks @brotbert)

## 1.0.1

### Changed

- Made `Clock` public again
- Simplified `debugger` interface
- Added Windows test

### Fixed

- Fixed iteration order over tags, leading to parsing errors
