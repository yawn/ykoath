# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Switch pcsclite dependency from cgo to native go

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
