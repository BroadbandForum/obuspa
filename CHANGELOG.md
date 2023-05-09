# OB-USP-AGENT Changelog since Release 7.0.0

## 2023-05-09 v7.0.3
### Fixed
- Prevent a parent object's parameters being spread across more than one resolved_path_result in the GetResponse, if it has many child object instances
- Example mqtt factory reset database should not contain wildcard in ResponseTopicConfigured (GH#78)

## 2023-03-13 v7.0.2
### Fixed
- USP Agent should attempt to restart all async operations, even if one restart fails
- Object creation notifications should not be sent at start up, if the object has a refresh instances vendor hook
- Instance cache should not expire during the phases of processing a USP request
- libjson modified to replace non-UTF8 characters with the Unicode replacement character (U+FFFD) instead of asserting

### Added
- New function: USP_REGISTER_AsyncOperation_MaxConcurrency() to register whether a USP command allows another invocation whilst running

## 2023-02-02 v7.0.1
### Added
- CMake support (GH#69)
- Development environment within Docker container

### Modified
- Memory allocation wrapper functions refactored to avoid erroneous warnings when compiling with -Wuse-after-free
