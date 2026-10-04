# Recapture v2.0 Roadmap

**Status:** In development  
**Development started:** April 2026  
**Current stable release:** v1.0

Recapture v2.0 is the next major version of Recapture. Development is focused on extending the existing triage and reporting functionality, improving performance and usability, and adding support for additional evidence sources and platforms.

The features below are currently planned for v2.0. This list may change during development and testing.

## Evidence sources

- [ ] Network drive support
- [ ] macOS support
- [ ] Improved forensic image handling
- [ ] Additional file system support

## Snapshot comparison

- [ ] Compare two Recapture snapshots
- [ ] Identify files added since the previous snapshot
- [ ] Identify files no longer present
- [ ] Identify modified files using hashes and metadata
- [ ] Separate added, removed, modified and unchanged files
- [ ] Export comparison results
- [ ] Generate comparison reports

## Keyword search

- [ ] Keyword searching
- [ ] Multiple keyword support
- [ ] Import keyword lists
- [ ] Record keyword hits
- [ ] Include keyword hits in reports
- [ ] Export keyword results

## Hash matching

- [ ] Import custom hash sets
- [ ] Match files against supplied hashes
- [ ] Record hash hits
- [ ] Include hash hits in reports
- [ ] Export hash results

## Known file filtering

- [ ] NSRL hash set support
- [ ] Identify known files
- [ ] Option to exclude known files from displayed results
- [ ] Record known-file statistics in reports

## Reporting

- [ ] Updated HTML report
- [ ] Snapshot comparison report
- [ ] Keyword hit reporting
- [ ] Hash hit reporting
- [ ] Known-file statistics
- [ ] Improved navigation for large reports
- [ ] Export selected results

## User interface

- [ ] Updated interface
- [ ] Simplified evidence selection and case setup
- [ ] Improved processing status and progress information
- [ ] Improved error handling
- [ ] Better handling of large evidence sets
- [ ] Cross-platform support

## Development

v1.0 remains the current stable release.

Development of v2.0 is taking place on the `v2-development` branch. Code on this branch should be considered development code and may be incomplete or unstable.

Features will be marked as complete as they are implemented and tested.
