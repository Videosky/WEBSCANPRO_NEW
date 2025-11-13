# Unified Vulnerability Scanner Integration Guide

## Overview

The Unified Vulnerability Scanner integrates machine learning models for detecting SQL Injection (SQLi) and Cross-Site Scripting (XSS) vulnerabilities into a single scanning pipeline.

## Features

- **Dual Detection**: Simultaneously scans for XSS and SQLi vulnerabilities
- **ML + Rule-based**: Uses machine learning models with rule-based fallbacks
- **Parallel Scanning**: Efficient parallel processing of multiple URLs and payloads
- **Comprehensive Reporting**: JSON, CSV, and console output formats
- **Graceful Degradation**: Falls back to rule-based detection if models are unavailable

## Quick Start

### Basic Usage

```bash
# Scan a single URL
python projects/unified_scanner/unified_scanner.py --url http://example.com

# Scan URLs from a file
python projects/unified_scanner/unified_scanner.py --url-list targets.txt

# Custom output and format
python projects/unified_scanner/unified_scanner.py --url http://test.com --output my_scan --format csv