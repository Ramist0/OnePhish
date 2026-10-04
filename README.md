# OnePhish

![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)

## Description

**OnePhish** is a Python script designed to simplify and automate the initial analysis of phishing emails ( .eml files ). It extracts the most interesting headers, URLs, attachments, and checks them with VirusTotal to identify malicious indicators.

## Features

- Header extraction: Automatically parses From, Reply-To, and SPF authentication results.

- Artifact extraction: Identifies and lists all URLs and file attachments within the email.

- Hash generation: Calculates SHA-256 hashes for all attachments.

- VirusTotal analysis: Queries the VirusTotal API to check the reputation of extracted URLs and attachment hashes.

- Json output: Displays a clean summary in the console or exports a detailed report in JSON format.

## How it works

```text
                         ┌──────────────────────┐
                         │      email.eml       │
                         └──────────┬───────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
           Headers                 URLs              Attachments
              │                     │                     │
      ┌───────┼───────┐             │                  SHA-256
      │       │       │             │                     │
    From  Reply-To   SPF            ▼                     ▼
      │       │       │       VirusTotal URL        VirusTotal HASH
      │       │       │             │                     │
      │       │       │             ▼                     │
      │       │       │        malicious /                │
      │       │       │        suspicious                 │
      │       │       │                                   │
      └───────┴───────┴───────────────────────────────────┘
```

## Installation

Create your VirusTotal account, and copy/paste your [api key](https://docs.virustotal.com/docs/please-give-me-an-api-key) in an environment variable :

```bash
 export VT_API_KEY="VIRUSTOTAL_API_KEY"
```

Install python requests lib :

```python
python3 -m pip install requests
```

## Usage

```python
python3 onephish.py .\phishing.eml --virustotal
python3 onephish.py .\phishing.eml --virustotal --json report.json
```
