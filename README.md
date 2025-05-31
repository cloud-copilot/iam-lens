# iam-lens

[![NPM Version](https://img.shields.io/npm/v/@cloud-copilot/iam-lens.svg?logo=nodedotjs)](https://www.npmjs.com/package/@cloud-copilot/iam-lens) [![License: AGPL v3](https://img.shields.io/github/license/cloud-copilot/iam-lens)](LICENSE.txt) [![GuardDog](https://github.com/cloud-copilot/iam-lens/actions/workflows/guarddog.yml/badge.svg)](https://github.com/cloud-copilot/iam-lens/actions/workflows/guarddog.yml) [![Known Vulnerabilities](https://snyk.io/test/github/cloud-copilot/iam-lens/badge.svg?targetFile=package.json&style=flat-square)](https://snyk.io/test/github/cloud-copilot/iam-lens?targetFile=package.json)

## iam-lens

Get visibility into the actual IAM policies that apply in your AWS organizations and accounts. This will use your existing AWS IAM policies (downloaded via [iam-collect](https://github.com/cloud-copilot/iam-collect)) and evaluate the effective permissions.

## Quick Start

```bash
# Install
npm install -g @cloud-copilot/iam-collect @cloud-copilot/iam-lens

# Download all IAM policies in your accounts
iam-collect init
iam-collect download

# Simulate a request
iam-lens simulate --principal arn:aws:iam::123456789012:role/ExampleRole --resource arn:aws:s3:::example-bucket/secret-file.txt --action s3:GetObject

# Find out who can do something
iam-lens who-can --resource arn:aws:s3:::example-bucket --actions s3:GetObject

# Find out who can do all actions on a resource
iam-lens who-can --resource arn:aws:iam::123456789012:role/ExampleRole
```
