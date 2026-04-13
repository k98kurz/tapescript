# Reporting Vulnerabilities

## Scope

Priority is given to vulnerabilities in these areas:

1. **`run_auth_scripts`** — The authentication/access control enforcement layer. Any flaw here is high priority.
2. **VM operations** — Functions like `op_merkleval` or other VM operations that could be exploited or bypassed.

However, any potentially exploitable weakness anywhere within the package is a problem, and reports will be appreciated.

## Response Timeline

I aim to acknowledge reports within **3 calendar days** under normal circumstances.

## How to Report

If you found a vulnerability, contact the admin of the Pycelium Discord. Please include:

- Description of the issue
- Steps to reproduce (if applicable)
- Potential impact
- Potential remediation steps (pull requests welcome after a discussion)

