# Local certificate artifact folder

This folder is used by `Get-LetsEncryptCertificate.ps1` to store local Let's Encrypt files.

Generated outputs:

- `certs/live/<domain>/fullchain.pem`
- `certs/live/<domain>/privkey.pem`

These files are gitignored and must not be committed.
