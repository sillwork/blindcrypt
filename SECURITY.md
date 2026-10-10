# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| 1.0.x | Yes |

## Reporting a Vulnerability

Do not open a public issue for a security problem.

Report it privately through GitHub: open https://github.com/sillwork/blindcrypt/security/advisories/new and describe the issue, affected version, and steps to reproduce.

If you cannot use GitHub, email sillwork.dev@gmail.com with the subject "BlindCrypt security".

You will get an acknowledgement within 5 working days. Fixes are released as a patch version and credited in the changelog unless you ask otherwise.

## Verifying Releases

Every artifact published to Maven Central is signed with the Sillwork release key:

| | |
| :--- | :--- |
| Key | `Sillwork (release signing) <sillwork.dev@gmail.com>` |
| Fingerprint | `053F 048B 16C8 A3A3 4B1C 78C6 E30F 14BB C013 8A43` |

To check a downloaded jar, fetch the key and verify the signature that sits next to the jar on Maven Central:

```bash
gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys 053F048B16C8A3A34B1C78C6E30F14BBC0138A43
gpg --verify blindcrypt-core-1.0.0.jar.asc blindcrypt-core-1.0.0.jar
```

The output must say `Good signature from "Sillwork (release signing) <sillwork.dev@gmail.com>"` and show the fingerprint above. A `WARNING: This key is not certified with a trusted signature` line is normal: it only means you have not personally certified the key. The matching fingerprint is what proves the signature is ours.
