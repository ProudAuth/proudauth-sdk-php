# Standalone validation — 2026-10-13

Source checkout HEAD: `5ff6ddb852b572a05d4b1b5e6afdf2ecc1350a11`.
SOURCE-MANIFEST.json records working-tree input hashes, including unpublished
changes; it does not assert that the input bytes equal that commit. The vendored
contracts/vectors are pinned separately in testdata/manifest.json.

Runtime: **PHP 8.5.8; OpenSSL 3.6.3; libsodium 1.0.22**.

Contract hashes (4 files): pass. Syntax: **90 files passed**, plus the corrected package test. Test runner: **157 passed, 0 failed; 3079 assertions**.

The license test checks the pinned Apache-2.0 license hash/text locally rather than
reading a sibling Node repository. Composer was unavailable for the local staging
checks; the subsequent independent CI runs verify it on PHP 8.2 and 8.5.

All restores used existing local caches with network package/module downloads
disabled. No Docker, database or public deployment was used; tests use synthetic
data and loopback mock servers. Commands: python3 scripts/check-contracts.py;
the standalone README and CI contain the build/test commands. npm used --offline;
Dart used pub get --offline; .NET used only local feeds and NuGetAudit=false.

Generated build outputs/dependencies and temporary consumer directories were
removed after verification. Dependency lockfiles and synthetic vectors remain.
Final documentation/repository metadata edits do not change runtime behavior.
The staging validation preceded source publication. The reviewed source is now
public at [`proudbase/proudauth-sdk-php`](https://github.com/proudbase/proudauth-sdk-php).
The [initial independent CI run](https://github.com/proudbase/proudauth-sdk-php/actions/runs/38454463845)
passed at commit `e54894273e4822458f901f7fd548503cb3a160c4` on PHP 8.2 and 8.5.
Composer validation, syntax and the SDK test runner passed.
The [public VCS consumer validation](https://github.com/proudbase/proudauth-sdk-php/actions/runs/38458707068)
passed at `80a1aee474ab2c2aa14ff64689ff8e47c637cdb3` on both PHP 8.2 and 8.5.
A fresh Composer application resolved `dev-main` at the exact tested source
revision, installed from the public repository and successfully autoloaded the
SDK's version class. Runtime and contract/vector bytes were unchanged.
GitHub private vulnerability reporting is enabled. No package-registry release
or SDK release tag has been published.

Excluded: original .git history, actual .env/credentials, deployment state,
private screenshots/database backups, SDK caches/build output, image archives,
benchmark seeds and customer data. The original checkout was not modified.
