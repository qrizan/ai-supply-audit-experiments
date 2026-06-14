# Experiment 04 - Dependency Audit

## Scenario

A team pins a set of Python packages for their ML service and never revisits them. The versions install cleanly and the service runs, so nothing looks wrong. What they do not see is that several of those pinned versions have known vulnerabilities published after they were chosen, including remote code execution in an image library the model pipeline uses to decode inputs. The attacker needed no access to the team's code, only a crafted input that reaches a known-vulnerable parser. Most of the code that runs in an ML service is not the model at all, it is this long tail of dependencies, and it is audited far less often.

## How it works

A vulnerability scanner takes the exact versions a project depends on and compares each one against a database of published advisories (CVEs). Where a pinned version falls inside a vulnerable range, the scanner reports the advisory and the version that fixes it. pip-audit (PyPA) reads a `requirements.txt`, looks up each package against the Python advisory data, and prints one row per finding. The check is on version metadata only, no package code is executed.

This check needs network access to reach the advisory database, so it does not run under `--network none` like the other experiments. That isolation rule exists to contain untrusted *model loading*, which executes code; auditing a `requirements.txt` executes nothing, so the rule does not apply here. `--no-deps` keeps pip-audit from building and installing a full virtual environment to resolve the tree, which keeps the run lighter. Note that the audit still covers the dependencies the pinned packages pull in, not just the lines in the file, so transitive packages can appear in the results. Expect the first run to take a few minutes: pip-audit fetches advisory data over the network for each package.

```
requirements.txt (pinned versions)
        │
        └──► pip-audit ──► compare each version to advisory database
                              │
                  ┌───────────┴───────────┐
              no match                  match
           version is clean      known vulnerability - upgrade to fixed version
```

## Run

Samples:
- `samples/requirements/vulnerable_requirements.txt` - versions pinned to releases with known CVEs
- `samples/requirements/safe_requirements.txt` - versions audited clean as of 2026-06-14 (this set has an expiry: see the note in the file and the Takeaway)

**1. Audit the vulnerable requirements:**

```bash
docker run --rm \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit pip-audit --no-deps -r samples/requirements/vulnerable_requirements.txt
```

```
Found 57 known vulnerabilities in 5 packages
Name     Version ID                  Fix Versions
-------- ------- ------------------- -------------
numpy    1.21.0  CVE-2021-34141      1.22
requests 2.18.0  PYSEC-2018-28       2.20.0
requests 2.18.0  PYSEC-2023-74       2.31.0
requests 2.18.0  CVE-2024-35195      2.32.0
requests 2.18.0  CVE-2024-47081      2.32.4
requests 2.18.0  CVE-2026-25645      2.33.0
pillow   8.0.0   PYSEC-2021-137      8.2.0
pillow   8.0.0   CVE-2023-50447      10.2.0
pillow   8.0.0   CVE-2023-4863       10.0.1
pillow   8.0.0   CVE-2024-28219      10.3.0
pillow   8.0.0   CVE-2026-42310      12.2.0
idna     2.5     CVE-2026-45409      3.15
urllib3  1.21.1  CVE-2024-37891      1.26.19,2.2.2
urllib3  1.21.1  CVE-2025-50181      2.5.0
urllib3  1.21.1  CVE-2025-66471      2.6.0
... (57 rows total)
```

Each row is a package version that matches a published advisory, with the version that fixes it in the last column. Note that `idna` and `urllib3` are not in the requirements file at all - they are transitive dependencies of `requests 2.18.0`, which is exactly the long tail the Scenario warns about: the riskiest versions are often ones the team never typed. The full run lists 57 findings across 5 packages; all of them must be upgraded before the dependency set can be trusted.

**2. Audit the safe requirements:**

```bash
docker run --rm \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit pip-audit --no-deps -r samples/requirements/safe_requirements.txt
```

```
No known vulnerabilities found
```

The same packages at upgraded versions report nothing. The difference between the two files is version numbers alone. But "clean" here means *clean as of 2026-06-14*: these exact versions were audited on that date and passed. The first version of this sample was clean when written and later started failing as new advisories landed, which is why the file now carries an audit date and must be re-checked rather than trusted indefinitely.

## Takeaway

Audit pinned dependencies against an advisory database on every build, and fail the build when a known vulnerability appears. The fix for a finding is almost always an upgrade to the listed fixed version. Two limits matter. First, pip-audit only knows vulnerabilities that have been published, so it does not catch a brand-new malicious package or a typosquatted name that no advisory has flagged yet - that is a separate problem from a known CVE. Second, a clean report today can turn into a finding tomorrow as new advisories land, so the audit has to run continuously, not once. Pair it with hash-pinned requirements (`--require-hashes`) so the versions you audited are exactly the ones that get installed.

## References

- pip-audit (PyPA) - https://github.com/pypa/pip-audit
- Python Packaging Advisory Database - https://github.com/pypa/advisory-database
- OSV - Open Source Vulnerabilities - https://osv.dev
- CVE-2023-32681 - requests leaks Proxy-Authorization header - https://nvd.nist.gov/vuln/detail/CVE-2023-32681
- CVE-2023-50447 - Pillow arbitrary code execution via ImageMath.eval - https://nvd.nist.gov/vuln/detail/CVE-2023-50447
