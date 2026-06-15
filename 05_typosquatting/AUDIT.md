# Experiment 05 - Typosquatting

## Scenario

A developer adds a dependency and makes a one-character slip, `reqeusts` instead of `requests`, or an attacker publishes a look-alike package and waits for someone to make that slip. The name installs without complaint, and the CVE audit from experiment 04 reports it clean. It is clean of *known* vulnerabilities, because the package is malicious by design and brand new, so no advisory has ever been filed against it. The attacker's code runs at install time from `setup.py`, or at first import, before any model or business logic is reached. The team needed to do nothing wrong except mistype, or trust a name that looked right.

## How it works

A CVE scanner answers "does this exact version have a published vulnerability". A typosquat has none, so that question is the wrong one. A vulnerability scan therefore passes a malicious-by-design package whether or not the name is a squat, because it has no advisory to match against, which is why the dependency audit in experiment 04 cannot be the control here. The right question is "is this name one we actually meant to trust", and that is answered by comparing the name, not by looking it up in an advisory database.

A simple, transparent check compares each requested name against a curated list of popular packages by string similarity. An exact match is fine, it is the real package. A name that is highly similar but not identical is a likely typosquat. A name that resembles nothing on the list is unknown, which is not the same as safe. Because this is pure string comparison, it resolves nothing and installs nothing, so it runs fully offline under `--network none`, unlike the dependency audit in experiment 04.

The detector in this experiment, `typosquat_check.py`, uses Python's standard-library `difflib` and a short allowlist. It is intentionally small so the logic is auditable. Production tooling such as GuardDog (Datadog) and OSSF Scorecard does the same job at scale, adding package age, download counts, maintainer signals, and install-script heuristics.

```
requirements names
        │
        └──► similarity check vs known packages
                              │
            ┌─────────────────┼─────────────────┐
        exact match     close but not exact   no match
        the real one    likely typosquat      unknown - verify source
```

## Run

Samples:
- `samples/requirements/typosquat_requirements.txt` - names only, several imitate real packages (never installed)
- `05_typosquatting/typosquat_check.py` - the static name-similarity detector

Run the name check (offline):

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  -v $(pwd)/05_typosquatting:/app/check:ro \
  ai-audit python3 /app/check/typosquat_check.py samples/requirements/typosquat_requirements.txt
```

```
OK       requests  (exact match to a known package)
OK       numpy  (exact match to a known package)
SUSPECT  reqeusts  ->  looks like 'requests' (similarity 0.88)
SUSPECT  python-dateutils  ->  looks like 'python-dateutil' (similarity 0.97)
SUSPECT  safetensor  ->  looks like 'safetensors' (similarity 0.95)
SUSPECT  scikit-lean  ->  looks like 'scikit-learn' (similarity 0.96)
SUSPECT  urlib3  ->  looks like 'urllib3' (similarity 0.92)
UNKNOWN  my-internal-utils  (not similar to any known package; verify the source)

Flagged 5 possible typosquat(s). Reject until verified.
```

The two real names pass, the five look-alikes are flagged with the package each imitates, and the unrecognised name is marked for manual review rather than waved through. The check exits non-zero when anything is flagged, so it can block a build.

## Takeaway

A CVE audit and a name check answer different questions, and a dependency set needs both. Run the name check on every change, before install, and reject anything flagged until a human confirms the source. Two limits matter. First, string similarity catches obvious slips but not a semantic squat, a name that is plausible yet wrong, such as a package that simply sounds like an official one. Second, the allowlist is only as good as it is maintained. Treat this detector as the idea, and lean on maintained tooling (GuardDog, OSSF Scorecard) and a vetted internal index for the real control. The durable fix is to install only from curated, approved sources rather than typing names by hand.

## References

- GuardDog (Datadog) - detects malicious and typosquatting PyPI/npm packages - https://github.com/DataDog/guarddog
- OSSF Scorecard - supply-chain risk signals for open-source projects - https://github.com/ossf/scorecard
- difflib (Python standard library) - https://docs.python.org/3/library/difflib.html
- PEP 541 - Package Index Name Retention (PyPI policy on name squatting and disputes) - https://peps.python.org/pep-0541/
