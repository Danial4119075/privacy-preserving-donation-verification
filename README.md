# Privacy-Preserving Verification of Charitable Donations

Prototype code for the minor thesis *Privacy-Preserving Verification of Charitable Donations: A Commitment-Based Prototype with Auditor Attestation*, by Danial Ansari, Master of Information Technology, RMIT University (COSC2390), 2026.

The same code is listed in full in Appendix B of the thesis. This repository gives it as a file that runs directly, because Python code copied from a PDF loses its indentation.

## What it is

A research prototype. It is not production software and it is not a zero-knowledge proof system.

- The public ledger stores a donation ID, a SHA-256 commitment to the donation details, and an Ed25519 attestation signed by an authorised auditor.
- The auditor receives the donation details privately, recomputes the commitment and checks the donation rules.
- A public verifier checks the auditor's signature, the signed statement and a shared, persistent SQLite replay registry. It never sees the amount, donor, charity or nonce.
- Baseline A publishes the donation in plain form and checks only the rules.
- Baseline B publishes the plain donation signed by the charity and uses the same replay registry.

## How to run it

Requires Python 3.10 or later.

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 donation_verify.py
```

On Windows, activate the environment with `venv\Scripts\activate` instead.

The script runs the 27 functional tests, the mutation tests (each of the 12 defences switched off in turn), the privacy scan, and the timing, verification-breakdown, scaling and record-size measurements (five runs of 1,000 trials, each after 50 warm-up runs). It writes `results.json`, `results.md`, `fig_timing.png`, `fig_breakdown.png` and `fig_scaling.png` next to itself. The run reported in the thesis took about 25 seconds. Times will differ on other hardware.

## Results in this repository

| Folder | Machine | Used in the thesis |
|---|---|---|
| `results/linux-vm` | Linux virtual machine (kernel 6.8, aarch64, 4 virtual CPUs, 3.8 GiB RAM) on an Apple-silicon MacBook Air; Python 3.10.12, cryptography 50.0.2, SQLite 3.37.2 | All tables and figures in Chapter 4 |
| `results/macos` | macOS 15.7.7 (arm64, 8 CPUs); Python 3.14.4, cryptography 50.0.2, SQLite 3.53.0 | Second set-up, Section 4.7 |

## Checking the file

SHA-256 of `donation_verify.py`:

```
263bcfc01d2a2d95f7032eb8c586d3e978c1b0e463fc04c691bc7122bbb6fc75
```

Check it with `shasum -a 256 donation_verify.py` (macOS) or `sha256sum donation_verify.py` (Linux).

## How the code was made

The code was written with an AI assistant (Claude) and reviewed by the author, as stated in the thesis's AI Use Statement and Section 3.7. Because the same process produced the code and its tests, the tests are not an independent check of the design.

## Papers

The papers cited are listed with DOIs in the thesis References. Their PDFs are not included because they are the copyright of their publishers.


## Literature search

The literature search used Consensus (consensus.app), as stated in the thesis's AI Use Statement. Shared search threads:

1. [Charity Donation Distrust Effects](https://consensus.app/search/charity-donation-distrust-effects/LDCjcg58QzSnCwwXuiTyaw/?utm_source=share&utm_medium=clipboard)
2. [Online Donation Platform Fees](https://consensus.app/search/online-donation-platform-fees/2nzATli8RTeg7dWQHaWgnQ/?utm_source=share&utm_medium=clipboard)
3. [Blockchain Donation Privacy Systems](https://consensus.app/search/blockchain-donation-privacy-systems/eweYiK3kRPalDhy0tLoIUQ/?utm_source=share&utm_medium=clipboard)
4. [Donor Privacy Anonymity Motivations](https://consensus.app/search/donor-privacy-anonymity-motivations/PeJZeqsuQnCfxn7pMP6SUQ/?utm_source=share&utm_medium=clipboard)
5. [Blockchain Transparency and Privacy](https://consensus.app/search/blockchain-transparency-and-privacy/PxUjXxIXSjCZl4PhNijh6A/?utm_source=share&utm_medium=clipboard)

