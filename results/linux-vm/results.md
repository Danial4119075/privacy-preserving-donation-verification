## Functional tests

| ID | Scenario | Property | Expected | Actual | Reason | Pass |
|---|---|---|---|---|---|---|
| TC01 | Valid donation, correct opening | Correctness | accept | accept | accepted | yes |
| TC02 | Amount changed after commitment | Binding | reject | reject | commitment does not match opening | yes |
| TC03 | Charity not in approved registry | Rule check | reject | reject | charity not in approved registry | yes |
| TC04 | Attestation signature tampered | Authenticity | reject | reject | invalid attestation signature | yes |
| TC05 | Replay at the same verifier | Replay resistance | reject | reject | replay: donation ID already accepted | yes |
| TC06 | Wrong nonce in the opening | Binding | reject | reject | commitment does not match opening | yes |
| TC07 | Replay at a second, independent verifier | Shared replay state | reject | reject | replay: donation ID already accepted | yes |
| TC08 | Same donation sent to 8 verifiers concurrently | Concurrency | accept | accept | 1 of 8 accepted | yes |
| TC09 | Replay after restart (reloaded key and registry) | Persistence | reject | reject | replay: donation ID already accepted | yes |
| TC10 | Attestation signed by an unknown key | Authenticity | reject | reject | unknown auditor key | yes |
| TC11 | Zero amount | Input validation | reject | reject | invalid amount | yes |
| TC12 | Negative amount | Input validation | reject | reject | invalid amount | yes |
| TC13 | Boolean amount (True) | Input validation | reject | reject | invalid amount | yes |
| TC14 | NaN amount | Input validation | reject | reject | invalid amount | yes |
| TC15 | Infinite amount | Input validation | reject | reject | invalid amount | yes |
| TC16 | Amount as text | Input validation | reject | reject | invalid amount | yes |
| TC17 | Amount above limit | Input validation | reject | reject | invalid amount | yes |
| TC18 | Missing field (charityID) | Input validation | reject | reject | record does not match schema | yes |
| TC19 | Unknown extra field | Input validation | reject | reject | record does not match schema | yes |
| TC20 | Malformed record | Input validation | reject | reject | malformed record | yes |
| TC21 | Attestation under an old policy version | Versioning | reject | reject | statement version or result not accepted | yes |
| TC22 | Valid attestation reused for another donation ID | Binding to record | reject | reject | statement does not match ledger record | yes |
| TC23 | Attestation under a revoked auditor key | Key revocation | reject | reject | auditor key revoked | yes |
| TC24 | Key rotation: old and new attestations both verify | Key rotation | accept | accept | old key accepted; new key accepted | yes |
| TC25 | Unsupported currency (USD) | Rule check | reject | reject | unsupported currency | yes |
| TC26 | Opening registered under a different donation ID | Binding to ID | reject | reject | donation ID does not match opening | yes |
| TC27 | Same donation sent to the auditor twice | Replay resistance (auditor) | reject | reject | donation ID already attested | yes |

## Mutation testing (one defence switched off at a time)

| Disabled check | Tests that then fail |
|---|---|
| commitment | TC02, TC06 |
| schema | TC18, TC19 |
| id_match | TC26 |
| amount | TC11, TC12, TC13, TC14, TC15, TC16, TC17 |
| currency | TC25 |
| registry | TC03 |
| auditor_replay | TC27 |
| registry_replay | TC05, TC07, TC08, TC09 |
| revocation | TC23 |
| signature | TC04, TC10 |
| version | TC21 |
| binding | TC22 |

## Privacy scan of the public record

| Private field | Found in public record? |
|---|---|
| amountCents | no |
| donorID | no |
| charityID | no |
| currency | no |
| nonce | no |

## Timing (µs; 5 runs x 1000 trials)

| Operation | Median | IQR | Mean | SD | Max | 95% CI of mean (from 5 run means) |
|---|---|---|---|---|---|---|
| commitment | 9.1 | 8.9 to 9.2 | 9.1 | 1.6 | 34.7 | 8.9 to 9.4 |
| auditor_check_and_sign | 43.4 | 43.0 to 43.7 | 43.6 | 2.9 | 65.0 | 43.1 to 44.1 |
| public_verification | 602.8 | 574.3 to 629.2 | 661.8 | 338.5 | 6441.3 | 639.3 to 684.3 |
| baseline_A_rule_check | 6.0 | 5.8 to 6.1 | 5.8 | 1.2 | 20.4 | 5.5 to 6.1 |
| baseline_B_signed_record_check | 599.4 | 570.2 to 626.5 | 661.1 | 360.8 | 7487.6 | 639.7 to 682.5 |
| end_to_end | 656.0 | 625.9 to 682.7 | 714.5 | 338.7 | 6493.7 | 691.5 to 737.6 |

## Breakdown of verification (µs; separate loop, 5 runs x 1000 trials)

| Part | Median | IQR | Mean | 95% CI of mean (from 5 run means) |
|---|---|---|---|---|
| design_signature_verify | 86.5 | 86.0 to 87.2 | 87.7 | 87.4 to 87.9 |
| design_statement_checks | 4.2 | 4.1 to 4.6 | 4.5 | 4.3 to 4.7 |
| design_registry_claim | 529.9 | 505.5 to 561.2 | 584.9 | 545.2 to 624.7 |
| B_signature_verify | 86.4 | 85.8 to 87.0 | 87.4 | 87.2 to 87.7 |
| B_rule_checks | 5.6 | 5.5 to 5.8 | 6.1 | 5.2 to 6.9 |
| B_registry_claim | 530.2 | 506.2 to 560.3 | 577.5 | 540.2 to 614.8 |
| registry_claim_in_memory | 8.6 | 8.4 to 9.3 | 9.5 | 8.3 to 10.8 |

## Scaling of full commitment (µs)

| Memo bytes | Record bytes | Median | Mean | SD |
|---|---|---|---|---|
| 0 | 122 | 3.9 | 4.0 | 0.7 |
| 64 | 196 | 4.2 | 4.2 | 0.4 |
| 128 | 260 | 4.3 | 4.4 | 0.5 |
| 256 | 388 | 4.7 | 4.8 | 0.8 |
| 512 | 644 | 5.6 | 5.6 | 0.5 |
| 1,024 | 1,156 | 7.2 | 7.2 | 0.6 |
| 2,048 | 2,180 | 10.3 | 10.4 | 1.0 |
| 4,096 | 4,228 | 16.4 | 16.5 | 1.0 |
| 8,192 | 8,324 | 28.6 | 28.9 | 1.4 |
| 16,384 | 16,516 | 53.0 | 53.5 | 1.9 |
| 32,768 | 32,900 | 101.8 | 102.7 | 2.5 |
| 65,536 | 65,668 | 199.4 | 200.8 | 2.7 |
| 131,072 | 131,204 | 394.3 | 397.8 | 5.9 |
| 262,144 | 262,276 | 788.8 | 797.5 | 26.1 |
| 524,288 | 524,420 | 1658.9 | 1753.5 | 670.2 |
| 1,048,576 | 1,048,708 | 3201.8 | 3268.5 | 149.2 |

## Storage

- commitment_bytes: 32
- signature_bytes: 64
- statement_bytes: 282
- design_public_record_bytes: 589
- baseline_A_public_record_bytes: 122
- baseline_B_public_record_bytes: 265
- private_opening_bytes: 154

## Environment

- os: Linux-6.8.0-138-generic-aarch64-with-glibc2.35
- python: 3.10.12
- machine: aarch64
- cpus: 4
- memory: 4000484 kB
- cryptography: 50.0.2
- sqlite: 3.37.2
- timer_floor_median_us: 0.083
