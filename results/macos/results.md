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
| commitment | 5.8 | 5.6 to 5.9 | 5.9 | 0.8 | 24.6 | 5.7 to 6.1 |
| auditor_check_and_sign | 37.9 | 37.8 to 38.2 | 38.3 | 1.2 | 62.2 | 37.9 to 38.6 |
| public_verification | 356.5 | 338.9 to 377.4 | 375.5 | 418.9 | 29731.6 | 345.5 to 405.5 |
| baseline_A_rule_check | 2.8 | 2.7 to 2.8 | 2.8 | 0.5 | 32.7 | 2.7 to 2.9 |
| baseline_B_signed_record_check | 356.0 | 337.8 to 377.2 | 369.3 | 57.9 | 1164.1 | 351.6 to 387.0 |
| end_to_end | 400.4 | 382.8 to 421.6 | 419.7 | 419.0 | 29776.1 | 389.2 to 450.1 |

## Breakdown of verification (µs; separate loop, 5 runs x 1000 trials)

| Part | Median | IQR | Mean | 95% CI of mean (from 5 run means) |
|---|---|---|---|---|
| design_signature_verify | 88.1 | 86.2 to 89.4 | 92.6 | 81.4 to 103.8 |
| design_statement_checks | 3.1 | 3.0 to 3.3 | 3.4 | 3.1 to 3.8 |
| design_registry_claim | 247.1 | 231.1 to 274.5 | 288.7 | 255.7 to 321.7 |
| B_signature_verify | 88.6 | 86.1 to 89.7 | 88.9 | 87.7 to 90.1 |
| B_rule_checks | 3.0 | 2.8 to 3.2 | 3.5 | 2.7 to 4.3 |
| B_registry_claim | 248.1 | 232.6 to 275.1 | 282.0 | 247.9 to 316.1 |
| registry_claim_in_memory | 4.6 | 4.3 to 5.3 | 5.6 | 4.4 to 6.8 |

## Scaling of full commitment (µs)

| Memo bytes | Record bytes | Median | Mean | SD |
|---|---|---|---|---|
| 0 | 122 | 4.0 | 4.0 | 0.0 |
| 64 | 196 | 4.3 | 4.3 | 0.1 |
| 128 | 260 | 4.5 | 4.5 | 0.1 |
| 256 | 388 | 5.0 | 5.0 | 0.3 |
| 512 | 644 | 5.8 | 5.9 | 0.3 |
| 1,024 | 1,156 | 7.2 | 7.2 | 0.1 |
| 2,048 | 2,180 | 10.1 | 10.2 | 0.6 |
| 4,096 | 4,228 | 15.8 | 15.9 | 0.2 |
| 8,192 | 8,324 | 27.3 | 27.5 | 0.9 |
| 16,384 | 16,516 | 50.5 | 50.9 | 1.1 |
| 32,768 | 32,900 | 115.4 | 108.9 | 8.9 |
| 65,536 | 65,668 | 192.5 | 195.4 | 15.4 |
| 131,072 | 131,204 | 374.1 | 376.7 | 5.3 |
| 262,144 | 262,276 | 745.3 | 754.5 | 31.8 |
| 524,288 | 524,420 | 1500.1 | 1547.0 | 157.4 |
| 1,048,576 | 1,048,708 | 3002.4 | 3077.8 | 249.9 |

## Storage

- commitment_bytes: 32
- signature_bytes: 64
- statement_bytes: 282
- design_public_record_bytes: 589
- baseline_A_public_record_bytes: 122
- baseline_B_public_record_bytes: 265
- private_opening_bytes: 154

## Environment

- os: macOS-15.7.7-arm64-arm-64bit-Mach-O
- python: 3.14.4
- machine: arm64
- cpus: 8
- memory: 
- cryptography: 50.0.2
- sqlite: 3.53.0
- timer_floor_median_us: 0.083
