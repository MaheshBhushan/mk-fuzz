## Results

### `cjson_target` — 30,000 executions per run

| scheduler | seeds | median edges | range | vs baseline (median) | paired W-L | sign-test p | median execs/s |
|---|---|---|---|---|---|---|---|
| `baseline` | 5 | 311 | 308–319 | — | — | — | 2438 |
| `bandit` | 5 | 304 | 300–305 | -7 (-2.3%) | 0-5 | 0.062 | 2214 |
| `linucb` | 5 | 305 | 299–319 | -6 (-1.9%) | 2-3 | 1.000 | 2369 |

Did the learned schedulers actually adapt? Total-variation distance, from actual operator-selection counts. The baseline row is the sampling-noise floor: it cannot adapt by construction, so anything near its value is noise.

| scheduler | TV(first 1k, last 1k) median | range | TV(run, hand-tuned weights) median | range |
|---|---|---|---|---|
| `baseline` | 0.0124 | 0.0073–0.0134 | 0.0011 | 0.0009–0.0014 |
| `bandit` | 0.0574 | 0.0467–0.0738 | 0.0936 | 0.0871–0.1053 |
| `linucb` | 0.0437 | 0.0245–0.0658 | 0.1422 | 0.1407–0.1447 |

### `zlib_target` — 200,000 executions per run

| scheduler | seeds | median edges | range | vs baseline (median) | paired W-L | sign-test p | median execs/s |
|---|---|---|---|---|---|---|---|
| `baseline` | 5 | 510 | 486–516 | — | — | — | 1706 |
| `bandit` | 5 | 510 | 490–513 | +0 (+0.0%) | 3-2 | 1.000 | 1788 |
| `linucb` | 5 | 493 | 474–509 | -17 (-3.3%) | 1-4 | 0.375 | 2009 |

Did the learned schedulers actually adapt? Total-variation distance, from actual operator-selection counts. The baseline row is the sampling-noise floor: it cannot adapt by construction, so anything near its value is noise.

| scheduler | TV(first 1k, last 1k) median | range | TV(run, hand-tuned weights) median | range |
|---|---|---|---|---|
| `baseline` | 0.0095 | 0.0076–0.0128 | 0.0004 | 0.0003–0.0005 |
| `bandit` | 0.0748 | 0.0390–0.1561 | 0.0970 | 0.0866–0.1307 |
| `linucb` | 0.0607 | 0.0277–0.0696 | 0.1438 | 0.1415–0.1451 |

