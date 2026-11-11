# Notice

`lib/goose_receiver.c` and `lib/goose_publisher.c` are modified copies of the files
`src/goose/goose_receiver.c` and `src/goose/goose_publisher.c` from **libIEC61850 v1.5.3**
(https://github.com/mz-automation/libiec61850), Copyright 2014-2022 Michael Zillgith,
licensed under the GNU General Public License, version 3 or (at your option) any later version.
The modifications are described in the header comment of each file.

Because these files are derived from GPL-licensed code, this repository is distributed under the
**GNU General Public License v3.0 or later** (see `LICENSE`).

The Ascon reference implementation (ascon-c, https://github.com/ascon/ascon-c) is **not** included:
`setup.sh` downloads it at build time and records the exact commit in `versions.txt`.

This repository is not affiliated with, or endorsed by, MZ Automation GmbH or the authors of the
papers it refers to.
