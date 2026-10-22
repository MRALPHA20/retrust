#!/usr/bin/env bash
set -euo pipefail

# Build data into Render's deployment artifact. Runtime requests only read it,
# so restarts do not depend on a paid persistent disk or repeat downloads.
python -m pip install .
python -u -m retrust.cli setup --force

# The exploitation-estimate page needs historical EPSS as well as current EPSS.
if [[ "${RETRUST_BUILD_LEV_HISTORY:-1}" == "1" ]]; then
  python -u -m retrust.cli lev --update
fi

python -m retrust.cli stats

# Refuse deployment if any indexed product fails the independent formula check.
python -m retrust.formula_check --output data/formula-validation.json
