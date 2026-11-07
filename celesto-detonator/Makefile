.PHONY: up fixtures test unit eval drill contain concurrency lifecycle finalize all
export PYTHONPATH := src
up:          ; docker compose up --build -d
fixtures:    ; python -c "from detonator.fixtures_build import build_all; print(build_all())"
unit:        ; python -m pytest tests/test_units.py tests/test_api.py -q
eval:        ; python scripts/run_eval.py 20
drill:       ; python scripts/run_failure_drill.py
contain:     ; python scripts/run_containment.py
concurrency: ; python scripts/run_concurrency.py 5
lifecycle:   ; python scripts/run_lifecycle_drill.py
finalize:    ; python scripts/finalize.py
test:        ; python -m pytest -q
# Everything that produces the graded files from REAL runs, then grades them:
all: contain drill eval concurrency lifecycle finalize test
