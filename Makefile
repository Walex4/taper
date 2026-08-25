.PHONY: help install test redteam validate demo doctor preflight all clean

help:
	@echo "make install    install with dev dependencies"
	@echo "make test       unit + integration tests"
	@echo "make redteam    adversarial validation (every case must be refused)"
	@echo "make validate   preflight + test + redteam — run before every release"
	@echo "make demo       walk through attenuation end to end"
	@echo ""
	@echo "Boundary checks need real infrastructure and are not in 'validate':"
	@echo "  python validate/check_postgres.py \"postgresql://taper_agent:pw@host/db\""
	@echo "  bash validate/check_ssh.sh build-1.internal ~/.taper/id_build_1_internal"

install:
	pip install -e ".[dev]"

test:
	pytest -q

redteam:
	python validate/redteam.py

preflight:
	bash scripts/preflight.sh

demo:
	python demo.py

doctor:
	python -m taper.cli doctor

# The gate. If this is red, nothing ships.
validate: preflight test redteam
	@echo ""
	@echo "  Local validation passed."
	@echo "  Still required before trusting this with real credentials:"
	@echo "    validate/check_postgres.py  — proves the DATABASE refuses"
	@echo "    validate/check_ssh.sh       — proves SSHD refuses"
	@echo "  The broker is never the only boundary."

all: validate

clean:
	rm -rf .pytest_cache **/__pycache__ *.egg-info
