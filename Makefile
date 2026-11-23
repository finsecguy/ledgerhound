.PHONY: example check-em-dash

example:
	python scripts/build_example.py

check-em-dash:
	python scripts/check_no_em_dash.py
