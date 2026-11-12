.PHONY: check queries

check:
	pytest -q
	python -m detlab lint
	python -m detlab test

queries:
	rm -rf queries
	python -m detlab convert spl -o queries
	python -m detlab convert kql -o queries
