.PHONY: install run test lint docker-up clean

install:
	python -m pip install -e ".[dev]"

run:
	uvicorn aegisnet.main:app --reload

test:
	pytest

lint:
	ruff check src tests

docker-up:
	docker compose up --build

clean:
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info aegisnet.db
