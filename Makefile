# ============================================================
# 3nricher — developer convenience commands
# ============================================================
#
# Common usage:
#
#   make build                   Build the Docker image
#   make enrich                  Enrich IOCs from iocs.txt
#   make enrich FILE=other.txt   Enrich IOCs from a specific file
#   make query IOC=8.8.8.8       Query a single IOC
#   make test                    Run the local test suite
#   make clean                   Remove generated files
#
# ============================================================

# --- Configuration ---
UID_VAL    := $(shell id -u)
GID_VAL    := $(shell id -g)
IMAGE      := 3nricher:latest
IOCS_FILE  ?= iocs.txt
OUT_DIR    := out

# Absolute paths (avoid $PWD issues)
ROOT       := $(shell pwd)
IOCS_ABS   := $(ROOT)/$(IOCS_FILE)
OUT_ABS    := $(ROOT)/$(OUT_DIR)

# Docker volume names (persist across runs)
CACHE_VOL  := 3nricher-cache
DATA_VOL   := 3nricher-data

# Suppress Make's default chatty output
MAKEFLAGS += --no-print-directory

.PHONY: help build enrich query test clean shell

# ------------------------------------------------------------
# help — default target
# ------------------------------------------------------------
help:
	@echo ""
	@echo "3nricher — available commands"
	@echo ""
	@echo "  make build                     Build the Docker image"
	@echo "  make enrich                    Enrich IOCs from iocs.txt"
	@echo "  make enrich FILE=threats.txt   Enrich IOCs from a specific file"
	@echo "  make query IOC=8.8.8.8         Query a single IOC"
	@echo "  make query IOC=google.com      Query a domain"
	@echo "  make test                      Run the local test suite"
	@echo "  make shell                     Open a shell in the container"
	@echo "  make clean                     Remove generated files"
	@echo ""

# ------------------------------------------------------------
# build — build the Docker image with matching UID/GID
# ------------------------------------------------------------
build:
	@echo "Building image with UID=$(UID_VAL) GID=$(GID_VAL)..."
	@docker build \
		--build-arg UID=$(UID_VAL) \
		--build-arg GID=$(GID_VAL) \
		-t $(IMAGE) \
		.
	@echo "Image built: $(IMAGE)"

# ------------------------------------------------------------
# enrich — process a file of IOCs
# ------------------------------------------------------------
enrich: build
	@if [ ! -f "$(IOCS_ABS)" ]; then \
		echo "ERROR: IOC file not found: $(IOCS_ABS)"; \
		echo "Create one or pass FILE=path/to/file"; \
		exit 1; \
	fi
	@mkdir -p $(OUT_ABS)
	@echo "Enriching IOCs from $(IOCS_FILE) ..."
	@docker run --rm \
		--env-file .env \
		-v $(CACHE_VOL):/app/cache \
		-v $(DATA_VOL):/app/data \
		-v $(IOCS_ABS):/data/iocs.txt:ro \
		-v $(OUT_ABS):/data/out \
		$(IMAGE) enrich -f /data/iocs.txt -o /data/out/report
	@echo ""
	@echo "Reports written to $(OUT_DIR)/"

# ------------------------------------------------------------
# query — enrich a single IOC on the command line
# ------------------------------------------------------------
query: build
	@if [ -z "$(IOC)" ]; then \
		echo "ERROR: specify an IOC, e.g.:"; \
		echo "  make query IOC=8.8.8.8"; \
		echo "  make query IOC=google.com"; \
		echo "  make query IOC=44d88612fea8a8f36de82e1278abb02f"; \
		exit 1; \
	fi
	@docker run --rm \
		--env-file .env \
		-v $(CACHE_VOL):/app/cache \
		-v $(DATA_VOL):/app/data \
		$(IMAGE) query $(IOC) || true

# ------------------------------------------------------------
# test — run the local test suite
# ------------------------------------------------------------
test:
	@echo "Running test suite..."
	@python -m pytest -q

# ------------------------------------------------------------
# shell — open an interactive shell in the container
# ------------------------------------------------------------
shell: build
	@docker run --rm -it \
		--env-file .env \
		-v $(CACHE_VOL):/app/cache \
		-v $(DATA_VOL):/app/data \
		$(IMAGE) sh

# ------------------------------------------------------------
# clean — remove generated artifacts
# ------------------------------------------------------------
clean:
	@echo "Cleaning generated files..."
	@rm -f report*.json report*.csv
	@rm -rf $(OUT_DIR)
	@echo "Done."

# ------------------------------------------------------------
# clean-volumes — remove Docker named volumes
# ------------------------------------------------------------
clean-volumes:
	@echo "Removing Docker volumes..."
	@docker volume rm $(CACHE_VOL) $(DATA_VOL) 2>/dev/null || true
	@echo "Done."
