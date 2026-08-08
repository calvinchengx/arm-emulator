# Thin wrappers over the docker compose workflow. The compose file remains the
# source of truth; this exists so the everyday cycle is one word each, and so
# the whole emulator family is driven the same way. Nothing here is required —
# every target shows the command it runs.
#
#   make up      # start the pair (entra-emulator + arm-emulator)
#   make status  # is the pair actually usable? (exit non-zero if not)
#   make down    # stop and remove the containers
#
# Linux, macOS and Windows. On Windows the recipes run under a POSIX shell —
# `sh.exe` from Git for Windows, which also supplies the grep/awk/curl the
# scripts use. Install once and everything below works from PowerShell or cmd:
#
#   winget install Git.Git         # provides sh.exe + grep/awk/cut/curl
#   winget install ezwinports.make # GNU Make itself (no admin needed)
#
# `make doctor` checks the whole toolchain and prints what is missing.
#
# The pair is entra (issues ARM-audience tokens) + arm (validates them and
# stores role assignments). The data planes that consume its authorization
# feed bring up their own compose stacks.
PROFILE ?=
COMPOSE  = docker compose $(PROFILE)

# Windows: force the recipes onto sh.exe. GNU Make on Windows falls back to
# cmd.exe when it cannot find a shell, and cmd cannot run a single line of what
# is below. Make searches PATH for this itself, so the spaces in
# "C:\Program Files\Git\bin" are its problem, not ours.
ifeq ($(OS),Windows_NT)
  SHELL := sh.exe
  .SHELLFLAGS := -c
endif

# Which interpreter is "python3" is not a given. On Windows `python3` normally
# resolves to the Microsoft Store *alias stub*: it exists on PATH, so
# `command -v python3` succeeds, and then it exits 49 with a "not found, install
# from the Store" message. Detection therefore has to RUN each candidate, not
# merely locate it. Override with PY= if you keep python somewhere unusual.
PY ?= $(shell for c in python3 python py; do if "$$c" -c '' >/dev/null 2>&1; then echo "$$c"; break; fi; done)

.PHONY: help doctor up down restart clean status logs ps test

help: ## Show the available targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'

doctor: ## Check the toolchain and the docker context this Makefile needs
	@sh scripts/doctor.sh

up: ## Start the pair (entra + arm) in the background
	$(COMPOSE) up -d

down: ## Stop and remove containers
	$(COMPOSE) down

clean: ## Stop and remove containers AND any anonymous volumes (full reset)
	$(COMPOSE) down -v

restart: clean up ## Full reset: clean, then start again

status: ## Report whether the pair is usable (non-zero exit if not)
	@sh scripts/status.sh

ps: ## Container states for this project
	$(COMPOSE) ps

logs: ## Tail logs (SVC=<service> to narrow)
	$(COMPOSE) logs -f --tail 100 $(SVC)

test: ## Go build, vet and unit tests (starts a real entra-emulator in-process)
	go build ./... && go vet ./... && go test ./...

# The cross-emulator chains that exercise this ARM surface live in the repos
# that consume it (azure-keyvault-emulator's e2e/arm-chain and e2e/az-cli),
# because that is where the assertion — "the data plane enforced it" — belongs.
