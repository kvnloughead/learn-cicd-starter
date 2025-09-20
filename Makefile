include .env

# ============================================================
# RUN
# ============================================================

## run/server: builds and runs the notely server
.PHONY: run/server
run/server:
	go build -o notely && ./notelyc

# ============================================================
# HELPERS
# ============================================================

## help: print this help message
.PHONY: help
help:
	@echo "\nUsage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'
	@echo "\nFlags: \n"
	@echo "  Command line flags are supported for run/api and run/air.\n  Specify them like this: "
	@echo "\n\t  make FLAGS=\"-x -y\" command"
	@echo "\n  For a list of implemented flags for the ./cmd/api application, \n  run 'make help/web'\n"
	@echo "\nEnvironmental Variables:\n"
	@echo "  Environmental variables are supported for run/api and run/air.\n  They can be exported to the environment, or stored in a .env file.\n"

.PHONY: confirm
confirm:
	@echo 'Are you sure? [y/N] ' && read ans && [ $${ans:-N} = y ]

