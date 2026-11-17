.PHONY: build test test-race vet static clean check-tools check-source format-check test-scripts test-detection verify rpm

BUILD_DIR ?= build
RPM_OUTPUT_DIR ?= dist/rpm

build:
	mkdir -p "$(BUILD_DIR)"
	go build -buildvcs=false -trimpath -o "$(BUILD_DIR)/sentineld" ./cmd/sentineld
	go build -buildvcs=false -trimpath -o "$(BUILD_DIR)/sentinel" ./cmd/sentinel
	go build -buildvcs=false -trimpath -o "$(BUILD_DIR)/sentinel-web" ./cmd/sentinel-web

test:
	go test ./...
	cd protocol && go test ./...

test-race:
	go test -race ./...
	cd protocol && go test -race ./...

vet:
	go vet ./...
	cd protocol && go vet ./...

static:
	mkdir -p "$(BUILD_DIR)"
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags='-s -w' -o "$(BUILD_DIR)/sentineld" ./cmd/sentineld
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags='-s -w' -o "$(BUILD_DIR)/sentinel" ./cmd/sentinel
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags='-s -w' -o "$(BUILD_DIR)/sentinel-web" ./cmd/sentinel-web

check-tools:
	@for tool in go gofmt git python3 node; do \
		command -v "$$tool" >/dev/null 2>&1 || { echo "Required verification tool is missing: $$tool" >&2; exit 1; }; \
	done
	@python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || { echo 'Python 3.9 or newer is required.' >&2; exit 1; }

check-source:
	@if [ -f .local/private-source-patterns.txt ]; then \
		python3 scripts/check-source.py --private-patterns-file .local/private-source-patterns.txt; \
	else \
		python3 scripts/check-source.py; \
	fi

format-check:
	@files=$$(gofmt -l cmd internal protocol) || exit 1; \
		if [ -n "$$files" ]; then printf 'Run gofmt on:\n%s\n' "$$files" >&2; exit 1; fi

test-scripts:
	@for script in install.sh packaging/install_test.sh scripts/*.sh; do bash -n "$$script" || exit 1; done
	@for script in internal/webpanel/assets/*.js; do node --check "$$script" || exit 1; done
	bash packaging/install_test.sh
	bash scripts/build_rpm_test.sh
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p check_source_test.py

verify:
	$(MAKE) check-tools
	$(MAKE) check-source
	$(MAKE) format-check
	$(MAKE) test-scripts
	$(MAKE) vet
	$(MAKE) test-race
	$(MAKE) static
	$(MAKE) test-detection

test-detection:
	python3 scripts/check-detection.py --bin-dir "$(BUILD_DIR)"

rpm:
	./scripts/build-rpm.sh --output-dir "$(RPM_OUTPUT_DIR)"

clean:
	go clean
