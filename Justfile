set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set export

FUNCS_SCRIPT   := "./_scripts/funcs.sh"
ROOT           := justfile_directory()
CARGO_TOML     := ROOT / "Cargo.toml"
CARGO_LOCK     := ROOT / "Cargo.lock"
PKGBUILD       := ROOT / "packaging/aur/PKGBUILD"

RUST_BACKTRACE := env_var_or_default("RUST_BACKTRACE", "1")
GIT_REMOTE     := env_var_or_default("GIT_REMOTE", "origin")
MAIN_BRANCH    := env_var_or_default("MAIN_BRANCH", "main")

# The published artifact is the CLI and tray without GTK, linked statically.
STATIC_TARGET  := env_var_or_default("STATIC_TARGET", "x86_64-unknown-linux-musl")

# print help for Just targets
help:
    @just -l

# Install the tools the dev and release recipes need
deps:
    cargo install --locked cargo-edit
    cargo install --locked cargo-audit
    @echo
    @echo 'wayvnc, sway, grim and wl-clipboard are needed by the smoke tests.'
    @echo 'On NixOS they come with `nix develop`; elsewhere install them yourself.'

# Install binary dependencies (gh-actions)
bin-deps:
    cargo binstall --no-confirm cargo-edit
    cargo binstall --no-confirm cargo-audit

# Enter the Nix dev shell, which has GTK, wayvnc, sway and the test tooling
shell:
    nix develop

# Build with the GTK configuration window (the default)
build *args:
    cargo build --locked {{args}}

# Build the CLI and tray only; needs no GTK at all
build-cli *args:
    cargo build --locked --no-default-features {{args}}

# Build the statically linked binary that releases publish
#
# Needs a toolchain that ships std for the musl target. rustup does; the
# rustc in the Nix dev shell does not, so on NixOS run this under
# `nix shell nixpkgs#rustup nixpkgs#pkgsStatic.stdenv.cc`.
build-static:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v rustup >/dev/null 2>&1; then
        rustup target add "{{STATIC_TARGET}}" 2>/dev/null || true
    fi
    libdir=$(rustc --print target-libdir --target "{{STATIC_TARGET}}" 2>/dev/null || true)
    if [ -z "$libdir" ] || [ -z "$(ls "$libdir"/libcore-*.rlib 2>/dev/null)" ]; then
        echo "ERROR: this toolchain has no std for {{STATIC_TARGET}}." >&2
        echo "  With rustup:  rustup target add {{STATIC_TARGET}}" >&2
        echo "  On NixOS:     nix shell nixpkgs#rustup nixpkgs#pkgsStatic.stdenv.cc -c just build-static" >&2
        exit 1
    fi
    cargo build --release --locked --no-default-features --target "{{STATIC_TARGET}}"
    bin="target/{{STATIC_TARGET}}/release/swayshare"
    # The whole point of this artifact is having no runtime dependencies, so
    # assert it. Depending on whether rustc emits static-pie, ldd says either
    # "not a dynamic executable" or "statically linked"; anything else means
    # we have dynamic dependencies and the artifact is a lie.
    out=$(ldd "$bin" 2>&1 || true)
    case "$out" in
        *"not a dynamic executable"*|*"statically linked"*)
            echo "$bin: no dynamic dependencies ($out)" ;;
        *)
            echo "ERROR: $bin has dynamic dependencies:" >&2
            echo "$out" >&2
            exit 1 ;;
    esac

# Build and run the binary + args
run *args:
    cargo run --locked -- {{args}}

# Run the supervisor in the foreground
daemon *args:
    just run daemon {{args}}

# Run the tray applet (hosts a daemon if none is running)
tray *args:
    just run tray {{args}}

# Open the configuration window
gui *args:
    just run gui {{args}}

# Run tests with the GTK window
test *args:
    cargo test --locked {{args}}

# Run tests without GTK
test-cli *args:
    cargo test --locked --no-default-features {{args}}

# Run tests in both feature sets
test-all: test test-cli

# Run Clippy, denying warnings
clippy *args:
    cargo clippy --all-targets --locked {{args}} -- -D warnings

# Run Clippy in both feature sets
clippy-all:
    just clippy
    just clippy --no-default-features

# Format the source
fmt:
    cargo fmt --all

# Check formatting without changing anything
fmt-check:
    cargo fmt --all --check

# Everything CI runs: formatting, lints and tests in both feature sets
check: fmt-check clippy-all test-all
    @echo
    @echo "All checks passed."

# Audit dependencies for known vulnerabilities
audit:
    cargo audit

# End-to-end test of the gate against a real wayvnc on a headless Sway
e2e:
    ./scripts/e2e-smoke.sh

# Test the tray over a private D-Bus session
tray-smoke:
    ./scripts/tray-smoke.sh

# Test the configuration window under a headless Sway
gui-smoke:
    ./scripts/gui-smoke.sh

# Run all three smoke suites (needs wayvnc, sway, grim: use `nix develop`)
smoke: e2e tray-smoke gui-smoke

# Build the Nix packages
nix-build:
    nix build .#swayshare
    nix build .#swayshare-cli

# Build the release tarball locally, exactly as the release workflow does
package: build-static
    #!/usr/bin/env bash
    set -euo pipefail
    version=$(grep -Po '^version = \K.*' "{{CARGO_TOML}}" | sed -e 's/"//g' | head -1)
    name="swayshare-cli-${version}-x86_64-linux-musl"
    rm -rf dist
    mkdir -p "dist/$name"
    cp "target/{{STATIC_TARGET}}/release/swayshare" "dist/$name/swayshare"
    strip "dist/$name/swayshare"
    cp README.md LICENSE "dist/$name/"
    tar -C dist -czf "dist/$name.tar.gz" "$name"
    (cd dist && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
    ls -la dist/

# Clean all build artifacts
clean:
    cargo clean
    rm -rf dist

# Bump the version and create a release branch to open a PR from
bump-version level="patch":
    # Accepts an explicit version (1.2.3) or a level (patch, minor, major).
    # There is deliberately no git-cliff step: this project does not use
    # conventional commits, so the bump is stated rather than derived.
    @if [ -n "$(git status --porcelain)" ]; then echo "## Git status is not clean. Commit your changes before bumping version."; exit 1; fi
    @if [ "$(git symbolic-ref --short HEAD)" != "{{MAIN_BRANCH}}" ]; then echo "## You may only bump the version from the {{MAIN_BRANCH}} branch."; exit 1; fi
    @set -eo pipefail; \
    source {{FUNCS_SCRIPT}}; \
    check_deps cargo-set-version git; \
    CURRENT_VERSION=$(grep -Po '^version = \K.*' {{CARGO_TOML}} | sed -e 's/"//g' | head -1); \
    case "{{level}}" in \
      patch) VERSION=$(awk -F. '{print $1"."$2"."$3+1}' <<<"${CURRENT_VERSION}");; \
      minor) VERSION=$(awk -F. '{print $1"."$2+1".0"}' <<<"${CURRENT_VERSION}");; \
      major) VERSION=$(awk -F. '{print $1+1".0.0"}' <<<"${CURRENT_VERSION}");; \
      *) VERSION="{{level}}";; \
    esac; \
    if [ -z "${VERSION}" ]; then echo "## Could not determine the new version."; exit 1; fi; \
    echo; \
    (if git rev-parse v${VERSION} >/dev/null 2>&1; then \
      echo "New version tag already exists: v${VERSION}" && \
      echo "If you need to re-do this release, delete the existing tag (git tag -d v${VERSION})" && \
      exit 1; \
     fi \
    ); \
    echo "## Current version: v${CURRENT_VERSION}"; \
    confirm yes "New version would be \"v${VERSION}\"" " -- Proceed?"; \
    git checkout -B release-v${VERSION}; \
    cargo set-version ${VERSION}; \
    cargo update --workspace; \
    sed -i "s/^pkgver=.*$/pkgver=${VERSION}/" {{PKGBUILD}}; \
    sed -i "s/^pkgrel=.*$/pkgrel=1/" {{PKGBUILD}}; \
    git add {{CARGO_TOML}} {{CARGO_LOCK}} {{PKGBUILD}}; \
    git commit -m "release: v${VERSION}"; \
    echo "Bumped version: v${VERSION}"; \
    echo "Created new branch: release-v${VERSION}"; \
    echo "You should push this branch and create a PR for it."

# Tag and release the current version from the main branch
release:
    @if [ -n "$(git status --porcelain)" ]; then echo "## Git status is not clean. Commit your changes before releasing."; exit 1; fi
    @if [ "$(git symbolic-ref --short HEAD)" != "{{MAIN_BRANCH}}" ]; then echo "## You may only release the {{MAIN_BRANCH}} branch."; exit 1; fi
    git remote update
    @if [[ "$(git status -uno)" != *"Your branch is up to date"* ]]; then echo "## Git branch is not in sync with git remote ${GIT_REMOTE}."; exit 1; fi
    @set -eo pipefail; \
    source {{FUNCS_SCRIPT}}; \
    CURRENT_VERSION=$(grep -Po '^version = \K.*' {{CARGO_TOML}} | sed -e 's/"//g' | head -1); \
    if git rev-parse "v${CURRENT_VERSION}" >/dev/null 2>&1; then echo "Tag already exists: v${CURRENT_VERSION}"; exit 1; fi; \
    if (git ls-remote --tags "${GIT_REMOTE}" | grep -q "refs/tags/v${CURRENT_VERSION}" >/dev/null 2>&1); then echo "Tag already exists on remote ${GIT_REMOTE}: v${CURRENT_VERSION}"; exit 1; fi; \
    PKG_VERSION=$(grep -Po '^pkgver=\K.*' {{PKGBUILD}}); \
    if [ "${PKG_VERSION}" != "${CURRENT_VERSION}" ]; then echo "## PKGBUILD pkgver (${PKG_VERSION}) does not match Cargo.toml (${CURRENT_VERSION})."; exit 1; fi; \
    cargo audit; \
    confirm yes "New tag will be \"v${CURRENT_VERSION}\"" " -- Proceed?"; \
    git tag "v${CURRENT_VERSION}"; \
    git push "${GIT_REMOTE}" tag "v${CURRENT_VERSION}"
