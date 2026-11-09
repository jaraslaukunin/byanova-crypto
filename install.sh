#!/usr/bin/env sh
set -eu

REPO="https://github.com/jaraslaukunin/byanova-crypto"
BRANCH="main"
BIN_DIR="${HOME}/.local/bin"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

printf '\033[36m\033[1m\n  BYANOVA · installer\n\033[0m'
printf '  Preparing the BYCR terminal console...\n\n'

if ! command -v go >/dev/null 2>&1; then
  printf '\033[31mError:\033[0m Go 1.23+ is required. Install Go from https://go.dev/dl/ and retry.\n' >&2
  exit 1
fi

GO_VERSION="$(go version | awk '{print $3}' | sed 's/^go//')"
GO_MAJOR="$(printf '%s' "$GO_VERSION" | cut -d. -f1)"
GO_MINOR="$(printf '%s' "$GO_VERSION" | cut -d. -f2)"
if [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 23 ]; }; then
  printf '\033[31mError:\033[0m Go 1.23+ is required (found %s).\n' "$GO_VERSION" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  printf '\033[31mError:\033[0m curl is required to download BYANOVA.\n' >&2
  exit 1
fi

mkdir -p "$BIN_DIR"
printf '  Downloading source...\n'
curl -fsSL "$REPO/archive/refs/heads/$BRANCH.tar.gz" -o "$TMP_DIR/source.tar.gz"
tar -xzf "$TMP_DIR/source.tar.gz" -C "$TMP_DIR"
SRC_DIR="$TMP_DIR/byanova-crypto-$BRANCH"

printf '  Compiling for %s/%s...\n' "$(go env GOOS)" "$(go env GOARCH)"
(
  cd "$SRC_DIR"
  go mod download
  go build -trimpath -ldflags="-s -w" -o "$TMP_DIR/bycr" .
)

install -m 0755 "$TMP_DIR/bycr" "$BIN_DIR/bycr"

SHELL_NAME="$(basename "${SHELL:-sh}")"
PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
case "$SHELL_NAME" in
  fish)
    CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/fish"
    mkdir -p "$CONFIG_DIR"
    CONFIG_FILE="$CONFIG_DIR/config.fish"
    FISH_LINE='fish_add_path "$HOME/.local/bin"'
    touch "$CONFIG_FILE"
    if ! grep -Fq "$FISH_LINE" "$CONFIG_FILE"; then
      printf '\n# BYANOVA command line\n%s\n' "$FISH_LINE" >> "$CONFIG_FILE"
    fi
    ;;
  zsh)
    CONFIG_FILE="$HOME/.zshrc"
    touch "$CONFIG_FILE"
    if ! grep -Fq '.local/bin' "$CONFIG_FILE"; then
      printf '\n# BYANOVA command line\n%s\n' "$PATH_LINE" >> "$CONFIG_FILE"
    fi
    ;;
  bash)
    CONFIG_FILE="$HOME/.bashrc"
    touch "$CONFIG_FILE"
    if ! grep -Fq '.local/bin' "$CONFIG_FILE"; then
      printf '\n# BYANOVA command line\n%s\n' "$PATH_LINE" >> "$CONFIG_FILE"
    fi
    ;;
  *)
    CONFIG_FILE="$HOME/.profile"
    touch "$CONFIG_FILE"
    if ! grep -Fq '.local/bin' "$CONFIG_FILE"; then
      printf '\n# BYANOVA command line\n%s\n' "$PATH_LINE" >> "$CONFIG_FILE"
    fi
    ;;
esac

printf '\n\033[32m\033[1m  ✓ BYANOVA installed successfully!\033[0m\n'
printf '  Binary: %s/bycr\n' "$BIN_DIR"
printf '  Shell config updated: %s\n\n' "$CONFIG_FILE"
printf '  Open a new terminal (or reload your shell config), then run:\n\n'
printf '    \033[36mbycr\033[0m       Start the interactive console\n'
printf '    \033[36mbycr help\033[0m  Show command-line help\n\n'
