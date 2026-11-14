#!/bin/bash
# Build do macOS (somente CLI). Requer as Command Line Tools do Xcode:
#   xcode-select --install
# Os utilitários Go (ardc-tunnel, nord-confgen, proton-confgen) já vêm
# compilados em PC/bin/macos-<arquitetura>/; este script compila apenas o
# executável C++ e o copia para a raiz do repositório.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
OUTPUT="$SCRIPT_DIR/../ARDiscordBypass_macos"

case "$(uname -m)" in
    arm64)  HELPER_DIR="macos-arm64" ;;
    x86_64) HELPER_DIR="macos-amd64" ;;
    *) echo "ERRO: arquitetura nao suportada: $(uname -m)"; exit 1 ;;
esac

echo "========================================="
echo "  ARDiscordBypass v3.5.0 - Build macOS"
echo "  Arquitetura: $(uname -m) (CLI)"
echo "========================================="
echo ""

for arg in "$@"; do
    if [ "$arg" = "--gui" ]; then
        echo "AVISO: a interface grafica ainda nao esta disponivel no macOS; compilando apenas a CLI."
        echo ""
    fi
done

if ! command -v clang++ >/dev/null 2>&1; then
    echo "ERRO: clang++ nao encontrado. Instale as Command Line Tools: xcode-select --install"
    exit 1
fi

echo "[1/2] Compilando..."
mkdir -p "$BUILD_DIR"
clang++ -std=c++20 -O2 -Wall -I"$SCRIPT_DIR" "$SCRIPT_DIR/main.cpp" -o "$BUILD_DIR/ARDiscordBypass_macos"
cp "$BUILD_DIR/ARDiscordBypass_macos" "$OUTPUT"

echo "[2/2] Conferindo utilitarios em PC/bin/$HELPER_DIR/..."
MISSING=""
for helper in ardc-tunnel nord-confgen proton-confgen; do
    if [ -f "$SCRIPT_DIR/bin/$HELPER_DIR/$helper" ]; then
        chmod +x "$SCRIPT_DIR/bin/$HELPER_DIR/$helper"
    else
        MISSING="$MISSING $helper"
    fi
done
# Arquivos baixados pelo navegador (zip do repositorio) chegam em quarentena e
# o macOS se recusa a executa-los; clones via git nao tem esse atributo.
xattr -dr com.apple.quarantine "$SCRIPT_DIR/bin/$HELPER_DIR" "$OUTPUT" 2>/dev/null || true

echo ""
if [ -n "$MISSING" ]; then
    echo "AVISO: utilitarios ausentes em PC/bin/$HELPER_DIR/:$MISSING"
    echo "  Compile-os com Go (ver tools/macos-tunnel/README.md)."
    echo ""
fi
echo "Build concluido com sucesso!"
echo "  ✔ CLI: $OUTPUT"
echo ""
echo "Para executar (a partir da raiz do repositorio):"
echo "  ./ARDiscordBypass_macos            # abre o Discord Web num navegador dentro do tunel"
echo "  ./ARDiscordBypass_macos --stop     # fecha esse navegador e remove o tunel"
echo "  ./ARDiscordBypass_macos --diag     # estado do tunel, para investigar falhas"
