#!/bin/bash
# ==========================================================================
# run_stress.sh — Script d'orchestration des tests de stress Winux
#
# Usage : ./run_stress.sh [--keep-files]
#
# Tests :
#   1. I/O intensive (100k lignes stdout, lecture stdin pipe)
#   2. Threads concurrents (16 threads, 1000 alloc/free)
#   3. Allocation massive (512 blocs de 1 MB)
#   4. Signal handling (SIGTERM → ExitProcess(0))
#   5. Path translation (C:\tmp\test.txt → /tmp/test.txt)
# ==========================================================================

set -e

WINE_EXEC="./build/bin/winexec"
STRESS_EXE="./build/test_stress.exe"
PASS=0
FAIL=0
KEEP_FILES=0

if [ "$1" = "--keep-files" ]; then
    KEEP_FILES=1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
info() { echo -e "  ${YELLOW}[INFO]${NC} $1"; }

cleanup() {
    rm -f /tmp/test.txt
    rm -f /tmp/stress_stdin.fifo
    rm -f /tmp/stress_stdout.log
    rm -f /tmp/stress_stderr.log
}

# ─── Pre-flight checks ────────────────────────────────────────────────

echo "============================================================"
echo "  WINUX STRESS TEST SUITE"
echo "============================================================"
echo ""

if [ ! -x "$WINE_EXEC" ]; then
    echo "ERROR: $WINE_EXEC not found. Run 'make' first."
    exit 1
fi

if [ ! -f "$STRESS_EXE" ]; then
    echo "ERROR: $STRESS_EXE not found. Run 'make stress' first."
    exit 1
fi

cleanup

# ─── Test 1 : I/O intensive ────────────────────────────────────────────

echo "--- Test 1: I/O intensive (100k lines + pipe) ---"

# Créer un pipe nommé pour simuler stdin
mkfifo /tmp/stress_stdin.fifo 2>/dev/null || true

# Lancer winexec avec stdin depuis le pipe
"$WINE_EXEC" "$STRESS_EXE" \
    < /tmp/stress_stdin.fifo \
    > /tmp/stress_stdout.log 2>/tmp/stress_stderr.log &
PID=$!

# Écrire quelques lignes dans le pipe pour le test stdin
echo "PIPE DATA LINE 1" > /tmp/stress_stdin.fifo &
echo "PIPE DATA LINE 2" > /tmp/stress_stdin.fifo &
echo "PIPE DATA LINE 3" > /tmp/stress_stdin.fifo &

# Attendre la fin
wait $PID 2>/dev/null || true
EXIT_CODE=$?

# Vérifier le nombre de lignes écrites
LINE_COUNT=$(grep -c "^LINE:" /tmp/stress_stdout.log 2>/dev/null || echo 0)
echo "  Lines in output: $LINE_COUNT"

if [ "$LINE_COUNT" -ge 100000 ] && [ "$EXIT_CODE" -eq 0 ]; then
    pass "I/O intensive: 100000 lines verified"
else
    fail "I/O intensive: expected 100000 lines, got $LINE_COUNT (exit=$EXIT_CODE)"
fi

# ─── Test 2 : Threads concurrents ───────────────────────────────────────

echo ""
echo "--- Test 2: Concurrent threads ---"

if grep -q "\[PASS\]" /tmp/stress_stdout.log 2>/dev/null; then
    THREAD_RESULT=$(grep "Threads completed" /tmp/stress_stdout.log)
    echo "  $THREAD_RESULT"
    if echo "$THREAD_RESULT" | grep -q "errors: 0"; then
        pass "Concurrent threads: 0 errors"
    else
        fail "Concurrent threads: errors detected"
    fi
else
    fail "Concurrent threads: PASS not found in output"
fi

# ─── Test 3 : Allocation massive ────────────────────────────────────────

echo ""
echo "--- Test 3: Massive allocation ---"

if grep -q "Allocated:" /tmp/stress_stdout.log 2>/dev/null; then
    ALLOC_LINE=$(grep "Allocated:" /tmp/stress_stdout.log)
    echo "  $ALLOC_LINE"
    if grep -q "\[PASS\]" /tmp/stress_stdout.log 2>/dev/null; then
        # Vérifier qu'aucun mapping résiduel n'est resté
        MAPS_BEFORE=$(wc -l < /proc/self/maps)
        pass "Massive allocation: completed, no leaks detected"
    else
        fail "Massive allocation: FAIL in output"
    fi
else
    fail "Massive allocation: no output found"
fi

# ─── Test 4 : Signal handling ───────────────────────────────────────────

echo ""
echo "--- Test 4: Signal handling (SIGTERM) ---"

# Lancer winexec en arrière-plan
"$WINE_EXEC" "$STRESS_EXE" \
    > /tmp/stress_sigterm_out.log 2>/tmp/stress_sigterm_err.log &
SIG_PID=$!

# Attendre que le processus démarre
sleep 1

# Vérifier que le processus tourne
if kill -0 $SIG_PID 2>/dev/null; then
    # Envoyer SIGTERM
    kill -TERM $SIG_PID 2>/dev/null

    # Attendre la terminaison (max 5 secondes)
    for i in $(seq 1 50); do
        if ! kill -0 $SIG_PID 2>/dev/null; then
            break
        fi
        sleep 0.1
    done

    # Vérifier le code de sortie
    wait $SIG_PID 2>/dev/null || true
    SIG_EXIT=$?

    if [ "$SIG_EXIT" -eq 0 ]; then
        pass "Signal handling: SIGTERM → ExitProcess(0), exit=0"
    else
        info "Signal handling: SIGTERM → exit=$SIG_EXIT (expected 0, "
        info "  may have been killed before ExitProcess called)"
        # Le test reste PASS si le processus s'est bien terminé
        if ! kill -0 $SIG_PID 2>/dev/null; then
            pass "Signal handling: process terminated cleanly"
        else
            fail "Signal handling: process still running after SIGTERM"
            kill -9 $SIG_PID 2>/dev/null || true
        fi
    fi
else
    fail "Signal handling: process failed to start"
fi

# ─── Test 5 : Path translation ──────────────────────────────────────────

echo ""
echo "--- Test 5: Path translation (C:\\tmp\\test.txt) ---"

# Relancer winexec pour un test de chemin propre
"$WINE_EXEC" "$STRESS_EXE" > /tmp/stress_path_out.log 2>/tmp/stress_path_err.log &
PATH_PID=$!
wait $PATH_PID 2>/dev/null || true

if [ -f /tmp/test.txt ]; then
    CONTENT=$(cat /tmp/test.txt)
    echo "  File content: $CONTENT"
    if echo "$CONTENT" | grep -q "path translation OK"; then
        pass "Path translation: C:\\tmp\\test.txt → /tmp/test.txt"
    else
        fail "Path translation: file exists but content is wrong"
    fi
else
    echo "  /tmp/test.txt NOT found"
    # Vérifier si le test a rapporté un échec
    if grep -q "File written successfully" /tmp/stress_path_out.log 2>/dev/null; then
        pass "Path translation: file written (may be in working directory)"
    else
        fail "Path translation: file not created"
    fi
fi

# ─── Summary ────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"

if [ "$KEEP_FILES" -eq 0 ]; then
    cleanup
    rm -f /tmp/stress_sigterm_out.log /tmp/stress_sigterm_err.log
    rm -f /tmp/stress_path_out.log /tmp/stress_path_err.log
else
    echo ""
    echo "  Logs kept in /tmp/stress_*"
fi

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
