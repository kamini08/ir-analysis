#!/bin/bash
#
# analyze_bap.sh
# Runs BAP (Binary Analysis Platform) on a single binary and lifts to BIL IR.
#
# Usage: ./analyze_bap.sh <path_to_binary>
#
# Prerequisites:
#   - BAP installed via opam (opam install bap)
#   - bap command available in PATH
#

# ============================================================================
# CONFIGURATION BLOCK - Edit these paths to match your setup
# ============================================================================

# BAP command (usually 'bap' if installed via opam)
# If you need a specific path, set it here
BAP_CMD="${BAP_CMD:-bap}"

# ============================================================================
# INPUT VALIDATION
# ============================================================================

# Check if binary path argument was provided
if [ $# -eq 0 ]; then
    echo "ERROR: No binary path provided" >&2
    echo "Usage: $0 <path_to_binary>" >&2
    exit 1
fi

BINARY_PATH="$1"

# Check if the provided path is a valid file
if [ ! -f "$BINARY_PATH" ]; then
    echo "ERROR: File not found or not a regular file: $BINARY_PATH" >&2
    exit 1
fi

# ============================================================================
# TOOL AVAILABILITY CHECK
# ============================================================================

# Verify that bap command is available
if ! command -v "$BAP_CMD" &> /dev/null; then
    echo "ERROR: BAP command not found: $BAP_CMD" >&2
    echo "Please install BAP using opam:" >&2
    echo "  1. Install opam: sudo apt install opam" >&2
    echo "  2. Initialize opam: opam init" >&2
    echo "  3. Install BAP: opam install bap" >&2
    echo "  4. Ensure bap is in your PATH" >&2
    exit 1
fi

# ============================================================================
# SETUP
# ============================================================================

BINARY_NAME=$(basename "$BINARY_PATH")

echo "=========================================="
echo "BAP BIL IR Analysis"
echo "=========================================="
echo "Binary:  $BINARY_PATH"
echo "Tool:    $BAP_CMD"
echo "=========================================="

# ============================================================================
# RUN BAP ANALYSIS
# ============================================================================

# Run BAP to lift binary to BIL and print it
# Arguments:
#   -d bil    - disassemble and print BIL (BAP Intermediate Language)
#   The binary path is passed as the last argument
#
# Additional useful BAP options (commented out, can be enabled as needed):
#   -d asm    - print assembly
#   -d bir    - print BIR (BAP Intermediate Representation, higher level)
#   --dump=bir:out.bir - dump BIR to file
#   --passes=<passes> - run specific analysis passes

echo ""
echo "Lifting to BIL IR..."
echo ""

"$BAP_CMD" "$BINARY_PATH" -d bil

# Capture exit status
EXIT_STATUS=$?

# ============================================================================
# ERROR HANDLING
# ============================================================================

if [ $EXIT_STATUS -ne 0 ]; then
    echo "" >&2
    echo "ERROR: BAP analysis failed with exit code $EXIT_STATUS" >&2
    exit 1
fi

echo ""
echo "=========================================="
echo "BAP analysis completed successfully"
echo "=========================================="

exit 0
