#!/bin/bash
#
# analyze_llvm.sh
# Analyzes a binary using LLVM toolchain and attempts to generate LLVM IR.
#
# Usage: ./analyze_llvm.sh <path_to_binary>
#
# Prerequisites:
#   - LLVM toolchain installed (llvm-dis, llvm-objdump, opt)
#   - For best results with compiled binaries, consider using:
#     - mcsema (https://github.com/lifting-bits/mcsema) for binary lifting
#     - remill (https://github.com/lifting-bits/remill) for instruction semantics
#
# Note: This script provides basic LLVM IR analysis. For production use,
#       consider integrating specialized binary lifting tools.
#

# ============================================================================
# CONFIGURATION BLOCK - Edit these paths to match your setup
# ============================================================================

# LLVM tools (usually available in PATH if installed via package manager)
LLVM_DIS="${LLVM_DIS:-llvm-dis}"
LLVM_OBJDUMP="${LLVM_OBJDUMP:-llvm-objdump}"
LLVM_OPT="${LLVM_OPT:-opt}"

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

# Check for at least one LLVM tool
LLVM_AVAILABLE=false

if command -v "$LLVM_OBJDUMP" &> /dev/null; then
    LLVM_AVAILABLE=true
fi

if command -v "$LLVM_DIS" &> /dev/null; then
    LLVM_AVAILABLE=true
fi

if [ "$LLVM_AVAILABLE" = false ]; then
    echo "ERROR: No LLVM tools found" >&2
    echo "Please install LLVM toolchain:" >&2
    echo "  Ubuntu/Debian: sudo apt install llvm" >&2
    echo "  Or download from: https://releases.llvm.org/" >&2
    exit 1
fi

# ============================================================================
# SETUP
# ============================================================================

BINARY_NAME=$(basename "$BINARY_PATH")

echo "=========================================="
echo "LLVM IR Analysis"
echo "=========================================="
echo "Binary:  $BINARY_PATH"
echo "=========================================="

# ============================================================================
# DETECT FILE TYPE
# ============================================================================

# Check if this is LLVM bitcode
FILE_TYPE=$(file "$BINARY_PATH")

if [[ "$FILE_TYPE" == *"LLVM"* ]] || [[ "$FILE_TYPE" == *"bitcode"* ]]; then
    echo ""
    echo "Detected LLVM bitcode file"
    echo "Disassembling to LLVM IR..."
    echo ""
    
    # Disassemble LLVM bitcode to IR
    if command -v "$LLVM_DIS" &> /dev/null; then
        "$LLVM_DIS" "$BINARY_PATH" -o - 2>&1
        EXIT_STATUS=$?
    else
        echo "ERROR: llvm-dis not found, cannot disassemble bitcode" >&2
        exit 1
    fi
else
    echo ""
    echo "Detected native binary (not LLVM bitcode)"
    echo "Performing LLVM-based binary analysis..."
    echo ""
    
    # For native binaries, use llvm-objdump to show disassembly and metadata
    # Note: This doesn't lift to LLVM IR, but provides LLVM-based analysis
    
    if command -v "$LLVM_OBJDUMP" &> /dev/null; then
        echo "--- Binary Information ---"
        "$LLVM_OBJDUMP" -h "$BINARY_PATH" 2>&1
        
        echo ""
        echo "--- Disassembly (first 100 instructions) ---"
        "$LLVM_OBJDUMP" -d "$BINARY_PATH" 2>&1 | head -n 150
        
        echo ""
        echo "--- Symbol Table (first 50 entries) ---"
        "$LLVM_OBJDUMP" -t "$BINARY_PATH" 2>&1 | head -n 55
        
        EXIT_STATUS=0
        
        echo ""
        echo "NOTE: For true binary-to-LLVM IR lifting, consider using:"
        echo "  - mcsema: https://github.com/lifting-bits/mcsema"
        echo "  - remill: https://github.com/lifting-bits/remill"
        echo "  - rellic: https://github.com/lifting-bits/rellic"
    else
        echo "ERROR: llvm-objdump not found" >&2
        exit 1
    fi
fi

# ============================================================================
# ERROR HANDLING
# ============================================================================

if [ $EXIT_STATUS -ne 0 ]; then
    echo "" >&2
    echo "ERROR: LLVM analysis failed with exit code $EXIT_STATUS" >&2
    exit 1
fi

echo ""
echo "=========================================="
echo "LLVM analysis completed successfully"
echo "=========================================="

exit 0
