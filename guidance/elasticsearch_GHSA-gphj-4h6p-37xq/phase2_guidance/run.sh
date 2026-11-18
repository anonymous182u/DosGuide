#!/usr/bin/env bash
# =============================================================================
# run.sh — Build and run the block builder fuzz harness
#
# Usage:
#   ./run.sh                    # Build only
#   ./run.sh V1 <seconds>       # Build + fuzz IntBlockBuilder
#   ./run.sh V2 <seconds>       # Build + fuzz LongBlockBuilder
#   ./run.sh replay <file> [V1|V2]  # Build + replay a saved input
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---- Fixed eval limits (from project spec) ----
XMX="-Xmx1g"
XSS="-Xss1m"
TIMEOUT_MS=20000
MAX_INPUT_SIZE=10240

# ---- Paths ----
TARGET_DIR="target"
TEST_CLASSES="$TARGET_DIR/test-classes"
CLASSES="$TARGET_DIR/classes"
LIB_DIR="lib"
DEP_DIR="$TARGET_DIR/dependency"
AGENT_JAR="$TARGET_DIR/blockbuilder-alloc-agent.jar"
MANIFEST_DIR="$TARGET_DIR/agent-manifest"

# ---- Step 1: Maven build ----
echo "=== Step 1: Maven package (skip tests) ==="
mvn -q package -DskipTests 2>&1 | tail -20
echo "Build complete."

# ---- Step 2: Create agent JAR ----
echo ""
echo "=== Step 2: Create agent JAR ==="
mkdir -p "$MANIFEST_DIR"
cat > "$MANIFEST_DIR/MANIFEST.MF" <<'MANIFEST'
Manifest-Version: 1.0
Premain-Class: org.elasticsearch.compute.data.fuzz.agent.BlockBuilderAllocAgent
Can-Retransform-Classes: false
Can-Redefine-Classes: false
MANIFEST

# The agent JAR includes AllocCounter, BlockBuilderAllocAgent, BlockBuilderAllocTransformer,
# and all inner classes (anonymous ClassVisitor $1 + NewArrayInstrumentor).
jar cfm "$AGENT_JAR" "$MANIFEST_DIR/MANIFEST.MF" \
    -C "$TEST_CLASSES" org/elasticsearch/compute/data/fuzz/agent/AllocCounter.class \
    -C "$TEST_CLASSES" org/elasticsearch/compute/data/fuzz/agent/BlockBuilderAllocAgent.class \
    -C "$TEST_CLASSES" org/elasticsearch/compute/data/fuzz/agent/BlockBuilderAllocTransformer.class \
    -C "$TEST_CLASSES" 'org/elasticsearch/compute/data/fuzz/agent/BlockBuilderAllocTransformer$1.class' \
    -C "$TEST_CLASSES" 'org/elasticsearch/compute/data/fuzz/agent/BlockBuilderAllocTransformer$NewArrayInstrumentor.class'
echo "Agent JAR: $AGENT_JAR"

# ---- Classpath ----
# test-classes: fuzz test + guidance + runner
# classes:      (empty in this project but included for completeness)
# lib/*:        vulnerable Elasticsearch jars (system scope)
# dependency/*: JQF, JUnit, Lucene, log4j, etc.
CP="$TEST_CLASSES:$CLASSES:$LIB_DIR/*:$DEP_DIR/*"

# ---- Dispatch ----
if [ $# -eq 0 ]; then
    echo ""
    echo "Build-only mode. To fuzz:"
    echo "  ./run.sh V1 5      # IntBlockBuilder for 5 seconds"
    echo "  ./run.sh V2 5      # LongBlockBuilder for 5 seconds"
    echo "  ./run.sh replay <file> [V1|V2]"
    exit 0
fi

CMD="$1"

if [ "$CMD" = "replay" ]; then
    # ---- Replay mode ----
    if [ $# -lt 2 ]; then
        echo "Usage: ./run.sh replay <inputFile> [V1|V2]"
        exit 1
    fi
    INPUT_FILE="$2"
    TARGET_ID="${3:-V1}"
    echo ""
    echo "=== Replay: $INPUT_FILE (target=$TARGET_ID) ==="
    java $XMX $XSS \
        -javaagent:"$AGENT_JAR" \
        -Djqf.ei.MAX_INPUT_SIZE="$MAX_INPUT_SIZE" \
        -cp "$CP" \
        org.elasticsearch.compute.data.fuzz.replay.ReplayRunner "$INPUT_FILE" "$TARGET_ID"
else
    # ---- Fuzz mode ----
    TARGET_ID="$CMD"
    DURATION_SEC="${2:-5}"
    OUTPUT_DIR="fuzz-results/$TARGET_ID"
    echo ""
    echo "=== Fuzzing: $TARGET_ID for ${DURATION_SEC}s ==="
    java $XMX $XSS \
        -javaagent:"$AGENT_JAR" \
        -Djqf.ei.MAX_INPUT_SIZE="$MAX_INPUT_SIZE" \
        -cp "$CP" \
        org.elasticsearch.compute.data.fuzz.FuzzRunner "$TARGET_ID" "$DURATION_SEC" "$OUTPUT_DIR"
fi
