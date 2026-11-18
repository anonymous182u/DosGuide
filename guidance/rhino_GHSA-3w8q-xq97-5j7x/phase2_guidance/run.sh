#!/usr/bin/env bash
# ============================================================================
# run.sh — Build and run the Rhino NativeNumber DoS fuzzer
#
# Usage:
#   ./run.sh <target> <maxTrials> [timeout_ms]
#
# Targets: V1 (toFixed), V2 (toString-radix), V3 (formatMethods)
#
# Examples:
#   ./run.sh V1 5          # 5 trials on toFixed
#   ./run.sh V2 10000      # 10000 trials on toString(radix)
#   ./run.sh V3 5 20000    # 5 trials on formatMethods, 20s timeout
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGET="${1:-V1}"
TRIALS="${2:-5}"
TIMEOUT_MS="${3:-20000}"

echo "=== Building ==="
mvn -q package -DskipTests 2>&1 | tail -5

# --- Build agent jar ---
echo "=== Building agent jar ==="
AGENT_DIR="target/agent-staging"
mkdir -p "$AGENT_DIR"

# Extract only the agent + counters classes from the compiled output
cp target/test-classes/fuzz/agent/DToAMeasureAgent.class "$AGENT_DIR/" 2>/dev/null || true
cp target/test-classes/fuzz/agent/DToAClassTransformer.class "$AGENT_DIR/" 2>/dev/null || true
cp target/test-classes/fuzz/agent/DToAClassTransformer\$*.class "$AGENT_DIR/" 2>/dev/null || true

# Create proper package directory structure inside staging
mkdir -p "$AGENT_DIR/fuzz/agent"
mv "$AGENT_DIR"/*.class "$AGENT_DIR/fuzz/agent/" 2>/dev/null || true

# Also include DToACounters (from main classes) in agent for bootstrap visibility
cp target/classes/fuzz/agent/DToACounters.class "$AGENT_DIR/fuzz/agent/" 2>/dev/null || true

# Write manifest
cat > target/agent-manifest.txt <<MANIFEST
Premain-Class: fuzz.agent.DToAMeasureAgent
Can-Retransform-Classes: true
MANIFEST

# Create the agent jar
jar cfm target/dos-agent.jar target/agent-manifest.txt -C "$AGENT_DIR" .
echo "Agent jar: target/dos-agent.jar ($(wc -c < target/dos-agent.jar) bytes)"

# --- Assemble classpath ---
CP="target/test-classes"
CP="$CP:target/classes"
CP="$CP:target/dependency/*"
CP="$CP:lib/rhino-1.7.14.jar"

echo "=== Running Fuzzer ==="
echo "Target: $TARGET  Trials: $TRIALS  Timeout: ${TIMEOUT_MS}ms"
echo "Classpath: $CP"
echo ""

java \
    -Xmx1g \
    -Xss1m \
    -javaagent:target/dos-agent.jar \
    -Djqf.ei.MAX_INPUT_SIZE=10240 \
    -Dfuzz.timeout.ms="$TIMEOUT_MS" \
    -cp "$CP" \
    fuzz.runner.FuzzRunner "$TARGET" "$TRIALS"
