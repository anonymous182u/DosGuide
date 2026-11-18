#!/usr/bin/env bash
# run.sh — Compile, build agent, and launch the fuzzer.
#
# Usage: ./run.sh <targetId> <durationSeconds>
#   targetId: V1
#   durationSeconds: max fuzzing duration (0 = unlimited)
#
# Example: ./run.sh V1 60
set -euo pipefail

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASEDIR"

TARGET_ID="${1:-V1}"
DURATION="${2:-60}"

echo "=== DoS Fuzzer: $TARGET_ID for ${DURATION}s ==="
echo ""

# Step 1: Compile with Maven
echo "[run.sh] Step 1: Compiling..."
mvn package -DskipTests -q 2>&1 | tail -5
echo "[run.sh] Compilation complete."
echo ""

# Step 2: Build the agent jar
echo "[run.sh] Step 2: Building agent jar..."
bash "$BASEDIR/build-agent.sh"
echo ""

# Step 3: Verify artifact provenance
echo "[run.sh] Step 3: Verifying vulnerable artifact..."
AGENT_JAR="$BASEDIR/target/v1-measure-agent.jar"
BC_JAR="$BASEDIR/lib/bcprov-jdk18on-1.75.jar"

if [ ! -f "$AGENT_JAR" ]; then
    echo "ERROR: Agent jar not found at $AGENT_JAR"
    exit 1
fi
if [ ! -f "$BC_JAR" ]; then
    echo "ERROR: BC jar not found at $BC_JAR"
    exit 1
fi

# Step 4: Build classpath
DEPS_DIR="$BASEDIR/target/deps"
TEST_CLASSES="$BASEDIR/target/test-classes"

# Classpath: test-classes + BC jar + all dependency jars
CP="$TEST_CLASSES"
CP="$CP:$BC_JAR"
for jar in "$DEPS_DIR"/*.jar; do
    # Skip the BC jar already in deps (use our lib/ copy instead)
    case "$(basename "$jar")" in
        bcprov-*) continue ;;
    esac
    CP="$CP:$jar"
done

echo "[run.sh] Classpath includes $(echo "$CP" | tr ':' '\n' | wc -l) entries"
echo ""

# Step 5: Launch the fuzzer
echo "[run.sh] Step 4: Launching fuzzer..."
echo "  Target:   $TARGET_ID"
echo "  Duration: ${DURATION}s"
echo "  Agent:    $AGENT_JAR"
echo "  BC jar:   $BC_JAR"
echo ""

java \
    -Xmx1g \
    -Xss1m \
    -Djqf.ei.MAX_INPUT_SIZE=10240 \
    -javaagent:"$AGENT_JAR" \
    -cp "$CP" \
    com.fuzzer.FuzzRunner "$TARGET_ID" "$DURATION"

echo ""
echo "[run.sh] Done."
