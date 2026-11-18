#!/usr/bin/env bash
# run.sh — Build and run msgpack-java DoS fuzzing harness
# Usage: ./run.sh <targetId> <durationSeconds> [outputDir]
#   targetId: V1, V2, or V3
#   durationSeconds: max fuzzing duration (0 = unlimited)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

TARGET="${1:?Usage: run.sh <V1|V2|V3> <durationSeconds> [outputDir]}"
DURATION="${2:?Usage: run.sh <V1|V2|V3> <durationSeconds> [outputDir]}"
OUTPUT_DIR="${3:-fuzz-output/$TARGET}"

echo "=== Building project ==="
mvn -q package -DskipTests 2>&1 | tail -20

echo "=== Building V1 agent jar ==="
mkdir -p target/agent-staging/agent
cp target/test-classes/agent/V1Counters.class target/agent-staging/agent/
cp target/test-classes/agent/V1Transformer.class target/agent-staging/agent/
cp target/test-classes/agent/V1MeasureAgent.class target/agent-staging/agent/
# Also include any inner classes
cp target/test-classes/agent/V1Transformer\$*.class target/agent-staging/agent/ 2>/dev/null || true
jar cfm target/v1-agent.jar src/test/resources/META-INF/MANIFEST.MF -C target/agent-staging .
echo "Agent jar: target/v1-agent.jar"

echo "=== Assembling classpath ==="
TEST_JAR="target/msgpack-fuzz-1.0-SNAPSHOT-tests.jar"
VULN_JAR="lib/msgpack-core-0.9.10-19-befe3b94-SNAPSHOT.jar"
TEST_DEPS="target/test-deps/*"
CP="${TEST_JAR}:${VULN_JAR}:${TEST_DEPS}"

# JVM args per target
JVM_ARGS="-Xmx1g -Xss1m -Djqf.ei.MAX_INPUT_SIZE=10240"
if [ "$TARGET" = "V1" ]; then
    JVM_ARGS="${JVM_ARGS} -javaagent:target/v1-agent.jar"
fi

echo "=== Running fuzzer: target=$TARGET, duration=${DURATION}s ==="
echo "JVM args: $JVM_ARGS"
echo "Classpath: $CP"
echo "Output: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

java $JVM_ARGS -cp "$CP" runner.FuzzRunner "$TARGET" "$DURATION" "$OUTPUT_DIR"
