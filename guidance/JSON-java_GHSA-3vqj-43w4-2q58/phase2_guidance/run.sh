#!/usr/bin/env bash
# run.sh — Build and run the DoS fuzzer for JSON-java GHSA-3vqj-43w4-2q58
#
# Usage:
#   ./run.sh V1 [durationSec] [outputDir]
#
# Steps:
#   1. Compile workspace (mvn package -DskipTests)
#   2. Assemble the java-agent jar (target/v1-agent.jar)
#   3. Copy ASM dependency jars for the agent's runtime
#   4. Launch FuzzRunner with the agent and correct classpath

set -euo pipefail

TARGET="${1:-V1}"
DURATION="${2:-120}"
OUTPUT="${3:-fuzz-results/${TARGET}}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Step 1: Compile workspace ==="
mvn package -DskipTests -q 2>&1 | tail -20

echo "=== Step 2: Assemble agent jar ==="
# Agent staging area
rm -rf target/agent-staging
mkdir -p target/agent-staging/fuzzing/agent
cp target/test-classes/fuzzing/agent/V1DepthCounters.class target/agent-staging/fuzzing/agent/
cp target/test-classes/fuzzing/agent/V1DepthTransformer.class target/agent-staging/fuzzing/agent/
cp target/test-classes/fuzzing/agent/V1MeasureAgent.class target/agent-staging/fuzzing/agent/

# Manifest
printf 'Premain-Class: fuzzing.agent.V1MeasureAgent\n' > target/agent-staging/MANIFEST.MF

# Build agent jar
jar cfm target/v1-agent.jar target/agent-staging/MANIFEST.MF -C target/agent-staging fuzzing/
echo "Agent jar: target/v1-agent.jar"

echo "=== Step 3: Prepare dependency jars ==="
# Copy ASM jars into target/deps/ for the agent's classpath
mvn dependency:copy-dependencies -DoutputDirectory=target/deps -DincludeScope=test -q 2>&1 | tail -10

echo "=== Step 4: Launch FuzzRunner ==="
# Build the runtime classpath
#   - target/test-classes: test code (harness, guidance, runner)
#   - target/deps/*:      JQF, ASM, JUnit, json jar
#   - lib/*:              vulnerable json jar (system-scoped dep)
CP="target/test-classes"
for jar in target/deps/*.jar lib/*.jar; do
    [ -f "$jar" ] && CP="${CP}:${jar}"
done

echo "Classpath: ${CP}"
echo "Target: ${TARGET}  Duration: ${DURATION}s  Output: ${OUTPUT}"

# Run the fuzzer
# -Xmx1g -Xss1m: fixed evaluation limits
# -javaagent: depth instrumentation
# jqf.ei.MAX_INPUT_SIZE: max input size (default 65536, override via env)
exec java \
    -Xmx1g \
    -Xss1m \
    -javaagent:target/v1-agent.jar \
    -Djqf.ei.MAX_INPUT_SIZE="${MAX_INPUT_SIZE:-65536}" \
    -cp "${CP}" \
    fuzzing.runner.FuzzRunner "${TARGET}" "${DURATION}" "${OUTPUT}"
