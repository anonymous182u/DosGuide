#!/usr/bin/env bash
# run.sh — Build and launch the XNIO DoS fuzz campaign.
#
# Usage:
#   ./run.sh <targetId> <durationSeconds>
#   ./run.sh V1 5          # Fuzz V1 for 5 seconds
#   ./run.sh V2 10         # Fuzz V2 for 10 seconds
#
# The script:
#   1. Compiles the workspace with Maven
#   2. Builds the RecursionDepthAgent JAR
#   3. Runs FuzzRunner with the agent attached

set -euo pipefail

TARGET="${1:?Usage: run.sh <targetId> <durationSeconds>}"
DURATION="${2:?Usage: run.sh <targetId> <durationSeconds>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== [run.sh] Building workspace ==="
mvn package -DskipTests -q

echo "=== [run.sh] Building RecursionDepthAgent JAR ==="
mkdir -p target/agent-meta/META-INF
printf 'Premain-Class: org.xnio.fuzz.agent.RecursionDepthAgent\nCan-Retransform-Classes: true\n' \
    > target/agent-meta/META-INF/MANIFEST.MF
jar cfm target/recursion-agent.jar \
    target/agent-meta/META-INF/MANIFEST.MF \
    -C target/test-classes org/xnio/fuzz/agent

echo "=== [run.sh] Assembling classpath ==="
CP="target/test-classes"
CP="$CP:target/dependency/*"
CP="$CP:lib/*"

AGENT_JAR="target/recursion-agent.jar"

echo "=== [run.sh] Starting FuzzRunner target=$TARGET duration=${DURATION}s ==="
java \
    -Xmx1g \
    -Xss1m \
    -javaagent:"$AGENT_JAR" \
    -Djqf.ei.MAX_INPUT_SIZE=65536 \
    -cp "$CP" \
    org.xnio.fuzz.FuzzRunner "$TARGET" "$DURATION"

echo "=== [run.sh] Done ==="
