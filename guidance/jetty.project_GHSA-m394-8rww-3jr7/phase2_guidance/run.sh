#!/usr/bin/env bash
# Build and run fuzzer for all selected targets.
set -euo pipefail

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
cd "${BASEDIR}"

echo "=== Step 1: Compile ==="
mvn package -DskipTests -q 2>&1 | tail -30

echo "=== Step 2: Build agent JAR ==="
bash build-agent.sh

echo "=== Step 3: Run V1 fuzzer ==="
CLASSPATH="target/test-classes:target/classes:lib/*:target/deps/*"
AGENT_JAR="target/v1-agent.jar"
DURATION="${1:-60}"

java -Xmx1g -Xss1m \
  -cp "${CLASSPATH}" \
  -javaagent:"${AGENT_JAR}" \
  -Djqf.ei.MAX_INPUT_SIZE=10240 \
  com.fuzzer.runner.FuzzRunner V1 "${DURATION}" 2>&1 | tail -50
