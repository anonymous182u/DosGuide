#!/usr/bin/env bash
# Build and run fuzzing for V1 (Decompression Bomb in jose4j).
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${PROJECT_DIR}"

echo "=== Step 1: Compile ==="
mvn package -DskipTests -q 2>&1 | tail -30

echo "=== Step 2: Build agent JAR ==="
bash scripts/build-agent.sh

echo "=== Step 3: Fuzz V1 (60 seconds) ==="
AGENT_JAR="target/v1-measure-agent.jar"
CP="target/test-classes:target/dependency/*:lib/jose4j-0.9.6-SNAPSHOT.jar"

java -Xmx1g -Xss1m \
     -javaagent:"${AGENT_JAR}" \
     -Djqf.ei.MAX_INPUT_SIZE=10240 \
     -cp "${CP}" \
     org.jose4j.fuzz.runner.FuzzRunner V1 60 2>&1 | tail -50

echo "=== Done ==="
