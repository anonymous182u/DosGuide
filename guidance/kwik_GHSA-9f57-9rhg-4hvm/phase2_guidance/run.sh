#!/usr/bin/env bash
# Build and run the kwik hash-collision DoS fuzzer.
set -euo pipefail

cd "$(dirname "$0")"

echo "=== Building ==="
mvn package -DskipTests -q 2>&1 | tail -20

echo "=== Building agent jar ==="
bash scripts/build-agent.sh

echo "=== Assembling classpath ==="
CP="target/test-classes:lib/kwik-0.10.jar"
for jar in target/dependency/*.jar; do
    CP="$CP:$jar"
done
echo "Classpath entries: $(echo "$CP" | tr ':' '\n' | wc -l)"

AGENT="-javaagent:target/agent/v1-measure-agent.jar"
TARGET="${1:-V1}"
DURATION="${2:-60}"
MAX_INPUT="${3:-1048576}"

echo "=== Running fuzzer: target=$TARGET duration=${DURATION}s maxInput=$MAX_INPUT ==="
java -Xmx1g -Xss1m \
     "$AGENT" \
     -Djqf.ei.MAX_INPUT_SIZE="$MAX_INPUT" \
     -cp "$CP" \
     tech.kwik.fuzz.runner.FuzzRunner "$TARGET" "$DURATION" \
     2>&1 | tail -50
