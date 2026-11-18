#!/bin/bash
# Build and run the V1 Snappy DoS fuzzer.
# Usage: ./run.sh [targetId] [durationSeconds]
#   targetId: V1 (default)
#   durationSeconds: 0 = infinite (default), >0 = bounded
set -e

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASEDIR"

echo "=== Step 1: Compile ==="
mvn package -DskipTests -q 2>&1 | tail -30

echo "=== Step 2: Build agent jar ==="
bash build-agent.sh

TARGET_ID="${1:-V1}"
DURATION="${2:-60}"

# Build classpath: test-classes + all deps + lib jars
CP="target/test-classes"
for jar in target/deps/*.jar; do
    [ -f "$jar" ] && CP="$CP:$jar"
done
for jar in lib/*.jar; do
    [ -f "$jar" ] && CP="$CP:$jar"
done

echo "=== Step 3: Run FuzzRunner $TARGET_ID for ${DURATION}s ==="
java -Xmx1g -Xss1m \
     -javaagent:target/v1-agent.jar \
     -cp "$CP" \
     com.fuzzer.runner.FuzzRunner "$TARGET_ID" "$DURATION" 2>&1 | tail -50
