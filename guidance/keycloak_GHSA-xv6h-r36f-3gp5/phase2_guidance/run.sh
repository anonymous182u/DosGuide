#!/bin/bash
# Build and run the V1 fuzzer.
# Usage: ./run.sh [targetId] [durationSeconds]
set -e

WORKSPACE="$(cd "$(dirname "$0")" && pwd)"
cd "$WORKSPACE"

TARGET="${1:-V1}"
DURATION="${2:-60}"

echo "=== Building ==="
mvn package -DskipTests -q 2>&1 | tail -20
bash build-agent.sh

echo "=== Building classpath ==="
CP="target/test-classes:target/classes"
for jar in lib/*.jar; do
    CP="$CP:$jar"
done
# Add Maven dependencies
if [ -f .mvn-test-cp.txt ]; then
    MVNCP="$(cat .mvn-test-cp.txt | tr -d '\n')"
    CP="$CP:$MVNCP"
fi

echo "=== Running target $TARGET for $DURATION seconds ==="
java -Xmx1g -Xss1m \
     -javaagent:v1-agent.jar \
     -cp "$CP" \
     com.fuzzer.runner.FuzzRunner "$TARGET" "$DURATION" 2>&1 | tail -50
