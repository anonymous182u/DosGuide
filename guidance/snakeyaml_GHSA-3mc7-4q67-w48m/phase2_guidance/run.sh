#!/usr/bin/env bash
# run.sh — Build and run V1 fuzzing for SnakeYAML GHSA-3mc7-4q67-w48m
set -e

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASEDIR"

echo "=== Step 1: Maven build ==="
mvn package -DskipTests -q 2>&1 | tail -30

echo "=== Step 2: Build V1 agent jar ==="
bash "$BASEDIR/build-agent.sh"

echo "=== Step 3: Assemble classpath ==="
CP="target/test-classes:target/classes:lib/snakeyaml-1.31-SNAPSHOT.jar"
for jar in target/deps/*.jar; do
    CP="$CP:$jar"
done
echo "Classpath assembled."

echo "=== Step 4: Run V1 fuzzer ==="
DURATION="${1:-60}"
echo "Duration: ${DURATION}s"

java -Xmx1g -Xss1m \
     -javaagent:target/v1-agent.jar \
     -cp "$CP" \
     v1.FuzzRunner V1 "$DURATION" 2>&1 | tail -50

echo "=== Done ==="
