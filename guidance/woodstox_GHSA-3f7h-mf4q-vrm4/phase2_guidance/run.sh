#!/bin/bash
# Compile and run the V1 fuzzer for Woodstox DTD content-spec recursion.
# Usage: ./run.sh [durationMs]   (default: 60000 = 60 seconds)

set -e

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASEDIR"

DURATION="${1:-60000}"

echo "=== Step 1: Compile ==="
mvn -q package -DskipTests 2>&1 | tail -30

echo "=== Step 2: Build agent jar ==="
bash build-agent.sh 2>&1 | tail -10

echo "=== Step 3: Build classpath ==="
CP="target/test-classes:lib/woodstox-core-5.3.1-SNAPSHOT.jar"
for jar in target/deps/*.jar; do
    [ -f "$jar" ] && CP="$CP:$jar"
done
CP="$CP:target/v1-agent.jar"
echo "Classpath entries: $(echo "$CP" | tr ':' '\n' | wc -l)"

echo "=== Step 4: Run V1 fuzzer for ${DURATION}ms ==="
java -Xmx1g -Xss1m \
     -javaagent:target/v1-agent.jar \
     -Djqf.ei.MAX_INPUT_SIZE=10240 \
     -cp "$CP" \
     fuzzing.runner.FuzzRunner V1 "$DURATION" 2>&1 | tail -50

echo "=== Done ==="
