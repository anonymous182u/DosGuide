#!/bin/bash
# Build and run json-smart DoS fuzzing campaign
set -e

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASEDIR"

echo "=== Step 1: Compile ==="
mvn package -DskipTests -q 2>&1 | tail -30

echo "=== Step 2: Build agent jar ==="
printf 'Premain-Class: fuzzing.agent.DepthMeasureAgent\nCan-Retransform-Classes: true\n' > target/agent-manifest.txt
jar cfm target/depth-agent.jar target/agent-manifest.txt -C target/test-classes fuzzing/agent/
echo "Agent jar created: target/depth-agent.jar"

CP="target/test-classes:target/deps/*:lib/*"
AGENT="-javaagent:target/depth-agent.jar"
JVM_OPTS="-Xmx1g -Xss1m"
DURATION="${1:-60}"

echo "=== Step 3: Fuzz V1 (${DURATION}s) ==="
java $JVM_OPTS $AGENT -cp "$CP" fuzzing.runner.FuzzRunner V1 "$DURATION" 2>&1 | tail -50

echo "=== Step 4: Fuzz V2 (${DURATION}s) ==="
java $JVM_OPTS $AGENT -cp "$CP" fuzzing.runner.FuzzRunner V2 "$DURATION" 2>&1 | tail -50

echo "=== Done ==="
