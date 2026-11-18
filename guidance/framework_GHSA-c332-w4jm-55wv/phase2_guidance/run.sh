#!/bin/bash
# Build and run the Vaadin EmailValidator fuzzer for all targets.
set -e

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASEDIR"

DURATION="${1:-60}"  # Default 60 seconds per target

echo "=== Step 1: Compile ==="
mvn package -DskipTests -q 2>&1 | tail -30

echo "=== Step 2: Build agent jar ==="
bash build-agent.sh 2>&1 | tail -20

# Classpath: test-classes + main classes + lib jars + Maven deps
CP="target/test-classes:target/classes:lib/*:target/deps/*"

echo "=== Step 3: Fuzz V1 (${DURATION}s) ==="
java -Xmx1g -Xss1m \
    -javaagent:target/regex-step-agent.jar \
    -cp "$CP" \
    com.vaadin.fuzz.FuzzRunner V1 "$DURATION" 2>&1 | tail -50

echo ""
echo "=== Step 4: Fuzz V2 (${DURATION}s) ==="
java -Xmx1g -Xss1m \
    -javaagent:target/regex-step-agent.jar \
    -cp "$CP" \
    com.vaadin.fuzz.FuzzRunner V2 "$DURATION" 2>&1 | tail -50

echo ""
echo "=== Done ==="
