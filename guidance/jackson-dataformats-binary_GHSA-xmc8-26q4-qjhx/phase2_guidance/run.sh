#!/usr/bin/env bash
# Build and run the CBOR DoS fuzzing campaign.
# Usage: ./run.sh [durationSeconds]
set -euo pipefail

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASEDIR"

DURATION="${1:-60}"

echo "=== Step 1: Compile ==="
mvn package -DskipTests -q 2>&1 | tail -30

echo "=== Step 2: Build agent JAR ==="
bash build-agent.sh

# Assemble classpath
CP="target/test-classes:lib/jackson-dataformat-cbor-2.11.4-SNAPSHOT.jar:target/dependency/*"

echo "=== Step 3: Run V1 (${DURATION}s) ==="
java -Xmx1g -Xss1m \
    -javaagent:target/pkgrisk1-agent.jar \
    -cp "$CP" \
    com.fasterxml.jackson.fuzz.runner.FuzzRunner V1 "$DURATION" 2>&1 | tail -50

echo "=== Step 4: Run PkgRisk1 (${DURATION}s) ==="
java -Xmx1g -Xss1m \
    -javaagent:target/pkgrisk1-agent.jar \
    -cp "$CP" \
    com.fasterxml.jackson.fuzz.runner.FuzzRunner PkgRisk1 "$DURATION" 2>&1 | tail -50

echo "=== Done ==="
