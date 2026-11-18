#!/bin/bash
# Build and run the V1 fuzzer for vfsjfilechooser2 ReDoS.
set -e
cd "$(dirname "$0")"

TARGET=${1:-V1}
DURATION=${2:-60}

echo "=== Building workspace ==="
mvn package -DskipTests -q 2>&1 | tail -30

echo "=== Building agent + counter JARs ==="
bash build_agent.sh

echo "=== Running fuzzer: target=$TARGET duration=${DURATION}s ==="
java -Xmx1g -Xss1m \
    -javaagent:target/v1-agent.jar \
    -cp "target/test-classes:lib/vfsjfilechooser2-0.2.9-SNAPSHOT.jar:target/dependency/*" \
    com.googlecode.vfsjfilechooser2.fuzz.runner.FuzzRunner "$TARGET" "$DURATION" 2>&1 | tail -50
