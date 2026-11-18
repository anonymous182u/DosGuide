#!/bin/bash
# Build and run the CXF CachedOutputStream DoS fuzzer.
# Usage: ./run.sh [durationSeconds]  (default: 60)
set -e

DURATION=${1:-60}
BASEDIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Step 1: Compile ==="
cd "$BASEDIR"
mvn package -DskipTests -q 2>&1 | tail -30

echo "=== Step 2: Create agent jar ==="
mkdir -p target/agent-meta
printf 'Premain-Class: com.fuzzing.agent.V1MeasureAgent\nCan-Retransform-Classes: true\n' > target/agent-meta/MANIFEST.MF
jar cfm target/v1-agent.jar target/agent-meta/MANIFEST.MF -C target/test-classes com/fuzzing/agent/

echo "=== Step 3: Assemble classpath ==="
CP="target/test-classes"
CP="$CP:lib/cxf-core-4.1.1-SNAPSHOT.jar"
for f in target/dependency/*.jar; do
    CP="$CP:$f"
done
echo "Classpath assembled: $(echo $CP | tr ':' '\n' | wc -l) entries"

echo "=== Step 4: Run V1 fuzzer for ${DURATION}s ==="
java -Xmx1g -Xss1m \
     -Djqf.ei.MAX_INPUT_SIZE=10240 \
     -javaagent:target/v1-agent.jar \
     -cp "$CP" \
     com.fuzzing.runner.FuzzRunner V1 "$DURATION" 2>&1 | tail -50
