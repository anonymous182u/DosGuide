#!/bin/bash
# Build and run the snappy-java DoS fuzzer for all targets.
set -e

WORKSPACE="$(cd "$(dirname "$0")" && pwd)"
cd "$WORKSPACE"

echo "=== Step 1: Compile ==="
mvn package -DskipTests -q 2>&1 | tail -30

echo "=== Step 2: Build agent JAR ==="
jar cfm target/agent.jar src/test/resources/META-INF/MANIFEST.MF \
    -C target/test-classes org/xerial/snappy/fuzz/AllocationMeasureAgent.class \
    -C target/test-classes org/xerial/snappy/fuzz/AllocationMeasureAgent\$AllocTransformer.class \
    -C target/test-classes org/xerial/snappy/fuzz/AllocationMeasureAgent\$AllocTransformer\$1.class \
    -C target/test-classes org/xerial/snappy/fuzz/AllocationMeasureAgent\$AllocMethodVisitor.class \
    -C target/test-classes org/xerial/snappy/fuzz/AllocCounters.class

# Add ASM classes to the agent JAR (needed for the transformer)
mkdir -p target/agent-staging
cd target/agent-staging
jar xf ../dependency/asm-9.8.jar org/objectweb/asm
cd "$WORKSPACE"
jar uf target/agent.jar -C target/agent-staging org/objectweb/asm

echo "=== Agent JAR built: target/agent.jar ==="

# Classpath for running
CP="target/test-classes:target/classes:lib/snappy-java-1.1.10.3-17-49d70017-SNAPSHOT.jar:target/dependency/*"

DURATION=${1:-60}  # default 60 seconds per target

echo "=== Step 3: Run fuzzer for each target (${DURATION}s each) ==="
for TARGET in V1 V2 V3; do
    echo "--- Fuzzing $TARGET ---"
    java -Xmx1g -Xss1m \
         -javaagent:target/agent.jar \
         -cp "$CP" \
         org.xerial.snappy.fuzz.FuzzRunner "$TARGET" "$DURATION" \
         2>&1 | tail -50
    echo ""
done

echo "=== Done ==="
