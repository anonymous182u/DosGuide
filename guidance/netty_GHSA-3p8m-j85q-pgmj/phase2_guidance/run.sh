#!/usr/bin/env bash
# run.sh — build, package, create agent JAR, and run the fuzz targets.
# Usage:
#   ./run.sh V1 60      # fuzz V1 (BrotliDecoder) for 60 seconds
#   ./run.sh V2 120     # fuzz V2 (ZstdDecoder) for 120 seconds
#   ./run.sh all 60     # fuzz both targets sequentially
set -euo pipefail

TARGET="${1:-V1}"
DURATION="${2:-60}"

echo "=== Step 1: Compile ==="
mvn -q compile test-compile 2>&1 | tail -30

echo "=== Step 2: Copy dependencies ==="
mvn -q dependency:copy-dependencies -DincludeScope=test -DoutputDirectory=target/deps 2>&1 | tail -20

echo "=== Step 3: Create agent JAR ==="
mkdir -p target/agent-meta
cat > target/agent-meta/MANIFEST.MF <<'MEOF'
Premain-Class: fuzzing.agent.DecompressAgent
Can-Retransform-Classes: true
MEOF
jar cfm target/decompression-agent.jar target/agent-meta/MANIFEST.MF \
    -C target/test-classes fuzzing/agent/
echo "Agent JAR created: target/decompression-agent.jar"

echo "=== Step 4: Assemble classpath ==="
CP="target/test-classes:target/classes"
for jar in lib/*.jar; do CP="$CP:$jar"; done
for jar in target/deps/*.jar; do CP="$CP:$jar"; done
echo "Classpath: ${CP:0:200}..."

run_target() {
    local tid="$1"
    local dur="$2"
    echo ""
    echo "=== Running $tid for $dur seconds ==="
    java -Xmx1g -Xss1m \
         -javaagent:target/decompression-agent.jar \
         -cp "$CP" \
         fuzzing.runner.FuzzRunner "$tid" "$dur" 2>&1 | tail -50
}

case "$TARGET" in
    V1|v1) run_target V1 "$DURATION" ;;
    V2|v2) run_target V2 "$DURATION" ;;
    all|ALL)
        run_target V1 "$DURATION"
        run_target V2 "$DURATION"
        ;;
    *)
        echo "Unknown target: $TARGET (use V1, V2, or all)"
        exit 1
        ;;
esac

echo ""
echo "=== Done ==="
