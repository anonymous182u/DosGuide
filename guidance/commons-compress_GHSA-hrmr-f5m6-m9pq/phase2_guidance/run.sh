#!/bin/bash
# Compile and run fuzzing for all targets.
# Usage:
#   ./run.sh                 # run all targets, 60s each
#   ./run.sh V1 120          # run V1 for 120s
#   ./run.sh PkgRisk1 60     # run PkgRisk1 for 60s

set -e
BASEDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASEDIR"

# Step 1: Compile
echo "=== Compiling ==="
mvn compile -q 2>&1 | tail -30
mvn package -DskipTests -q 2>&1 | tail -30

# Step 2: Build agent jar
echo "=== Building agent jar ==="
bash build-agents.sh 2>&1 | tail -10

# Step 3: Compute classpath
# The runtime classpath includes:
#   - target/test-classes (compiled test code)
#   - lib/commons-compress-1.17.jar (vulnerable library)
#   - Maven test dependencies (JQF, JUnit, ASM, etc.)
MAVEN_CP=$(mvn dependency:build-classpath -DincludeScope=test -Dmdep.outputFile=/dev/stdout -q 2>/dev/null | tail -1)
CP="target/test-classes:lib/commons-compress-1.17.jar:${MAVEN_CP}"

# Determine targets and duration
TARGET="${1:-all}"
DURATION="${2:-60}"

run_target() {
    local tid="$1"
    local dur="$2"
    echo ""
    echo "=== Fuzzing target $tid for ${dur}s ==="
    java -Xmx1g -Xss1m \
        -javaagent:dos-agent.jar \
        -cp "$CP" \
        fuzzing.runner.FuzzRunner "$tid" "$dur" 2>&1 | tail -50
}

if [ "$TARGET" = "all" ]; then
    run_target V1 "$DURATION"
    run_target PkgRisk1 "$DURATION"
else
    run_target "$TARGET" "$DURATION"
fi

echo ""
echo "=== Done ==="
