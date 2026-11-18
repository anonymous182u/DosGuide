#!/usr/bin/env bash
# run.sh — Build and run DoS fuzz tests for JSON-java (GHSA-whgh-g24c-3j5q)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGET="${1:-all}"
DURATION="${2:-60}"

echo "=== Step 1: Compile ==="
mvn package -DskipTests -q 2>&1 | tail -30
echo "Compilation successful."

echo "=== Step 2: Build agent JAR ==="
rm -rf target/agent-staging
mkdir -p target/agent-staging
cd target/agent-staging
jar xf ~/.m2/repository/org/ow2/asm/asm/9.6/asm-9.6.jar 2>/dev/null
jar xf ~/.m2/repository/org/ow2/asm/asm-commons/9.6/asm-commons-9.6.jar 2>/dev/null
rm -rf META-INF
mkdir -p fuzzing/agent
cp ../test-classes/fuzzing/agent/*.class fuzzing/agent/
jar cfm ../dos-measure-agent.jar ../../src/test/resources/META-INF/MANIFEST.MF fuzzing/ org/
cd "$SCRIPT_DIR"
echo "Agent JAR built: target/dos-measure-agent.jar"

echo "=== Step 3: Resolve classpath ==="
M2="${HOME}/.m2/repository"
CP="target/test-classes"
CP="$CP:lib/json-20211205.jar"
CP="$CP:$M2/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar"
CP="$CP:$M2/edu/berkeley/cs/jqf/jqf-instrument/2.1/jqf-instrument-2.1.jar"
CP="$CP:$M2/junit/junit/4.13.2/junit-4.13.2.jar"
CP="$CP:$M2/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar"
CP="$CP:$M2/com/pholser/junit-quickcheck-core/1.0/junit-quickcheck-core-1.0.jar"
CP="$CP:$M2/com/pholser/junit-quickcheck-generators/1.0/junit-quickcheck-generators-1.0.jar"
CP="$CP:$M2/org/ow2/asm/asm/9.6/asm-9.6.jar"
CP="$CP:$M2/org/ow2/asm/asm-commons/9.6/asm-commons-9.6.jar"

AGENT="-javaagent:target/dos-measure-agent.jar"
JVM_OPTS="-Xmx1g -Xss1m"

run_target() {
    local tid="$1"
    echo ""
    echo "=== Running target $tid for ${DURATION}s ==="
    java $JVM_OPTS $AGENT -cp "$CP" fuzzing.runner.FuzzRunner "$tid" "$DURATION" 2>&1 | tail -50
    echo "=== Target $tid complete ==="
}

case "$TARGET" in
    V1)   run_target V1 ;;
    V2)   run_target V2 ;;
    all)  run_target V1; run_target V2 ;;
    *)    echo "Unknown target: $TARGET. Use V1, V2, or all."; exit 1 ;;
esac

echo ""
echo "=== Done ==="
