#!/bin/bash
# DoS Fuzz Runner for ActiveMQ OpenWireFormat (GHSA-whxr-3p84-rf3c)
# Usage: ./run.sh [V1|V2|V3|all] [duration_seconds]
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

TARGET="${1:-all}"
DURATION="${2:-60}"

# Step 1: Compile
echo "=== Compiling workspace ==="
mvn package -DskipTests -q 2>&1 | tail -30

# Step 2: Build fat agent jar (includes ASM for bytecode transformation)
echo "=== Building agent jar ==="
rm -rf agent-jar/build
mkdir -p agent-jar/build/dosguide/agent
cp target/test-classes/dosguide/agent/*.class agent-jar/build/dosguide/agent/
(cd agent-jar/build && jar xf ../../target/deps/asm-9.8.jar org/)
jar cfm agent-jar/dosguide-agent.jar agent-jar/MANIFEST.MF \
  -C agent-jar/build .

# Classpath
CP="target/test-classes"
CP="$CP:lib/activemq-client-6.2.0-SNAPSHOT.jar"
CP="$CP:target/deps/jqf-fuzz-2.1.jar"
CP="$CP:target/deps/jqf-instrument-2.1.jar"
CP="$CP:target/deps/asm-9.8.jar"
CP="$CP:target/deps/junit-4.13.2.jar"
CP="$CP:target/deps/junit-quickcheck-core-1.0.jar"
CP="$CP:target/deps/junit-quickcheck-generators-1.0.jar"
CP="$CP:target/deps/hawtbuf-1.11.jar"
CP="$CP:target/deps/jakarta.jms-api-3.1.0.jar"
CP="$CP:target/deps/slf4j-api-2.0.16.jar"
CP="$CP:target/deps/slf4j-simple-2.0.16.jar"
CP="$CP:target/deps/generics-resolver-3.0.1.jar"
CP="$CP:target/deps/javaruntype-1.3.jar"
CP="$CP:target/deps/antlr-runtime-3.1.2.jar"
CP="$CP:target/deps/hamcrest-core-1.3.jar"

JVM_OPTS="-Xmx1g -Xss1m"
AGENT="-javaagent:agent-jar/dosguide-agent.jar"

run_target() {
    local tid="$1"
    echo ""
    echo "=== Running target $tid for ${DURATION}s ==="
    java $JVM_OPTS $AGENT -cp "$CP" \
      dosguide.runner.FuzzRunner "$tid" "$DURATION" "out/$tid" 2>&1 | tail -50
}

case "$TARGET" in
    V1|v1) run_target V1 ;;
    V2|v2) run_target V2 ;;
    V3|v3) run_target V3 ;;
    all|ALL)
        run_target V1
        run_target V2
        run_target V3
        ;;
    replay)
        # Replay mode: ./run.sh replay V1 out/V1/best_input.bin
        REPLAY_TARGET="${2:-V1}"
        REPLAY_FILE="${3:-out/$REPLAY_TARGET/best_input.bin}"
        echo "=== Replaying $REPLAY_TARGET from $REPLAY_FILE ==="
        java $JVM_OPTS $AGENT -cp "$CP" \
          dosguide.runner.FuzzRunner replay "$REPLAY_TARGET" "$REPLAY_FILE" 2>&1 | tail -50
        ;;
    *)
        echo "Usage: $0 [V1|V2|V3|all|replay] [duration_seconds]"
        echo "  Replay: $0 replay <V1|V2|V3> <input_file>"
        exit 1
        ;;
esac

echo ""
echo "=== Done ==="
