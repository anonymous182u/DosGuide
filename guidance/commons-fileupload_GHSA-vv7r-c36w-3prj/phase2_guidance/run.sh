#!/usr/bin/env bash
# run.sh — Build and run the DoS fuzzer for commons-fileupload V1 target.
#
# Usage:
#   ./run.sh                 # build + run V1 for 300 s (default)
#   ./run.sh build           # build only (compile + agent jar)
#   ./run.sh run V1 60       # run V1 for 60 s (assumes build done)
#   ./run.sh replay V1 file  # replay a saved input
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ---- paths ----
TARGET_DIR="$SCRIPT_DIR/target"
DEP_DIR="$TARGET_DIR/dependency"
TEST_CLASSES="$TARGET_DIR/test-classes"
AGENT_JAR="$TARGET_DIR/v1-agent.jar"
LIB_JAR="$SCRIPT_DIR/lib/commons-fileupload-1.6.0-SNAPSHOT.jar"

# ---- build ----
do_build() {
    echo "[build] Running mvn package -DskipTests ..."
    mvn -q package -DskipTests

    echo "[build] Assembling agent fat jar ..."
    AGENT_BUILD="$TARGET_DIR/agent-build"
    rm -rf "$AGENT_BUILD"
    mkdir -p "$AGENT_BUILD"

    # Extract ASM classes needed by the agent
    (cd "$AGENT_BUILD" && jar xf "$DEP_DIR/asm-9.8.jar" org/)
    (cd "$AGENT_BUILD" && jar xf "$DEP_DIR/asm-commons-9.5.jar" org/)

    # Copy agent + counters classes
    mkdir -p "$AGENT_BUILD/com/fuzzing/agent"
    cp "$TEST_CLASSES/com/fuzzing/agent/V1Counters.class"     "$AGENT_BUILD/com/fuzzing/agent/"
    cp "$TEST_CLASSES/com/fuzzing/agent/V1MeasureAgent.class" "$AGENT_BUILD/com/fuzzing/agent/"

    # Manifest
    cat > "$AGENT_BUILD/manifest.txt" <<MANIFEST
Premain-Class: com.fuzzing.agent.V1MeasureAgent
Can-Retransform-Classes: true
MANIFEST

    # Build the agent jar
    jar cfm "$AGENT_JAR" "$AGENT_BUILD/manifest.txt" -C "$AGENT_BUILD" com/ -C "$AGENT_BUILD" org/

    echo "[build] Agent jar: $AGENT_JAR"
    echo "[build] Build complete."
}

# ---- classpath ----
make_classpath() {
    local CP="$TEST_CLASSES"
    CP="$CP:$LIB_JAR"
    for jar in "$DEP_DIR"/*.jar; do
        CP="$CP:$jar"
    done
    echo "$CP"
}

# ---- run ----
do_run() {
    local TARGET_ID="${1:-V1}"
    local DURATION="${2:-300}"
    local OUTPUT_DIR="$SCRIPT_DIR/fuzz-output/$TARGET_ID"
    local CP
    CP="$(make_classpath)"

    echo "[run] target=$TARGET_ID duration=${DURATION}s output=$OUTPUT_DIR"
    java -Xmx1g -Xss1m \
         -Djqf.ei.MAX_INPUT_SIZE=10240 \
         -javaagent:"$AGENT_JAR" \
         -cp "$CP" \
         com.fuzzing.runner.FuzzRunner "$TARGET_ID" "$DURATION" "$OUTPUT_DIR"
}

# ---- replay ----
do_replay() {
    local TARGET_ID="${1:-V1}"
    local INPUT_FILE="${2:?Usage: run.sh replay <targetId> <inputFile>}"
    local CP
    CP="$(make_classpath)"

    echo "[replay] target=$TARGET_ID input=$INPUT_FILE"
    java -Xmx1g -Xss1m \
         -javaagent:"$AGENT_JAR" \
         -cp "$CP" \
         com.fuzzing.replay.ReplayRunner "$TARGET_ID" "$INPUT_FILE"
}

# ---- main ----
CMD="${1:-all}"
case "$CMD" in
    build)
        do_build
        ;;
    run)
        shift
        do_run "$@"
        ;;
    replay)
        shift
        do_replay "$@"
        ;;
    all|"")
        do_build
        do_run V1 300
        ;;
    *)
        echo "Unknown command: $CMD"
        echo "Usage: run.sh [build|run|replay|all]"
        exit 1
        ;;
esac
