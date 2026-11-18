#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# run.sh — Build and run the ReDoS fuzzer for powsybl-core RegexCriterion
#
# Usage:
#   ./run.sh <targetId> <durationSeconds>
#   ./run.sh V1 5             # Fuzz V1 for 5 seconds
#   ./run.sh PkgRisk1 120     # Fuzz PkgRisk1 for 120 seconds
#   ./run.sh replay <targetId> <inputFile>  # Replay a single input
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"

TARGET="${1:?Usage: run.sh <targetId> <durationSec>}"
DURATION="${2:-5}"

# ── Step 1: Compile ──────────────────────────────────────────────────
echo "[run.sh] Compiling..."
mvn -q compile test-compile 2>&1 | tail -20

# ── Step 2: Build the javaagent jar ──────────────────────────────────
echo "[run.sh] Building regex-agent.jar..."
mkdir -p target/agent-build

ASM_JAR="$(find ~/.m2/repository/org/ow2/asm/asm/9.8 -name 'asm-9.8.jar' | head -1)"
if [ -z "$ASM_JAR" ]; then
    echo "ERROR: asm-9.8.jar not found in Maven repo" >&2
    exit 1
fi

# MANIFEST.MF for the agent jar
# Boot-Class-Path puts the counter class + ASM on bootstrap classpath
cat > target/agent-build/MANIFEST.MF <<EOF
Premain-Class: com.powsybl.fuzzing.agent.RegexBacktrackAgent
Can-Retransform-Classes: true
Boot-Class-Path: regex-agent.jar ${ASM_JAR}
EOF

# Build agent jar with agent + counter + ASM classes
jar cfm regex-agent.jar target/agent-build/MANIFEST.MF \
    -C target/test-classes com/powsybl/fuzzing/agent \
    -C target/test-classes com/powsybl/fuzzing/counter

echo "[run.sh] Agent jar built: regex-agent.jar"

# ── Step 3: Build classpath ──────────────────────────────────────────
CP="target/test-classes"
for jar in lib/*.jar; do
    CP="${CP}:${jar}"
done

# Add Maven test-scope dependencies
MAVEN_CP="$(mvn -q dependency:build-classpath -DincludeScope=test \
    -Dmdep.outputFile=/dev/stdout 2>/dev/null || true)"
if [ -n "$MAVEN_CP" ]; then
    CP="${CP}:${MAVEN_CP}"
fi

echo "[run.sh] Classpath assembled"

# ── Step 4: Run ──────────────────────────────────────────────────────
if [ "$TARGET" = "replay" ]; then
    # Replay mode: run.sh replay <targetId> <inputFile>
    REPLAY_TARGET="${DURATION}"
    INPUT_FILE="${3:?Usage: run.sh replay <targetId> <inputFile>}"
    echo "[run.sh] Replaying $INPUT_FILE for target $REPLAY_TARGET"
    java -Xmx1g -Xss1m \
        -javaagent:regex-agent.jar \
        -Djqf.ei.MAX_INPUT_SIZE=10240 \
        -cp "$CP" \
        com.powsybl.fuzzing.replay.ReplayRunner "$REPLAY_TARGET" "$INPUT_FILE"
else
    # Fuzz mode
    echo "[run.sh] Fuzzing target=$TARGET duration=${DURATION}s"
    java -Xmx1g -Xss1m \
        -javaagent:regex-agent.jar \
        -Djqf.ei.MAX_INPUT_SIZE=10240 \
        -cp "$CP" \
        com.powsybl.fuzzing.runner.FuzzRunner "$TARGET" "$DURATION"
fi

echo "[run.sh] Done."
