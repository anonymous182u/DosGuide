#!/usr/bin/env bash
# build-agent.sh — Builds the V1MeasureAgent jar with ASM classes included.
#
# The agent jar must be self-contained because it is loaded via -javaagent
# before the application classpath is set up. It must include:
#   1. V1MeasureAgent.class + inner classes
#   2. V1Counters.class (added to bootstrap classpath by the agent)
#   3. ASM classes (org/objectweb/asm/*) needed for bytecode transformation
#
# Prereq: mvn package -DskipTests must have been run first.
set -euo pipefail

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="$BASEDIR/target"
TEST_CLASSES="$TARGET/test-classes"
AGENT_JAR="$TARGET/v1-measure-agent.jar"
AGENT_WORK="$TARGET/agent-build"

echo "[build-agent] Building V1MeasureAgent jar..."

# Clean build area
rm -rf "$AGENT_WORK"
mkdir -p "$AGENT_WORK"

# 1. Copy V1MeasureAgent classes (including inner classes) and V1Counters
cp "$TEST_CLASSES/com/fuzzer/V1MeasureAgent.class" "$AGENT_WORK/" 2>/dev/null || true
cp "$TEST_CLASSES/com/fuzzer/V1MeasureAgent\$ScalarUtilTransformer.class" "$AGENT_WORK/" 2>/dev/null || true
cp "$TEST_CLASSES/com/fuzzer/V1MeasureAgent\$InstrumentingClassVisitor.class" "$AGENT_WORK/" 2>/dev/null || true
cp "$TEST_CLASSES/com/fuzzer/V1MeasureAgent\$InstrumentingMethodVisitor.class" "$AGENT_WORK/" 2>/dev/null || true
cp "$TEST_CLASSES/com/fuzzer/V1Counters.class" "$AGENT_WORK/" 2>/dev/null || true

# Organize into package directories
mkdir -p "$AGENT_WORK/com/fuzzer"
mv "$AGENT_WORK"/V1MeasureAgent*.class "$AGENT_WORK/com/fuzzer/" 2>/dev/null || true
mv "$AGENT_WORK"/V1Counters*.class "$AGENT_WORK/com/fuzzer/" 2>/dev/null || true

# 2. Extract ASM classes from the dependency jar
ASM_JAR="$TARGET/deps/asm-9.8.jar"
if [ ! -f "$ASM_JAR" ]; then
    echo "[build-agent] ERROR: ASM jar not found at $ASM_JAR"
    echo "[build-agent] Run 'mvn package -DskipTests' first."
    exit 1
fi
(cd "$AGENT_WORK" && jar xf "$ASM_JAR" org/)

# 3. Create the MANIFEST with Premain-Class
mkdir -p "$AGENT_WORK/META-INF"
cat > "$AGENT_WORK/META-INF/MANIFEST.MF" <<'MANIFEST'
Manifest-Version: 1.0
Premain-Class: com.fuzzer.V1MeasureAgent
Boot-Class-Path: v1-measure-agent.jar
Can-Retransform-Classes: false
Can-Redefine-Classes: false
MANIFEST

# 4. Build the jar
(cd "$AGENT_WORK" && jar cfm "$AGENT_JAR" META-INF/MANIFEST.MF .)

echo "[build-agent] Agent jar built: $AGENT_JAR"
echo "[build-agent] Contents:"
jar tf "$AGENT_JAR" | head -30
echo "[build-agent] Done."
