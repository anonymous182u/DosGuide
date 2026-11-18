#!/usr/bin/env bash
# Assembles the v1-measure-agent.jar from compiled test-classes + ASM.
# The resulting jar is self-contained and can be used as -javaagent.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="$PROJECT_DIR/target"
AGENT_DIR="$TARGET_DIR/agent"
WORK_DIR="$AGENT_DIR/work"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$AGENT_DIR"

# Copy only agent classes (V1Counters, V1MeasureAgent + inner classes)
mkdir -p "$WORK_DIR/tech/kwik/fuzz/agent"
cp "$TARGET_DIR/test-classes/tech/kwik/fuzz/agent/"*.class \
   "$WORK_DIR/tech/kwik/fuzz/agent/"

# Extract ASM classes needed by the transformer at runtime
(cd "$WORK_DIR" && jar xf "$TARGET_DIR/dependency/asm-9.8.jar" org/)

# Create MANIFEST.MF
mkdir -p "$WORK_DIR/META-INF"
cat > "$WORK_DIR/META-INF/MANIFEST.MF" <<'MANIFEST'
Manifest-Version: 1.0
Premain-Class: tech.kwik.fuzz.agent.V1MeasureAgent
Can-Retransform-Classes: true
MANIFEST

# Build the agent jar
(cd "$WORK_DIR" && jar cfm "$AGENT_DIR/v1-measure-agent.jar" \
    META-INF/MANIFEST.MF \
    tech/ \
    org/)

echo "[build-agent] Created: $AGENT_DIR/v1-measure-agent.jar"
jar tf "$AGENT_DIR/v1-measure-agent.jar" | head -15
echo "..."

# Clean up work directory
rm -rf "$WORK_DIR"
