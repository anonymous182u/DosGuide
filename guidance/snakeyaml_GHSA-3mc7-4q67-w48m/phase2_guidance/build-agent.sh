#!/usr/bin/env bash
# build-agent.sh — Build the V1 depth agent jar.
set -euo pipefail

# Resolve workspace root (script lives at workspace root)
WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
CLASSES="$WORKSPACE/target/test-classes"
DEPS="$WORKSPACE/target/deps"
STAGING="$WORKSPACE/target/agent-staging"
AGENT_JAR="$WORKSPACE/target/v1-agent.jar"

echo "[build-agent] workspace=$WORKSPACE"

# Verify prerequisites
if [ ! -d "$CLASSES/v1" ]; then
    echo "[build-agent] ERROR: $CLASSES/v1 not found. Run 'mvn package -DskipTests' first." >&2
    exit 1
fi

# Clean staging
rm -rf "$STAGING"
mkdir -p "$STAGING/v1"

# Copy agent classes
cp "$CLASSES/v1/DepthCounters.class" "$STAGING/v1/"
cp "$CLASSES/v1/V1DepthAgent.class" "$STAGING/v1/"

# Copy inner classes (named: DepthTransformer, DepthClassVisitor, DepthMethodVisitor)
for f in "$CLASSES"/v1/V1DepthAgent\$*.class; do
    if [ -f "$f" ]; then
        cp "$f" "$STAGING/v1/"
        echo "[build-agent]   copied $(basename "$f")"
    fi
done

# Extract only core ASM classes (agent uses ClassReader, ClassWriter, etc.)
ASM_JAR="$DEPS/asm-9.7.jar"
if [ ! -f "$ASM_JAR" ]; then
    echo "[build-agent] ERROR: $ASM_JAR not found" >&2
    exit 1
fi
cd "$STAGING"
jar xf "$ASM_JAR" org/
echo "[build-agent] extracted ASM from $ASM_JAR"

# Write manifest
cat > "$STAGING/manifest.mf" <<'MFEOF'
Premain-Class: v1.V1DepthAgent
Can-Retransform-Classes: true
Boot-Class-Path: v1-agent.jar

MFEOF

# Build agent jar from staging directory
jar cfm "$AGENT_JAR" "$STAGING/manifest.mf" -C "$STAGING" v1 -C "$STAGING" org

# Verify result
if [ ! -f "$AGENT_JAR" ]; then
    echo "[build-agent] ERROR: agent jar not created" >&2
    exit 1
fi
echo "[build-agent] OK: $(ls -la "$AGENT_JAR" | awk '{print $5}') bytes"
jar tf "$AGENT_JAR" | grep -c "\.class$" | xargs -I{} echo "[build-agent] {} class files"
