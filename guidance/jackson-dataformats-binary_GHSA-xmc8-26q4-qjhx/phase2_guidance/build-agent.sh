#!/usr/bin/env bash
# Build the measurement agent JAR from compiled test classes.
# Run this AFTER: mvn package -DskipTests
set -euo pipefail

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASEDIR"

AGENT_JAR="target/pkgrisk1-agent.jar"
MANIFEST="src/test/resources/META-INF/MANIFEST-AGENT.MF"
TEST_CLASSES="target/test-classes"

echo "[build-agent] Creating agent JAR: $AGENT_JAR"

# Verify that test classes exist
if [ ! -d "$TEST_CLASSES/com/fasterxml/jackson/fuzz/agent" ]; then
    echo "ERROR: Agent classes not found in $TEST_CLASSES. Run 'mvn package -DskipTests' first."
    exit 1
fi

# Create the agent JAR with the manifest and all agent classes
jar cfm "$AGENT_JAR" "$MANIFEST" \
    -C "$TEST_CLASSES" com/fasterxml/jackson/fuzz/agent/AllocationSizeCounters.class \
    -C "$TEST_CLASSES" com/fasterxml/jackson/fuzz/agent/AllocationSizeTransformer.class \
    -C "$TEST_CLASSES" 'com/fasterxml/jackson/fuzz/agent/AllocationSizeTransformer$1.class' \
    -C "$TEST_CLASSES" 'com/fasterxml/jackson/fuzz/agent/AllocationSizeTransformer$AllocClassVisitor.class' \
    -C "$TEST_CLASSES" 'com/fasterxml/jackson/fuzz/agent/AllocationSizeTransformer$AllocMethodVisitor.class' \
    -C "$TEST_CLASSES" com/fasterxml/jackson/fuzz/agent/NestingDepthCounters.class \
    -C "$TEST_CLASSES" com/fasterxml/jackson/fuzz/agent/NestingDepthTransformer.class \
    -C "$TEST_CLASSES" 'com/fasterxml/jackson/fuzz/agent/NestingDepthTransformer$LoaderAwareClassWriter.class' \
    -C "$TEST_CLASSES" 'com/fasterxml/jackson/fuzz/agent/NestingDepthTransformer$DepthClassVisitor.class' \
    -C "$TEST_CLASSES" 'com/fasterxml/jackson/fuzz/agent/NestingDepthTransformer$DepthMethodVisitor.class' \
    -C "$TEST_CLASSES" com/fasterxml/jackson/fuzz/agent/PkgRisk1MeasureAgent.class

echo "[build-agent] Agent JAR created: $AGENT_JAR ($(wc -c < "$AGENT_JAR") bytes)"
echo "[build-agent] Contents:"
jar tf "$AGENT_JAR"
