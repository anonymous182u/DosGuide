#!/bin/bash
# Build the V1 measurement agent JAR and the bootstrap counter JAR.
# Run after: mvn package -DskipTests
set -e

# ---- 1. Counter JAR (goes on bootstrap classpath via Boot-Class-Path) ----
COUNTER_DIR=target/counter-staging
rm -rf "$COUNTER_DIR"
mkdir -p "$COUNTER_DIR/regexmeasure"
cp target/test-classes/regexmeasure/RegexStepCounter*.class \
   "$COUNTER_DIR/regexmeasure/"

jar cf target/v1-counter.jar -C "$COUNTER_DIR" .
echo "[build_agent] Built target/v1-counter.jar (bootstrap counter)"

# ---- 2. Agent JAR (stays on system classpath via -javaagent:) ----
# MUST NOT contain RegexStepCounter or NodeMatchAdapter on bootstrap —
# only the agent entry class. The adapter and counter are resolved from
# the system classpath and bootstrap classpath respectively.
AGENT_DIR=target/agent-staging
rm -rf "$AGENT_DIR"
mkdir -p "$AGENT_DIR"

# Agent + adapter classes
mkdir -p "$AGENT_DIR/com/googlecode/vfsjfilechooser2/fuzz/agent"
cp target/test-classes/com/googlecode/vfsjfilechooser2/fuzz/agent/V1MeasureAgent.class \
   "$AGENT_DIR/com/googlecode/vfsjfilechooser2/fuzz/agent/"
cp target/test-classes/com/googlecode/vfsjfilechooser2/fuzz/agent/V1MeasureAgent\$*.class \
   "$AGENT_DIR/com/googlecode/vfsjfilechooser2/fuzz/agent/" 2>/dev/null || true
cp target/test-classes/com/googlecode/vfsjfilechooser2/fuzz/agent/NodeMatchAdapter.class \
   "$AGENT_DIR/com/googlecode/vfsjfilechooser2/fuzz/agent/"
cp target/test-classes/com/googlecode/vfsjfilechooser2/fuzz/agent/NodeMatchAdapter\$*.class \
   "$AGENT_DIR/com/googlecode/vfsjfilechooser2/fuzz/agent/" 2>/dev/null || true

# Create MANIFEST with Boot-Class-Path pointing to the counter JAR
# (paths in Boot-Class-Path are relative to the agent JAR's directory)
mkdir -p "$AGENT_DIR/META-INF"
cat > "$AGENT_DIR/META-INF/MANIFEST.MF" <<'MANIFEST'
Manifest-Version: 1.0
Premain-Class: com.googlecode.vfsjfilechooser2.fuzz.agent.V1MeasureAgent
Can-Retransform-Classes: true
Can-Redefine-Classes: true
Boot-Class-Path: v1-counter.jar

MANIFEST

jar cfm target/v1-agent.jar "$AGENT_DIR/META-INF/MANIFEST.MF" -C "$AGENT_DIR" .

echo "[build_agent] Built target/v1-agent.jar (agent)"
jar tf target/v1-agent.jar | grep -c '\.class$' | xargs -I{} echo "[build_agent] {} class files in agent JAR"
jar tf target/v1-counter.jar | grep -c '\.class$' | xargs -I{} echo "[build_agent] {} class files in counter JAR"
