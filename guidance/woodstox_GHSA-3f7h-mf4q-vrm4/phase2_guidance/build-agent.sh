#!/bin/bash
# Build the V1 measurement agent jar.
# The jar must include:
#   - fuzzing/agent/V1MeasureAgent.class (premain entry)
#   - fuzzing/agent/V1ClassTransformer.class (ASM transformer)
#   - fuzzing/agent/V1Counters.class (ThreadLocal counters)
#   - org/objectweb/asm/** (ASM classes needed by the transformer)
# and a MANIFEST with Premain-Class: fuzzing.agent.V1MeasureAgent

set -e

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASEDIR"

AGENT_STAGING="$BASEDIR/target/agent-staging"
rm -rf "$AGENT_STAGING"
mkdir -p "$AGENT_STAGING/fuzzing/agent"

# Copy agent classes
cp target/test-classes/fuzzing/agent/V1MeasureAgent.class "$AGENT_STAGING/fuzzing/agent/"
cp target/test-classes/fuzzing/agent/V1ClassTransformer.class "$AGENT_STAGING/fuzzing/agent/"
# Also copy inner classes of V1ClassTransformer
for f in target/test-classes/fuzzing/agent/V1ClassTransformer\$*.class; do
    [ -f "$f" ] && cp "$f" "$AGENT_STAGING/fuzzing/agent/"
done
cp target/test-classes/fuzzing/agent/V1Counters.class "$AGENT_STAGING/fuzzing/agent/"

# Extract ASM classes from the ASM jars into the staging area
cd "$AGENT_STAGING"
for jar in "$BASEDIR"/target/deps/asm-9.7.jar "$BASEDIR"/target/deps/asm-commons-9.7.jar "$BASEDIR"/target/deps/asm-tree-9.7.jar; do
    if [ -f "$jar" ]; then
        jar xf "$jar" org/ 2>/dev/null || true
    fi
done
cd "$BASEDIR"

# Build the agent jar
jar cfm target/v1-agent.jar src/test/resources/V1-MANIFEST.MF -C "$AGENT_STAGING" .

echo "[build-agent] Created target/v1-agent.jar"
jar tf target/v1-agent.jar | grep -c "\.class$"
echo " classes in agent jar"
