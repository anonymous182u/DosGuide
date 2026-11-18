#!/bin/bash
# Build the V1 measurement agent jar from compiled test classes + ASM.
# Run AFTER mvn package -DskipTests.
set -e

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="$BASEDIR/target"
TEST_CLASSES="$TARGET/test-classes"
AGENT_JAR="$TARGET/v1-agent.jar"

# Locate the ASM core jar (from target/deps or Maven repo)
ASM_JAR=""
if [ -d "$TARGET/deps" ]; then
    ASM_JAR=$(find "$TARGET/deps" -maxdepth 1 -name 'asm-9*.jar' \
        ! -name '*commons*' ! -name '*analysis*' ! -name '*util*' ! -name '*tree*' \
        | sort -V | tail -1)
fi
if [ -z "$ASM_JAR" ]; then
    ASM_JAR=$(find "$HOME/.m2/repository/org/ow2/asm/asm" -name 'asm-9.*.jar' \
        | sort -V | tail -1)
fi

if [ -z "$ASM_JAR" ]; then
    echo "[build-agent] ERROR: Cannot find ASM jar" >&2
    exit 1
fi
echo "[build-agent] Using ASM: $ASM_JAR"

# Create temp working directory
WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT

# Extract ASM classes into work dir
(cd "$WORK" && jar xf "$ASM_JAR" org/)

# Copy agent classes
mkdir -p "$WORK/com/fuzzer/agent"
cp "$TEST_CLASSES/com/fuzzer/agent/V1MeasureAgent.class" "$WORK/com/fuzzer/agent/"
cp "$TEST_CLASSES/com/fuzzer/agent/V1Transformer.class"  "$WORK/com/fuzzer/agent/"
# Inner class (DecodeMethodVisitor)
for f in "$TEST_CLASSES/com/fuzzer/agent/V1Transformer"'$'*.class; do
    [ -f "$f" ] && cp "$f" "$WORK/com/fuzzer/agent/"
done

# Copy manifest
mkdir -p "$WORK/META-INF"
cp "$BASEDIR/src/test/resources/META-INF/MANIFEST.MF" "$WORK/META-INF/"

# Build the agent jar
jar cfm "$AGENT_JAR" "$WORK/META-INF/MANIFEST.MF" -C "$WORK" .

echo "[build-agent] Agent jar created: $AGENT_JAR ($(wc -c < "$AGENT_JAR") bytes)"
