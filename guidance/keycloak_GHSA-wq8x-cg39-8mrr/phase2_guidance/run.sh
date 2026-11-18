#!/usr/bin/env bash
# ───────────────────────────────────────────────────────────────────────────
# run.sh — Build and run the JQF fuzz campaign for Keycloak SearchQueryUtils
#
# Usage:
#   ./run.sh <targetId> <durationSeconds>
#
# Example:
#   ./run.sh V1 120
#
# Prerequisites:
#   - JDK 17+
#   - Maven 3.8+
# ───────────────────────────────────────────────────────────────────────────
set -euo pipefail

TARGET="${1:?Usage: $0 <targetId> <durationSeconds>}"
DURATION="${2:?Usage: $0 <targetId> <durationSeconds>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Step 1: Compile project ==="
mvn -q package -DskipTests

echo "=== Step 2: Build boot jar (RegexStepCounter for bootstrap classpath) ==="
rm -rf target/boot-staging
mkdir -p target/boot-staging/org/keycloak/fuzzing/agent
cp target/test-classes/org/keycloak/fuzzing/agent/RegexStepCounter.class \
   target/boot-staging/org/keycloak/fuzzing/agent/
jar cf target/regex-counter-boot.jar -C target/boot-staging .
echo "  Built target/regex-counter-boot.jar"

echo "=== Step 3: Build agent jar ==="
rm -rf target/agent-staging
mkdir -p target/agent-staging/META-INF target/agent-staging/org/keycloak/fuzzing/agent

# Copy agent classes
cp target/test-classes/org/keycloak/fuzzing/agent/RegexStepCounter.class \
   target/agent-staging/org/keycloak/fuzzing/agent/
cp target/test-classes/org/keycloak/fuzzing/agent/PatternNodeTransformer.class \
   target/agent-staging/org/keycloak/fuzzing/agent/
cp target/test-classes/org/keycloak/fuzzing/agent/PatternNodeTransformer\$*.class \
   target/agent-staging/org/keycloak/fuzzing/agent/ 2>/dev/null || true
cp target/test-classes/org/keycloak/fuzzing/agent/V1MeasureAgent.class \
   target/agent-staging/org/keycloak/fuzzing/agent/

# Bundle ASM into agent jar
ASM_JAR=$(find "$HOME/.m2/repository/org/ow2/asm/asm" -name 'asm-9*.jar' | sort -V | tail -1)
if [ -z "$ASM_JAR" ]; then
    echo "ERROR: Could not find ASM jar" >&2; exit 1
fi
echo "  ASM jar: $ASM_JAR"
(cd target/agent-staging && jar xf "$ASM_JAR" org/)

# Manifest with Boot-Class-Path for bootstrap visibility of RegexStepCounter
printf 'Manifest-Version: 1.0\nPremain-Class: org.keycloak.fuzzing.agent.V1MeasureAgent\nBoot-Class-Path: regex-counter-boot.jar\nCan-Retransform-Classes: true\nCan-Redefine-Classes: true\n' \
    > target/agent-staging/META-INF/MANIFEST.MF

jar cfm target/v1-measure-agent.jar target/agent-staging/META-INF/MANIFEST.MF \
    -C target/agent-staging .
echo "  Built target/v1-measure-agent.jar"

echo "=== Step 4: Build classpath ==="
# Resolve test classpath
DEP_CP=""
if mvn -q dependency:build-classpath -DincludeScope=test -Dmdep.outputFile=target/cp.txt 2>/dev/null; then
    DEP_CP="$(cat target/cp.txt)"
else
    M2="$HOME/.m2/repository"
    for j in \
        "$M2/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar" \
        "$M2/edu/berkeley/cs/jqf/jqf-instrument/2.1/jqf-instrument-2.1.jar" \
        "$M2/junit/junit/4.13.2/junit-4.13.2.jar" \
        "$M2/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar" \
        "$ASM_JAR"; do
        [ -f "$j" ] && DEP_CP="${DEP_CP:+$DEP_CP:}$j"
    done
fi
CP="target/classes:target/test-classes${DEP_CP:+:$DEP_CP}"

echo "=== Step 5: Run fuzzer ==="
echo "Target: $TARGET  Duration: ${DURATION}s"
exec java \
    -Xmx1g \
    -Xss1m \
    -Djqf.ei.MAX_INPUT_SIZE=10240 \
    -javaagent:target/v1-measure-agent.jar \
    -cp "$CP" \
    org.keycloak.fuzzing.FuzzRunner \
    "$TARGET" "$DURATION"
