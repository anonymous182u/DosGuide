#!/usr/bin/env bash
# Build the V1 measurement agent JAR from compiled test classes.
# This script packages agent classes + ASM dependencies into a standalone JAR
# with the correct MANIFEST.MF for -javaagent usage.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${PROJECT_DIR}/target"
TEST_CLASSES="${TARGET_DIR}/test-classes"
AGENT_JAR="${TARGET_DIR}/v1-measure-agent.jar"
MANIFEST="${PROJECT_DIR}/src/test/resources/META-INF/MANIFEST.MF"

echo "[build-agent] Project: ${PROJECT_DIR}"
echo "[build-agent] Test classes: ${TEST_CLASSES}"

if [ ! -d "${TEST_CLASSES}" ]; then
    echo "[build-agent] Error: test-classes not found. Run 'mvn package -DskipTests' first."
    exit 1
fi

# Create a temp directory for assembling the agent jar contents
AGENT_STAGING="${TARGET_DIR}/agent-staging"
rm -rf "${AGENT_STAGING}"
mkdir -p "${AGENT_STAGING}"

# Copy agent classes
cp -r "${TEST_CLASSES}/org/jose4j/fuzz/agent" "${AGENT_STAGING}/org/jose4j/fuzz/agent" 2>/dev/null || {
    mkdir -p "${AGENT_STAGING}/org/jose4j/fuzz/agent"
    cp "${TEST_CLASSES}/org/jose4j/fuzz/agent/"*.class "${AGENT_STAGING}/org/jose4j/fuzz/agent/"
}

# Copy ASM classes from dependency jars (needed by the transformer at agent load time)
DEP_DIR="${TARGET_DIR}/dependency"
if [ -d "${DEP_DIR}" ]; then
    for jar in "${DEP_DIR}"/asm-*.jar; do
        if [ -f "$jar" ]; then
            (cd "${AGENT_STAGING}" && jar xf "$jar" org/ 2>/dev/null || true)
        fi
    done
fi

# Build the agent jar with our manifest
echo "[build-agent] Creating agent JAR: ${AGENT_JAR}"
jar cfm "${AGENT_JAR}" "${MANIFEST}" -C "${AGENT_STAGING}" .

echo "[build-agent] Done. Agent JAR: ${AGENT_JAR}"
echo "[build-agent] Size: $(wc -c < "${AGENT_JAR}") bytes"

# Verify contents
echo "[build-agent] Contents:"
jar tf "${AGENT_JAR}" | grep -E "(V1Measure|Inflate|AdviceAdapter)" | head -10
