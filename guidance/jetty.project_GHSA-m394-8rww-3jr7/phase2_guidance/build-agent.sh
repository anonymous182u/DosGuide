#!/usr/bin/env bash
# Build the V1 measurement agent JAR from compiled test classes.
# Run after: mvn package -DskipTests
set -euo pipefail

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
TEST_CLASSES="${BASEDIR}/target/test-classes"
AGENT_JAR="${BASEDIR}/target/v1-agent.jar"
MANIFEST_DIR="${BASEDIR}/target/agent-manifest"

# Create manifest
mkdir -p "${MANIFEST_DIR}"
cat > "${MANIFEST_DIR}/MANIFEST.MF" <<'MANIFEST'
Manifest-Version: 1.0
Premain-Class: com.fuzzer.agent.V1MeasureAgent
Can-Retransform-Classes: true
MANIFEST

# Package agent classes into JAR
cd "${TEST_CLASSES}"
jar cfm "${AGENT_JAR}" "${MANIFEST_DIR}/MANIFEST.MF" \
    com/fuzzer/agent/V1Counters.class \
    com/fuzzer/agent/V1MeasureAgent.class \
    com/fuzzer/agent/V1MeasureAgent\$SortComparisonTransformer.class \
    com/fuzzer/agent/V1MeasureAgent\$SortInstrumentingClassVisitor.class \
    com/fuzzer/agent/V1MeasureAgent\$SortMethodVisitor.class

echo "Agent JAR built: ${AGENT_JAR}"
