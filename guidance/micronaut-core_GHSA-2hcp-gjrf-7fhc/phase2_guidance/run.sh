#!/usr/bin/env bash
# run.sh — build and run the V1 DoS fuzzer
#
# Usage:
#   ./run.sh [TARGET] [DURATION_SEC] [OUTPUT_DIR]
#
# Defaults:
#   TARGET       = V1
#   DURATION_SEC = 20
#   OUTPUT_DIR   = fuzz-output/$TARGET
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# ── 1. Build ──────────────────────────────────────────────────────────────────
echo "[run.sh] Building workspace …"
mvn -q package -DskipTests

# ── 2. Build agent JAR ───────────────────────────────────────────────────────
echo "[run.sh] Packaging Java agent …"
mkdir -p target/agent-manifest
cat > target/agent-manifest/MANIFEST.MF <<'MANIFEST'
Premain-Class: com.fuzzing.agent.V1MeasureAgent
MANIFEST
jar cfm target/v1-agent.jar target/agent-manifest/MANIFEST.MF \
    -C target/test-classes com/fuzzing/agent/

# ── 3. Assemble classpath ────────────────────────────────────────────────────
# target/deps/ contains all dependency jars (incl. system-scope micronaut jars)
# target/test-classes/ contains compiled test code (harness, guidance, runners, agent)
CP="target/test-classes"
for jar in target/deps/*.jar; do
    CP="$CP:$jar"
done

# ── 4. Run ────────────────────────────────────────────────────────────────────
TARGET="${1:-V1}"
DURATION="${2:-20}"
OUTPUT="${3:-fuzz-output/$TARGET}"

echo "[run.sh] Running fuzzer: target=$TARGET duration=${DURATION}s output=$OUTPUT"

java -Xmx1g -Xss1m \
     -javaagent:target/v1-agent.jar \
     -Djqf.ei.MAX_INPUT_SIZE=1048576 \
     -cp "$CP" \
     com.fuzzing.runner.FuzzRunner "$TARGET" "$DURATION" "$OUTPUT"
