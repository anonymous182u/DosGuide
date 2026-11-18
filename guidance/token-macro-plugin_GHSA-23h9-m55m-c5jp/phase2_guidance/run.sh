#!/bin/bash
# run.sh — build and fuzz token-macro plugin targets V1 and V2
set -e

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASEDIR"

# ---- 1. Build ----------------------------------------------------------
echo "=== Building ==="
mvn package -DskipTests -q 2>&1 | tail -30

# ---- 2. Create agent jar -----------------------------------------------
mkdir -p target/agents
printf 'Premain-Class: dosguide.agent.DoSMeasureAgent\nCan-Retransform-Classes: true\n\n' \
    > target/agents/MANIFEST.MF
jar cfm target/agents/dos-measure-agent.jar \
    target/agents/MANIFEST.MF \
    -C target/test-classes dosguide/agent
echo "Agent jar created: target/agents/dos-measure-agent.jar"

# ---- 3. Classpath & JVM args -------------------------------------------
CP="target/test-classes:target/classes:lib/token-macro-2.6-SNAPSHOT.jar:target/deps/*"
JVM_ARGS="-Xmx1g -Xss1m"
JVM_ARGS="$JVM_ARGS --add-opens java.base/java.lang=ALL-UNNAMED"
JVM_ARGS="$JVM_ARGS --add-opens java.base/java.util=ALL-UNNAMED"
JVM_ARGS="$JVM_ARGS --add-opens java.base/java.lang.reflect=ALL-UNNAMED"
JVM_ARGS="$JVM_ARGS --add-opens java.base/java.text=ALL-UNNAMED"
JVM_ARGS="$JVM_ARGS --add-opens java.base/java.io=ALL-UNNAMED"
JVM_ARGS="$JVM_ARGS --add-opens java.desktop/java.awt.font=ALL-UNNAMED"
AGENT="-javaagent:target/agents/dos-measure-agent.jar"

# ---- 4. Run each target ------------------------------------------------
TARGET="${1:-all}"
DURATION="${2:-60}"

if [ "$TARGET" = "V1" ] || [ "$TARGET" = "all" ]; then
    echo ""
    echo "=== Running V1 — recursive token expansion (${DURATION}s) ==="
    java $JVM_ARGS $AGENT -cp "$CP" dosguide.FuzzRunner V1 "$DURATION" 2>&1 | tail -50
fi

if [ "$TARGET" = "V2" ] || [ "$TARGET" = "all" ]; then
    echo ""
    echo "=== Running V2 — regex DoS (${DURATION}s) ==="
    java $JVM_ARGS $AGENT -cp "$CP" dosguide.FuzzRunner V2 "$DURATION" 2>&1 | tail -50
fi

echo ""
echo "=== Done ==="
