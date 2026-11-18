#!/bin/bash
# Build the v1-agent.jar from compiled test classes + shaded ASM.
# Run after: mvn package -DskipTests -q
set -e

WORKSPACE="$(cd "$(dirname "$0")" && pwd)"
cd "$WORKSPACE"

echo "[build-agent] Building v1-agent.jar ..."

# --- Step 1: Compile test classes via Maven (if not already done) ---
if [ ! -d "target/test-classes/com/fuzzer/agent" ]; then
    echo "[build-agent] Compiling test classes ..."
    mvn package -DskipTests -q 2>&1 | tail -20
fi

# --- Step 2: Create clean agent build directory ---
rm -rf agent-build
mkdir -p agent-build/com/fuzzer/agent
mkdir -p agent-build/META-INF

# --- Step 3: Copy ALL agent classes (including inner/anonymous classes) ---
cp target/test-classes/com/fuzzer/agent/*.class agent-build/com/fuzzer/agent/

# --- Step 4: Shade ASM into agent jar (self-contained) ---
ASM_JAR="$HOME/.m2/repository/org/ow2/asm/asm/9.7/asm-9.7.jar"
if [ -f "$ASM_JAR" ]; then
    echo "[build-agent] Shading ASM from $ASM_JAR"
    (cd agent-build && jar xf "$ASM_JAR" org/objectweb/asm/)
else
    echo "[build-agent] WARNING: ASM jar not found at $ASM_JAR"
    echo "[build-agent] Agent will rely on ASM from the runtime classpath"
fi

# --- Step 5: Create MANIFEST.MF ---
cat > agent-build/META-INF/MANIFEST.MF << 'EOF'
Manifest-Version: 1.0
Premain-Class: com.fuzzer.agent.V1MeasureAgent
Can-Retransform-Classes: true
EOF

# --- Step 6: Create agent jar ---
(cd agent-build && jar cmf META-INF/MANIFEST.MF "$WORKSPACE/v1-agent.jar" .)

echo "[build-agent] v1-agent.jar created:"
ls -la "$WORKSPACE/v1-agent.jar"

# --- Step 7: Save Maven test classpath for run.sh / launch.json ---
mvn -q dependency:build-classpath -DincludeScope=test \
    -Dmdep.outputFile="$WORKSPACE/.mvn-test-cp.txt" 2>/dev/null || true

echo "[build-agent] Done."
