#!/bin/bash
# Build the DoS measurement agent jar.
# The agent combines:
#   - fuzzing.agent.DoSMeasureAgent (premain)
#   - fuzzing.agent.V1Counters
#   - fuzzing.agent.PkgRisk1Counters
#   - ASM 9.8 classes (for bytecode transformation)
# into a single fat jar with the proper MANIFEST.MF.

set -e
BASEDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASEDIR"

# Ensure compiled
mvn compile -q 2>&1 | tail -5
mvn package -DskipTests -q 2>&1 | tail -5

AGENT_DIR="$BASEDIR/target/agent-build"
rm -rf "$AGENT_DIR"
mkdir -p "$AGENT_DIR"

# Copy agent + counter classes (preserving package directory structure)
mkdir -p "$AGENT_DIR/fuzzing/agent"
cp target/test-classes/fuzzing/agent/*.class "$AGENT_DIR/fuzzing/agent/"

# Extract ASM classes from the ASM jar
ASM_JAR="$HOME/.m2/repository/org/ow2/asm/asm/9.8/asm-9.8.jar"
if [ ! -f "$ASM_JAR" ]; then
    echo "ERROR: ASM jar not found at $ASM_JAR"
    exit 1
fi
cd "$AGENT_DIR"
jar xf "$ASM_JAR" org/objectweb/asm

# Create MANIFEST.MF
mkdir -p META-INF
cat > META-INF/MANIFEST.MF << 'EOF'
Manifest-Version: 1.0
Premain-Class: fuzzing.agent.DoSMeasureAgent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
EOF

# Build the agent jar
jar cmf META-INF/MANIFEST.MF "$BASEDIR/dos-agent.jar" fuzzing/ org/

cd "$BASEDIR"
echo "Agent jar built: $BASEDIR/dos-agent.jar"
ls -la dos-agent.jar
