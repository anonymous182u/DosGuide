#!/usr/bin/env bash
# run.sh — Build and run fuzzer for V1 (ETAG regex quadratic backtracking)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Step 1: Compile workspace ==="
mvn package -DskipTests -q 2>&1 | tail -30

echo "=== Step 2: Build agent jar ==="
rm -rf agent-build/combined/com
mkdir -p agent-build/combined/com/fuzzing/agent
cp target/test-classes/com/fuzzing/agent/*.class agent-build/combined/com/fuzzing/agent/
ASM_JAR=$(find ~/.m2/repository/org/ow2/asm/asm -name 'asm-9.*.jar' | sort -V | tail -1)
(cd agent-build/combined && jar xf "$ASM_JAR" org/)
mkdir -p agent
jar cfm agent/v1-agent.jar agent-build/MANIFEST.MF -C agent-build/combined .
echo "Agent jar built: agent/v1-agent.jar"

echo "=== Step 3: Build classpath ==="
JQF_FUZZ_JAR=$(find ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1 -name '*.jar' | head -1)
JQF_INST_JAR=$(find ~/.m2/repository/edu/berkeley/cs/jqf/jqf-instrument/2.1 -name '*.jar' | head -1)
JUNIT_JAR=$(find ~/.m2/repository/junit/junit/4.13.2 -name '*.jar' | head -1)
HAMCREST_JAR=$(find ~/.m2/repository/org/hamcrest -name 'hamcrest-core-*.jar' | head -1)

CP="target/test-classes"
CP="$CP:lib/spring-web-5.3.38-SNAPSHOT.jar"
CP="$CP:lib/spring-core-5.3.38-SNAPSHOT.jar"
CP="$CP:lib/spring-jcl-5.3.38-SNAPSHOT.jar"
CP="$CP:$JQF_FUZZ_JAR"
CP="$CP:$JQF_INST_JAR"
CP="$CP:$ASM_JAR"
CP="$CP:$JUNIT_JAR"
CP="$CP:$HAMCREST_JAR"

DURATION=${1:-60}

echo "=== Step 4: Run FuzzRunner V1 for ${DURATION}s ==="
java -Xmx1g -Xss1m \
     -javaagent:"$SCRIPT_DIR/agent/v1-agent.jar" \
     -cp "$CP" \
     com.fuzzing.runner.FuzzRunner V1 "$DURATION" 2>&1 | tail -50

echo "=== Done ==="
