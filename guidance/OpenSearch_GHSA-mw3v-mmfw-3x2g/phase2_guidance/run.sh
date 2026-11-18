#!/usr/bin/env bash
# Build and run the V1 fuzzing setup (OpenSearch query_string -> classic QueryParser recursion, CWE-674).
# Usage: ./run.sh [durationSeconds]   (default 60; 0 = run indefinitely)
set -euo pipefail
cd "$(dirname "$0")"
DUR="${1:-60}"

# 1. Build
mvn compile -q 2>&1 | tail -30
mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt 2>&1 | tail -30
mkdir -p target/test-classes
javac -d target/test-classes -cp "target/classes:$(cat target/cp.txt)" $(find src/test/java -name '*.java') 2>&1 | tail -30
bash build-agent.sh   # self-contained agent jar (agent classes + ASM)

CP="target/test-classes:target/classes:$(cat target/cp.txt)"
JVM_OPTS="-Xmx1g -Xss1m -javaagent:target/v1-agent.jar"

# 2. Fuzz each selected target (V1 only; V2 was dropped by the scale measurement)
java $JVM_OPTS -cp "$CP" org.opensearch.fuzz.runner.FuzzRunner V1 "$DUR" out/V1 2>&1 | tail -50

# 3. Replay the deepest retained inputs from their metadata (no agent needed)
# java -Xmx1g -Xss1m -cp "$CP" org.opensearch.fuzz.repro.MetadataReplay out/V1/corpus --top 3 2>&1 | tail -50
# Reproduce a single input:
# java -Xmx1g -Xss1m -cp "$CP" org.opensearch.fuzz.repro.V1Repro out/V1/corpus/id_000123.bin 2>&1 | tail -50
