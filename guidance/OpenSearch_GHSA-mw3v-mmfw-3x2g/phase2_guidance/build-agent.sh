#!/usr/bin/env bash
# Builds target/v1-agent.jar as a self-contained agent: the V1 agent classes plus the ASM classes
# they use (asm, asm-commons, asm-tree, taken from the resolved Maven class path). The agent then
# works even when the fuzz classpath is loaded in a separate class loader and only the agent jar is
# on the JVM's system class path.
set -euo pipefail
cd "$(dirname "$0")"
STAGE=target/agent-stage
rm -rf "$STAGE"
mkdir -p "$STAGE"
for j in $(tr ':' '\n' < target/cp.txt | grep -E 'org/ow2/asm/asm(-commons|-tree)?/[^/]+/asm(-commons|-tree)?-[0-9.]+\.jar$'); do
  (cd "$STAGE" && jar xf "$j")
done
rm -rf "$STAGE/META-INF" "$STAGE/module-info.class"
find "$STAGE" -name module-info.class -delete
mkdir -p "$STAGE/org/opensearch/fuzz/agent"
cp target/test-classes/org/opensearch/fuzz/agent/*.class "$STAGE/org/opensearch/fuzz/agent/"
jar cfm target/v1-agent.jar src/test/resources/v1-agent.mf -C "$STAGE" .

# V1Counters also goes on the bootstrap class path (manifest Boot-Class-Path: v1-counters.jar, resolved
# next to the agent jar). Every parent-first class loader then resolves one shared counter class: the
# rewritten parser classes, the agent and V1Guidance all see the same counters.
CSTAGE=target/counters-stage
rm -rf "$CSTAGE"
mkdir -p "$CSTAGE/org/opensearch/fuzz/agent"
cp target/test-classes/org/opensearch/fuzz/agent/V1Counters.class "$CSTAGE/org/opensearch/fuzz/agent/"
jar cf target/v1-counters.jar -C "$CSTAGE" .
echo "built target/v1-agent.jar ($(jar tf target/v1-agent.jar | grep -c '\.class$') classes)"
