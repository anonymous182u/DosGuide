# Benchmark fixtures

One folder per subject (33). Each folder holds only the files written for the benchmark:

- `oracle.json`: the evaluation limits every engine runs with (per-execution time limit, JVM options, input size
  limit, see `scripts/oracle_config.py`) and the fixed version used by the fixed-version check (`fixed`).
- `src/`: the fuzz harness (the `@Fuzz` methods and the failure oracle they contain).
- `pom.xml`: the harness build. It refers to the library under test as `lib/<jar>` (system scope).
- `build.json`: how to obtain the parts that are not in the folder (below).

The library under test and the fixed release are not included. `fetch.py` obtains them:

- **Library under test (`lib/`)**: built from the project's vulnerable commit (`commit` in `build.json`, the same as
  `vuln_ref` in `campaign/synthesis_inputs.json`). It clones `clone_url` into a work directory, checks out the commit,
  and runs the build commands. Each project uses its own build (Maven, Gradle, sbt), or `javac` on the checked-out tree
  where that is how the evaluation's jar was made. Only build flags are added (skipping tests and checks such as
  checkstyle, rat or javadoc); the project's sources and build files are not changed. Third-party dependencies and
  build tools come from Maven Central or the project's wrapper.
- **Fixed release (`fixed/lib/`)**: release jars downloaded from Maven Central (one subject from the Jenkins
  repository), checked against the sha256 of the jars the evaluation used.

## Requirements

git, Python 3, Maven, network access to GitHub and Bitbucket (jose4j, snakeyaml), Maven Central, the Jenkins repository
(token-macro-plugin) and the projects' build-tool distributions, and the JDKs the recipes name (`jdk` in
`build.json`):

| JDK | subjects |
|---|---|
| 8 | 8, plus token-macro-plugin (its message-class generator) |
| 17 | 23 |
| 21 | OpenSearch, elasticsearch (Gradle builds of 2.19.3 and v8.19.7) |

snappy-java and netty-incubator-codec-quic contain native code and build only on Linux x86_64. Install the packages
listed in their `system_packages` first (C/C++ toolchain, CMake, static libstdc++; Rust and Cargo for quic).

## Usage

```
python3 benchmarks/fetch.py --all --jdk8 <JAVA_HOME of JDK 8> --jdk17 <JDK 17> --jdk21 <JDK 21> --keep-going
python3 benchmarks/fetch.py commons-compress_GHSA-hrmr-f5m6-m9pq --jdk8 <JDK 8>
```

`--work DIR` puts the checkouts and build trees elsewhere (default `benchmarks/.work`). `--out DIR` writes
`lib/` and `fixed/` under `DIR/<subject>/` instead of the subject folder. `--skip-lib` and `--skip-fixed` run one of
the two parts. The synthesis and the campaign read the fixtures in place (`--benchmarks-root benchmarks`), so run it
without `--out` before them.

The saved guidances in `guidance/<subject>/phase2_guidance/` build against their own `lib/`, a copy of the
fixture's `lib/` (the synthesis copies the fixture into the run directory). After `fetch.py`, copy it there:

```
for s in $(ls guidance); do [ -d benchmarks/$s/lib ] && cp -R benchmarks/$s/lib guidance/$s/phase2_guidance/; done
```

## Check

A rebuilt jar is not byte-identical to the evaluation's: manifests and timestamps differ. `fetch.py` therefore
compares the `.class` entries. `classes_sha256` in `build.json` is the sha256 of the sorted lines
"`<entry name> <sha256 of the entry>`" of the evaluation jar's `.class` entries (without the entries listed in
`classes_exclude`, used for one class that embeds the build time), and `fetch.py` reports for every jar
whether the rebuilt one has the same digest. The fixed jars must match their sha256 exactly. The summary at the end
lists `ok` for a subject where everything matched and `check` otherwise.

The native libraries of snappy-java and quic are rebuilt from the commit as well, but they are not compared (a
native build is not reproducible byte for byte); their `.class` entries are compared as for the other subjects.

## Notes on individual subjects

- **keycloak (GHSA-wq8x)**: the harness build compiles one project file itself,
  `org/keycloak/utils/SearchQueryUtils.java`. `fetch.py` copies it from the checkout into `src/main/java` (`sources`
  in `build.json`) and checks that it is byte-identical; there is no `lib/`. The fixed release replaces the compiled
  class (`drop` `^classes$`, the harness build's `target/classes`).
- **dnssecjava**: `lib/dnsjava-local-3.0.0.jar` is the third-party dependency dnsjava 3.0.0, downloaded from Maven
  Central and checked. The fixed release (dnsjava 3.6.0) has the validator under another package
  (`org.xbill.DNS.dnssec`), so the harness does not link against it. Its `oracle.json` has no `fixed` entry, as in
  the evaluation, where this subject's fixed-version check was a separate replay with the harness's import changed.
- **OpenSearch, elasticsearch**: built from the tags 2.19.3 and v8.19.7 (the Java 17 lines the advisories cover).
- **powsybl-core**: one class, `com/powsybl/tools/PowsyblCoreVersion.class` in powsybl-tools, embeds the build time,
  so it differs on every build; it is left out of the comparison (`classes_exclude` in `build.json`). All other
  classes are compared as usual.
- **snappy-java**: the build names its jar with the build time; the recipe copies it to a name without one,
  `snappy-java-1.1.10.3-17-49d70017-SNAPSHOT.jar`, which the pom uses. The fixture's jar is the evaluation's jar with
  the version lines of its MANIFEST written without the build time; its .class entries are identical.
- **token-macro-plugin**: needs JDK 8 for the project's message-class generator and JDK 17 for the rest; its fixed
  release is in the Jenkins repository.
