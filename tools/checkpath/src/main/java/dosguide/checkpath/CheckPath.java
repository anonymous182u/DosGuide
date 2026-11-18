package dosguide.checkpath;

import dosguide.checkpath.HopParser.Hop;
import dosguide.checkpath.HopParser.MethodRef;
import dosguide.checkpath.SourceIndex.CallSite;
import dosguide.checkpath.SourceIndex.MethodInfo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;

/**
 * CheckPath grounds the entry-to-sink path that the analysis agent reports for a target
 * in the project's source code.
 *
 * <p>For each target it (1) resolves every hop of the path to a method, constructor or
 * external API, (2) checks that each pair of consecutive hops is connected by a call or a
 * field data flow (allowing a bounded number of omitted intermediate calls), and
 * (3) checks that the path ends in the file named by {@code source_path}. Failures are
 * reported as diagnostics that name the offending hop, so they can be returned to the agent.
 *
 * <p>Call edges are found on a name- and arity-based call graph; when a matching call can be
 * resolved with the JavaParser symbol solver, a call that resolves to an unrelated class is
 * discarded. CheckPath does not judge whether the mechanism is correct.
 */
public final class CheckPath {

    enum HopStatus { RESOLVED, EXTERNAL, UNRESOLVED, DROPPED }

    enum EdgeStatus { CALL, DISPATCH, DATAFLOW, INDIRECT, SEQUENCE, UNCHECKED, MISSING, SKIPPED }

    private static final int BFS_BUDGET = 50_000;
    private static final String VERSION = "1.0.0";
    private static final List<String> JDK_PACKAGES = List.of(
            "java.lang", "java.util", "java.util.regex", "java.util.zip", "java.io", "java.nio",
            "java.math", "java.security", "java.util.concurrent", "java.net", "java.text",
            "java.lang.reflect", "javax.xml.parsers", "javax.xml.stream", "javax.crypto");

    private final SourceIndex idx;
    private final int maxGap;
    private final int sinkDepth;
    private final boolean resolve;
    private boolean requireSink;
    private final Map<MethodInfo, Set<String>> writes = new IdentityHashMap<>();
    private final Map<MethodInfo, Set<String>> reads = new IdentityHashMap<>();
    /** The resolved hops of the most recent check(), used by checkPlan() for the same target. */
    private List<HopResult> lastHops = List.of();

    CheckPath(SourceIndex idx, int maxGap, int sinkDepth, boolean resolve) {
        this.idx = idx;
        this.maxGap = maxGap;
        this.sinkDepth = sinkDepth;
        this.resolve = resolve;
    }

    /** Resolution result for one hop. */
    private static final class HopResult {
        final Hop hop;
        final List<MethodInfo> candidates = new ArrayList<>();
        final List<MethodRef> external = new ArrayList<>();
        final List<MethodRef> unresolved = new ArrayList<>();
        /** References whose method exists, but not in the named class's hierarchy. */
        final Map<MethodRef, List<MethodInfo>> misattributed = new LinkedHashMap<>();
        final List<String> notes = new ArrayList<>();
        final List<String> ignored = new ArrayList<>();
        HopStatus status;

        HopResult(Hop hop) {
            this.hop = hop;
        }
    }

    /**
     * Outcome of checking one pair of consecutive hops. {@code caveat}, if not null, is a warning about the
     * evidence (a dispatch through a supertype that could not be resolved).
     */
    private record Edge(EdgeStatus status, String evidence, List<String> chain,
                        MethodInfo from, MethodInfo to, List<MethodInfo> via, String caveat) {
        Edge(EdgeStatus status, String evidence, List<String> chain) {
            this(status, evidence, chain, null, null, List.of(), null);
        }

        /** The same edge with the declarations its evidence uses (null when outside the source tree). */
        Edge witnessed(MethodInfo f, MethodInfo t, List<MethodInfo> v) {
            return new Edge(status, evidence, chain, f, t, v, caveat);
        }

        Edge withCaveat(String c) {
            return new Edge(status, evidence, chain, from, to, via, c);
        }
    }

    // ------------------------------------------------------------------
    // Per-target check
    // ------------------------------------------------------------------

    Map<String, Object> check(String targetId, String entrypoint, String sourcePath) {
        return check(targetId, entrypoint, sourcePath, null);
    }

    /**
     * @param sinkSpec optional declared vulnerable method ("Class#method" or "Class.method(T)"); when
     *                 given, the path must pass through it rather than merely through source_path
     */
    Map<String, Object> check(String targetId, String entrypoint, String sourcePath, String sinkSpec) {
        List<String> diagnostics = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        String sink = normalizeSink(sourcePath);
        Set<String> sinkFiles = findSinkFiles(sink);

        List<HopResult> hops = new ArrayList<>();
        List<String> droppedHops = new ArrayList<>();
        for (Hop h : HopParser.parse(entrypoint)) {
            HopResult r = resolveHop(h, hops.isEmpty() ? null : hops.get(hops.size() - 1));
            if (r.status == HopStatus.DROPPED) {
                droppedHops.add(h.raw);
                warnings.add("Hop " + (h.index + 1) + " `" + h.raw + "` names no method in the source tree "
                        + "(a constant, a class or prose); it is ignored.");
                continue;
            }
            Set<String> written = new java.util.HashSet<>();
            h.alternatives.forEach(ref -> {
                if (ref.className != null) {
                    written.add(ref.className);
                }
            });
            rankCandidates(r.candidates, sinkFiles, sink, written);
            hops.add(r);
            long names = h.alternatives.stream().map(ref -> ref.name).distinct().count();
            if (names > 1 && !h.raw.matches(".*(/|\\||\\bor\\b).*")) {
                warnings.add("Hop " + (h.index + 1) + " `" + h.raw + "` names several methods; write one method "
                        + "per hop, in call order, separated by →.");
            }
        }

        // "A via B" does not say who calls whom: keep the order whose connection the code supports best.
        for (int i = 0; i + 1 < hops.size(); i++) {
            HopResult a = hops.get(i);
            HopResult b = hops.get(i + 1);
            if (!a.hop.unorderedWithNext) {
                continue;
            }
            if (strength(edge(b, a)) > strength(edge(a, b))) {
                hops.set(i, b);
                hops.set(i + 1, a);
                warnings.add(String.format("Hops %d `%s` and %d `%s` were joined by \"via\"; checked in the order "
                        + "%d → %d, which the code supports", a.hop.index + 1, a.hop.raw, b.hop.index + 1, b.hop.raw,
                        b.hop.index + 1, a.hop.index + 1));
            }
        }

        if (hops.isEmpty()) {
            diagnostics.add("The entrypoint chain `" + entrypoint + "` contains no method reference. "
                    + "Write the path as `Class.method(ParamType, ...) → Class.method(...) → ...` "
                    + "from the public entry point to the vulnerable location.");
        }

        for (HopResult r : hops) {
            if (r.status == HopStatus.UNRESOLVED) {
                for (MethodRef ref : r.unresolved) {
                    diagnostics.add(String.format("Hop %d `%s` does not match any method in the source tree.%s",
                            r.hop.index + 1, ref.raw, suggest(ref.name)));
                }
                r.misattributed.forEach((ref, named) -> diagnostics.add(String.format(
                        "Hop %d `%s`: `%s` is not declared in %s or its supertypes/subtypes; it is declared in %s. "
                                + "Correct the class, or the path if a different method was meant.",
                        r.hop.index + 1, ref.raw, ref.name, ref.className, declarations(named))));
            }
            for (String n : r.notes) {
                warnings.add("Hop " + (r.hop.index + 1) + ": " + n);
            }
        }

        List<Map<String, Object>> edgeOut = new ArrayList<>();
        List<Edge> edgeList = new ArrayList<>();
        for (int i = 0; i + 1 < hops.size(); i++) {
            HopResult a = hops.get(i);
            HopResult b = hops.get(i + 1);
            Edge e = edge(a, b);
            edgeList.add(e);
            Map<String, Object> em = new LinkedHashMap<>();
            em.put("from", a.hop.index + 1);
            em.put("to", b.hop.index + 1);
            em.put("status", e.status().name());
            em.put("evidence", e.evidence());
            if (!e.chain().isEmpty()) {
                em.put("chain", e.chain());
            }
            edgeOut.add(em);
            switch (e.status()) {
                case MISSING -> diagnostics.add(e.evidence().isEmpty()
                        ? String.format("No call or field data flow from hop %d `%s` to hop %d `%s` within %d "
                                + "intermediate call(s). %s%s", a.hop.index + 1, a.hop.raw, b.hop.index + 1,
                                b.hop.raw, maxGap, calleeHint(a), callerHint(b))
                        : String.format("Hops %d `%s` and %d `%s` are in the wrong order: %s. List the hops from "
                                + "the entry point toward the vulnerable location.", a.hop.index + 1, a.hop.raw,
                                b.hop.index + 1, b.hop.raw, e.evidence()));
                case UNCHECKED -> warnings.add(String.format("Edge %d→%d not checked: %s",
                        a.hop.index + 1, b.hop.index + 1, e.evidence()));
                case INDIRECT -> warnings.add(String.format("Edge %d→%d is indirect: %s",
                        a.hop.index + 1, b.hop.index + 1, String.join(" → ", e.chain())));
                case SEQUENCE -> warnings.add(String.format("Edge %d→%d is a call sequence, not a call chain: %s",
                        a.hop.index + 1, b.hop.index + 1, e.evidence()));
                default -> {
                }
            }
            if (e.caveat() != null) {
                warnings.add(String.format("Edge %d→%d %s", a.hop.index + 1, b.hop.index + 1, e.caveat()));
            }
        }

        boolean startOk = !hops.isEmpty() && hops.get(0).status != HopStatus.UNRESOLVED
                && (idx.hasHarness() ? checkHarnessEntry(hops.get(0), diagnostics)
                                     : checkEntry(hops.get(0), diagnostics, warnings));
        Map<String, Object> end = checkSink(hops, sink, sinkFiles, diagnostics, warnings);
        if (requireSink && (sinkSpec == null || sinkSpec.isBlank())) {
            diagnostics.add("The target has no `sink`. Add the method where the resource is actually consumed "
                    + "(`Class#method`; for a risk inside a library, that library method); the path must pass through it.");
        }
        if (Boolean.TRUE.equals(end.get("ok")) && sinkSpec != null && !sinkSpec.isBlank()) {
            checkDeclaredSink(hops, sinkSpec, sinkFiles, end, diagnostics);
        } else if (Boolean.TRUE.equals(end.get("ok"))) {
            end.put("level", "file");
        }

        boolean ok = diagnostics.isEmpty();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("target", targetId);
        out.put("status", ok ? "PASS" : "FAIL");
        out.put("entrypoint", entrypoint);
        out.put("source_path", sourcePath);
        out.put("start_ok", startOk);
        if (startOk && idx.hasHarness()) {
            MethodInfo f = hops.get(0).candidates.stream().filter(m -> m.fuzzEntry).findFirst().orElseThrow();
            out.put("harness_entry", f.typeFqn + "#" + f.name);
        }
        out.put("end_ok", end.get("ok"));
        out.put("end", end);
        out.put("hops", hopsJson(hops));
        out.put("path_signature", signature(hops));
        out.put("normalized_path", normalizedPath(hops, edgeList));
        if (!droppedHops.isEmpty()) {
            out.put("ignored_hops", droppedHops);
        }
        out.put("edges", edgeOut);
        out.put("diagnostics", diagnostics);
        out.put("warnings", warnings);
        lastHops = hops;
        return out;
    }

    // ------------------------------------------------------------------
    // Guidance plan check
    // ------------------------------------------------------------------

    private static final List<String> SIGNAL_FIELDS =
            List.of("name", "quantity", "aggregation", "technique", "storage", "reset", "read");

    /**
     * Checks a target's guidance plan (Block 2) against the source. Every signal names where its cost
     * is incurred as Class#method; each location must resolve to a method in the source tree or to a
     * library method, and an in-tree location is related to the target's path as checked by the
     * preceding check(): on it, called from it, or calling into it within sink-depth calls. Also
     * checks that the plan is complete and that the retention policy uses declared signals.
     */
    Map<String, Object> checkPlan(String targetId, Object planEntry) {
        List<String> diagnostics = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        List<Map<String, Object>> signalsOut = new ArrayList<>();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("target", targetId);
        if (!(planEntry instanceof Map<?, ?> plan)) {
            diagnostics.add("There is no guidance plan for target " + targetId + ".");
            out.put("status", "FAIL");
            out.put("signals", signalsOut);
            out.put("diagnostics", diagnostics);
            out.put("warnings", warnings);
            return out;
        }
        // The harness method is on every path but is the API boundary, not where any cost is incurred.
        Set<MethodInfo> pathMethods = identitySet(lastHops.stream().flatMap(h -> h.candidates.stream())
                .filter(m -> !m.harness).toList());
        List<?> signals = plan.get("signals") instanceof List<?> l ? l : List.of();
        if (signals.isEmpty()) {
            diagnostics.add("Target " + targetId + ": the plan declares no signal.");
        }
        Set<String> names = new LinkedHashSet<>();
        for (Object o : signals) {
            if (!(o instanceof Map<?, ?> s)) {
                diagnostics.add("Target " + targetId + ": every entry of `signals` must be an object.");
                continue;
            }
            String name = str(s.get("name")).trim();
            String label = name.isEmpty() ? "(unnamed)" : name;
            for (String field : SIGNAL_FIELDS) {
                if (str(s.get(field)).isBlank()) {
                    diagnostics.add(String.format("Target %s, signal `%s`: `%s` is missing.", targetId, label, field));
                }
            }
            if (!name.isEmpty() && !names.add(name)) {
                diagnostics.add(String.format("Target %s: signal `%s` is declared twice.", targetId, name));
            }
            String technique = str(s.get("technique")).trim().toLowerCase();
            if (!technique.isEmpty() && !technique.equals("bytecode") && !technique.equals("wrapper")) {
                diagnostics.add(String.format("Target %s, signal `%s`: `technique` must be \"bytecode\" (instrument "
                        + "the location) or \"wrapper\" (measure around the target invocation), not \"%s\".",
                        targetId, label, technique));
            }
            List<String> locations = new ArrayList<>();
            if (s.get("locations") instanceof List<?> ls) {
                ls.forEach(x -> locations.add(str(x).trim()));
            } else if (!str(s.get("location")).isBlank()) {
                locations.add(str(s.get("location")).trim());
            }
            locations.removeIf(String::isEmpty);
            if (locations.isEmpty()) {
                diagnostics.add(String.format("Target %s, signal `%s`: `locations` must name where the cost is "
                        + "incurred as `Class#method`.", targetId, label));
            }
            List<Map<String, Object>> locOut = new ArrayList<>();
            for (String loc : locations) {
                locOut.add(checkLocation(targetId, label, loc, pathMethods, diagnostics, warnings));
            }
            Map<String, Object> so = new LinkedHashMap<>();
            so.put("name", name);
            so.put("technique", technique);
            so.put("locations", locOut);
            signalsOut.add(so);
        }
        List<String> retention = new ArrayList<>();
        if (plan.get("retention_signals") instanceof List<?> rs) {
            rs.forEach(x -> retention.add(str(x).trim()));
        }
        if (str(plan.get("retention")).isBlank()) {
            diagnostics.add("Target " + targetId + ": `retention` must describe which inputs are kept and prioritized.");
        }
        if (retention.isEmpty()) {
            diagnostics.add("Target " + targetId + ": `retention_signals` must list the signals the retention policy uses.");
        }
        for (String r : retention) {
            if (!names.contains(r)) {
                diagnostics.add(String.format("Target %s: the retention policy uses `%s`, which is not a declared signal.",
                        targetId, r));
            }
        }
        out.put("status", diagnostics.isEmpty() ? "PASS" : "FAIL");
        out.put("signals", signalsOut);
        out.put("diagnostics", diagnostics);
        out.put("warnings", warnings);
        return out;
    }

    private Map<String, Object> checkLocation(String targetId, String signal, String loc, Set<MethodInfo> pathMethods,
                                              List<String> diagnostics, List<String> warnings) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("written", loc);
        List<Hop> parsed = HopParser.parse(loc.replace('#', '.'));
        if (parsed.isEmpty()) {
            m.put("status", "INVALID");
            diagnostics.add(String.format("Target %s, signal `%s`: location `%s` is not a method reference; write "
                    + "`Class#method`.", targetId, signal, loc));
            return m;
        }
        HopResult r = resolveHop(parsed.get(0), null);
        if (r.status == HopStatus.DROPPED && loc.contains("#")) {
            // A location always names a method, so an upper-case name the source does not declare is a library
            // method if its class is outside the source tree or is an external supertype of a path class;
            // otherwise the class does not declare it.
            String cls = loc.substring(0, loc.indexOf('#')).trim();
            cls = cls.substring(cls.lastIndexOf('.') + 1);
            String outer = cls.contains("$") ? cls.substring(0, cls.indexOf('$')) : cls;
            String name = loc.substring(loc.indexOf('#') + 1).replaceAll("\\(.*", "").trim();
            boolean externalSuper = lastHops.stream().flatMap(h -> h.candidates.stream())
                    .anyMatch(x -> idx.externalAncestorNamed(x.typeSimple, outer));
            if (externalSuper || !idx.knownTypes.contains(outer)) {
                m.put("status", HopStatus.EXTERNAL.name());
                m.put("relation", "library");
            } else {
                m.put("status", HopStatus.UNRESOLVED.name());
                diagnostics.add(String.format("Target %s, signal `%s`: location `%s`: %s does not declare a method "
                        + "`%s`.%s", targetId, signal, loc, cls, name, suggest(name)));
            }
            return m;
        }
        m.put("status", r.status.name());
        switch (r.status) {
            case RESOLVED -> {
                MethodInfo hit = r.candidates.get(0);
                m.put("method", hit.typeFqn + "#" + hit.name);
                m.put("declared_at", hit.location());
                if (r.candidates.stream().allMatch(c -> c.harness)) {
                    m.put("relation", "harness");
                    diagnostics.add(String.format("Target %s, signal `%s`: location `%s` is in the fuzz harness (%s), "
                            + "the API boundary. Measure where the cost is incurred, in the code the path reaches.",
                            targetId, signal, loc, hit.location()));
                    break;
                }
                String relation;
                List<String> chain = List.of();
                if (r.candidates.stream().anyMatch(pathMethods::contains)) {
                    relation = "on_path";
                } else {
                    List<MethodInfo> down = pathMethods.isEmpty() ? null
                            : bfs(pathMethods, identitySet(r.candidates)::contains, 1, sinkDepth);
                    List<MethodInfo> up = down != null || pathMethods.isEmpty() ? null
                            : bfs(r.candidates, pathMethods::contains, 1, sinkDepth);
                    relation = down != null ? "called_from_path" : up != null ? "calls_into_path" : "unrelated";
                    List<MethodInfo> c = down != null ? down : up;
                    if (c != null) {
                        chain = c.stream().map(MethodInfo::label).toList();
                    }
                }
                m.put("relation", relation);
                if (!chain.isEmpty()) {
                    m.put("chain", chain);
                }
                if (relation.equals("unrelated")) {
                    warnings.add(String.format("Target %s, signal `%s`: no call chain of up to %d calls connects "
                            + "location `%s` (%s) with the target's attack path; check that the cost of this target "
                            + "is incurred there.", targetId, signal, sinkDepth, loc, hit.location()));
                }
            }
            case EXTERNAL -> m.put("relation", "library");
            case UNRESOLVED -> {
                for (MethodRef ref : r.unresolved) {
                    diagnostics.add(String.format("Target %s, signal `%s`: location `%s` does not match any method "
                            + "in the source tree.%s", targetId, signal, loc, suggest(ref.name)));
                }
                r.misattributed.forEach((ref, named) -> diagnostics.add(String.format(
                        "Target %s, signal `%s`: location `%s`: `%s` is not declared in %s; it is declared in %s.",
                        targetId, signal, loc, ref.name, ref.className, declarations(named))));
            }
            default -> diagnostics.add(String.format("Target %s, signal `%s`: location `%s` does not name a method; "
                    + "write `Class#method`.", targetId, signal, loc));
        }
        return m;
    }

    // ------------------------------------------------------------------
    // Hop resolution
    // ------------------------------------------------------------------

    private HopResult resolveHop(Hop hop, HopResult prev) {
        HopResult r = new HopResult(hop);
        List<MethodInfo> prevGot = List.of();
        boolean prevExternal = false;
        for (MethodRef ref : hop.alternatives) {
            int c0 = r.candidates.size();
            int e0 = r.external.size();
            if (ref.chained) {
                resolveChained(ref, prevGot, prevExternal, r);
            } else {
                resolveOne(ref, prev, r);
            }
            prevGot = new ArrayList<>(r.candidates.subList(c0, r.candidates.size()));
            prevExternal = r.external.size() > e0;
        }
        dedupe(r.candidates);

        if (!r.candidates.isEmpty()) {
            r.status = HopStatus.RESOLVED;
        } else if (!r.external.isEmpty()) {
            r.status = HopStatus.EXTERNAL;
        } else if (!r.unresolved.isEmpty() || !r.misattributed.isEmpty()) {
            r.status = HopStatus.UNRESOLVED;
        } else {
            r.status = HopStatus.DROPPED;
        }
        if (r.status == HopStatus.RESOLVED || r.status == HopStatus.EXTERNAL) {
            // Another alternative of the hop resolved; a misattributed one is only worth a note.
            r.misattributed.forEach((ref, named) -> r.notes.add(String.format(
                    "`%s` is attributed to %s, but `%s` is declared only in %s",
                    ref.raw, ref.className, ref.name, typesOf(named))));
        }
        return r;
    }

    /** Resolves one method reference of a hop into r (candidates, external refs, notes). */
    private void resolveOne(MethodRef ref, HopResult prev, HopResult r) {
        if (ref.className == null && ref.receiverName == null && !ref.constructor
                && OBJECT_METHODS.contains(ref.name)) {
            // toString()/equals() with no class could be any object's; do not guess an in-tree override.
            r.external.add(ref);
            r.notes.add("`" + ref.raw + "` is a java.lang.Object method written without a class; "
                    + "treated as a call on an unspecified object");
            return;
        }
        if (ref.maybeNotMethod) {
            List<MethodInfo> c = methodsOnly(idx.methodsNamed(ref.name));
            if (ref.className != null && idx.knownTypes.contains(ref.className)) {
                Set<String> fam = family(ref.className);
                c = c.stream().filter(m -> fam.contains(m.typeSimple)).toList();
            }
            if (c.isEmpty()) {
                r.ignored.add(ref.raw);
            } else {
                r.candidates.addAll(c);
            }
            return;
        }
        if (ref.bareWord) {
            List<MethodInfo> c = methodsOnly(idx.methodsNamed(ref.name));
            if (c.isEmpty()) {
                r.ignored.add(ref.raw);
            } else {
                r.candidates.addAll(c);
            }
            return;
        }
        if (ref.constructor && !idx.knownTypes.contains(ref.className) && ref.outerName != null
                && idx.knownTypes.contains(ref.outerName)) {
            // Outer.name(...) with an upper-case method name.
            Set<String> fam = family(ref.outerName);
            List<MethodInfo> c = methodsOnly(idx.methodsNamed(ref.name)).stream()
                    .filter(m -> fam.contains(m.typeSimple)).toList();
            if (!c.isEmpty()) {
                r.candidates.addAll(byArity(c, ref, r));
                return;
            }
        }
        if (ref.className != null && prev != null
                && prev.candidates.stream().anyMatch(m -> idx.externalAncestorNamed(m.typeSimple, ref.className))) {
            r.external.add(ref);
            r.notes.add("`" + ref.raw + "` refers to " + ref.className + ", a supertype of the previous hop's class "
                    + "that is declared outside the source tree");
            return;
        }
        if (isExternalOwner(ref)) {
            r.external.add(ref);
            r.notes.add(externalNote(ref));
            return;
        }
        if (ref.constructor) {
            List<MethodInfo> c = idx.constructorsOf(ref.className);
            if (c.isEmpty()) {
                r.external.add(ref);
                r.notes.add("`" + ref.raw + "` uses the implicit default constructor of " + ref.className);
            } else {
                r.candidates.addAll(byArity(c, ref, r));
            }
            return;
        }
        if (("super".equals(ref.receiverName) || "this".equals(ref.receiverName))
                && prev != null && !prev.candidates.isEmpty()) {
            // super.m() is a superclass method of the previous hop's class (not that class itself);
            // this.m() stays within its hierarchy.
            boolean sup = "super".equals(ref.receiverName);
            Set<String> scope = new java.util.HashSet<>();
            for (MethodInfo m : prev.candidates) {
                if (sup) {
                    Set<String> anc = new java.util.HashSet<>(idx.ancestors(m.typeSimple));
                    anc.remove(m.typeSimple);
                    scope.addAll(anc);
                } else {
                    scope.addAll(family(m.typeSimple));
                }
            }
            List<MethodInfo> c = methodsOnly(idx.methodsNamed(ref.name)).stream()
                    .filter(m -> scope.contains(m.typeSimple)).toList();
            if (c.isEmpty()) {
                r.external.add(ref);
                r.notes.add("`" + ref.raw + "` calls a " + (sup ? "superclass " : "") + "method outside the source tree");
            } else {
                r.candidates.addAll(byArity(c, ref, r));
            }
            return;
        }
        String receiverType = receiverFieldType(ref, prev);
        if (receiverType != null && !idx.knownTypes.contains(receiverType)) {
            r.external.add(ref);
            r.notes.add(String.format("`%s`: field `%s` has type %s, which is outside the source tree",
                    ref.raw, ref.receiverName, receiverType));
            return;
        }
        List<MethodInfo> named = methodsOnly(idx.methodsNamed(ref.name));
        if (named.isEmpty()) {
            r.unresolved.add(ref);
            return;
        }
        List<MethodInfo> c = named;
        if (receiverType != null) {
            Set<String> fam = family(receiverType);
            List<MethodInfo> inFamily = named.stream().filter(m -> fam.contains(m.typeSimple)).toList();
            if (!inFamily.isEmpty()) {
                c = inFamily;
            } else {
                r.external.add(ref);
                r.notes.add(String.format("`%s`: field `%s` has type %s, which does not declare `%s` in the "
                        + "source tree", ref.raw, ref.receiverName, receiverType, ref.name));
                return;
            }
        }
        if (ref.className != null) {
            Set<String> fam = family(ref.className);
            List<MethodInfo> inFamily = named.stream().filter(m -> fam.contains(m.typeSimple)).toList();
            if (inFamily.isEmpty()) {
                if (mayInheritExternally(ref.className, ref.name)) {
                    r.external.add(ref);
                    r.notes.add(String.format("`%s` is not declared in the source hierarchy of %s; "
                            + "assuming it is inherited from a supertype outside the source tree", ref.raw, ref.className));
                } else {
                    r.misattributed.put(ref, named);
                }
                return;
            }
            c = inFamily;
        }
        if (ref.packageName != null) {
            List<MethodInfo> inPkg = c.stream().filter(m -> m.typeFqn.startsWith(ref.packageName + ".")).toList();
            if (!inPkg.isEmpty()) {
                c = inPkg;
            }
        }
        r.candidates.addAll(byArity(c, ref, r));
    }

    /**
     * Resolves a call chained on the previous reference's result (Pattern.compile(s).matcher(t)):
     * within the hierarchy of the previous call's return type, or as
     * external when the previous call is outside the source tree.
     */
    private void resolveChained(MethodRef ref, List<MethodInfo> prevGot, boolean prevExternal, HopResult r) {
        if (prevGot.isEmpty()) {
            if (prevExternal) {
                r.external.add(ref);
                r.notes.add("`" + ref.raw + "` is called on the result of an external call; its body is not analyzed");
            } else {
                r.ignored.add(ref.raw);
            }
            return;
        }
        Set<String> receivers = new java.util.HashSet<>();
        for (MethodInfo m : prevGot) {
            if (m.returnType != null && !m.returnType.isEmpty() && !"void".equals(m.returnType)) {
                receivers.addAll(family(m.returnType));
            }
        }
        List<MethodInfo> c = methodsOnly(idx.methodsNamed(ref.name)).stream()
                .filter(m -> receivers.contains(m.typeSimple)).toList();
        if (c.isEmpty()) {
            r.external.add(ref);
            r.notes.add("`" + ref.raw + "` is called on a result whose type is outside the source tree");
            return;
        }
        r.candidates.addAll(byArity(c, ref, r));
    }

    /**
     * For {@code field.method(...)}, the declared type of {@code field} in the class of the
     * previous hop (or its ancestors), or null if it cannot be determined.
     */
    private String receiverFieldType(MethodRef ref, HopResult prev) {
        if (ref.receiverName == null || prev == null) {
            return null;
        }
        for (MethodInfo m : prev.candidates) {
            Optional<String> t = idx.fieldType(m.typeSimple, ref.receiverName);
            if (t.isPresent()) {
                return t.get();
            }
        }
        return null;
    }

    /** Methods that JDK code calls implicitly on application objects (collections, sorting, printing). */
    private static final Set<String> JDK_CALLBACKS = Set.of("hashCode", "equals", "compareTo", "compare", "toString");

    private static final Set<String> OBJECT_METHODS = Set.of(
            "toString", "hashCode", "equals", "getClass", "clone", "finalize", "notify", "notifyAll", "wait");

    /**
     * True if {@code cls} could inherit {@code method} from a supertype outside the source tree:
     * a JDK supertype that declares it, or a non-JDK supertype we cannot inspect.
     */
    private boolean mayInheritExternally(String cls, String method) {
        if (OBJECT_METHODS.contains(method)) {
            return true;
        }
        for (String a : idx.ancestors(cls)) {
            if (idx.knownTypes.contains(a)) {
                continue;
            }
            Optional<Class<?>> c = loadJdk(null, a);
            if (c.isEmpty() || declares(c.get(), method)) {
                return true;
            }
        }
        return false;
    }

    private static boolean declares(Class<?> c, String method) {
        Deque<Class<?>> todo = new ArrayDeque<>(List.of(c));
        Set<Class<?>> seen = new java.util.HashSet<>();
        while (!todo.isEmpty()) {
            Class<?> k = todo.pop();
            if (!seen.add(k)) {
                continue;
            }
            for (java.lang.reflect.Method m : k.getDeclaredMethods()) {
                if (m.getName().equals(method)) {
                    return true;
                }
            }
            if (k.getSuperclass() != null) {
                todo.push(k.getSuperclass());
            }
            todo.addAll(List.of(k.getInterfaces()));
        }
        return false;
    }

    /** True if the method is attributed to a class (or enclosing class) that is not in the source tree. */
    private boolean isExternalOwner(MethodRef ref) {
        if (ref.outerName != null && !idx.knownTypes.contains(ref.outerName)) {
            return true;
        }
        if (ref.className != null && !idx.knownTypes.contains(ref.className)) {
            return true;
        }
        // java.util.regex.Matcher.find() names the JDK class even where the tree declares a class of the same
        // simple name.
        return namesJdkClass(ref);
    }

    /** True if the reference is written with a package and names a JDK class that the source tree does not declare. */
    private boolean namesJdkClass(MethodRef ref) {
        if (ref.className == null || ref.packageName == null) {
            return false;
        }
        String fqn = ref.packageName + "." + (ref.outerName != null ? ref.outerName + "." : "") + ref.className;
        return !idx.sourceTypeFqns.contains(fqn) && idx.loadClass(fqn).isPresent();
    }

    private static String externalNote(MethodRef ref) {
        String cls = ref.outerName != null ? ref.outerName : ref.className;
        String where = loadJdk(ref.packageName, cls).map(c -> "JDK class " + c.getName())
                .orElse("a class outside the source tree");
        return "`" + ref.raw + "` belongs to " + where + "; its body is not analyzed";
    }

    private static Optional<Class<?>> loadJdk(String pkg, String simple) {
        List<String> pkgs = pkg != null ? List.of(pkg) : JDK_PACKAGES;
        for (String p : pkgs) {
            try {
                return Optional.of(Class.forName(p + "." + simple, false, ClassLoader.getPlatformClassLoader()));
            } catch (ClassNotFoundException | LinkageError e) {
                // try next package
            }
        }
        return Optional.empty();
    }

    private static List<MethodInfo> methodsOnly(List<MethodInfo> l) {
        return l.stream().filter(m -> !m.constructor).toList();
    }

    private static List<MethodInfo> byArity(List<MethodInfo> c, MethodRef ref, HopResult r) {
        if (ref.arity < 0) {
            return c;
        }
        List<MethodInfo> matched = c.stream().filter(m -> m.acceptsArity(ref.arity)).toList();
        if (!matched.isEmpty()) {
            // Prefer overloads whose declared parameter types are exactly the written ones.
            List<MethodInfo> exact = matched.stream().filter(m -> m.paramTypes.equals(ref.paramTypes)).toList();
            return exact.isEmpty() ? matched : exact;
        }
        Set<Integer> arities = new TreeSet<>();
        c.forEach(m -> arities.add(m.arity()));
        r.notes.add(String.format("`%s` is written with %d parameter(s); declared overloads take %s",
                ref.raw, ref.arity, arities));
        return c;
    }

    private static void dedupe(List<MethodInfo> l) {
        Set<MethodInfo> seen = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        l.removeIf(m -> !seen.add(m));
    }

    private Set<String> family(String typeSimple) {
        return idx.typeFamily(typeSimple);
    }

    // ------------------------------------------------------------------
    // Edges
    // ------------------------------------------------------------------

    private Edge edge(HopResult a, HopResult b) {
        if (a.status == HopStatus.UNRESOLVED || b.status == HopStatus.UNRESOLVED) {
            return new Edge(EdgeStatus.SKIPPED, "an endpoint is unresolved", List.of());
        }
        if (a.candidates.isEmpty()) {
            return new Edge(EdgeStatus.UNCHECKED, "hop " + (a.hop.index + 1)
                    + " is outside the source tree, so calls made inside it cannot be inspected", List.of());
        }

        // 1. Direct call into an in-source candidate.
        Optional<Edge> direct = directCall(a.candidates, b.candidates);
        if (direct.isPresent()) {
            return direct.get();
        }
        // 1b. Dynamic dispatch: hop a calls a method on a variable whose declared type is outside the source
        //     tree, and hop b is an in-tree override the call can run.
        Optional<Edge> dispatched = dispatchCall(a.candidates, b.candidates);
        if (dispatched.isPresent()) {
            return dispatched.get();
        }
        // 2. Direct call to an external API named by hop b.
        for (MethodInfo m : a.candidates) {
            for (CallSite cs : m.calls) {
                for (MethodRef ext : b.external) {
                    if (cs.name.equals(ext.name)) {
                        return new Edge(EdgeStatus.CALL, m.label() + " calls " + ext.raw + " at "
                                + m.file + ":" + cs.line, List.of()).witnessed(m, null, List.of());
                    }
                }
            }
        }
        // 3. Field data flow on the same object: a (or a same-object callee, e.g. a delegated
        //    constructor) writes a field that b (or a same-object callee) reads. This is how
        //    consecutive API calls on one object, such as `new Stream(in)` then `getNextEntry()`, connect.
        for (MethodInfo m : a.candidates) {
            for (MethodInfo t : b.candidates) {
                if (!family(m.typeSimple).contains(t.typeSimple)) {
                    continue;
                }
                Set<String> written = writes.computeIfAbsent(m,
                        k -> idx.fieldsWrittenClosure(List.of(k), maxGap + 1));
                Set<String> read = reads.computeIfAbsent(t,
                        k -> idx.fieldsReadClosure(List.of(k), maxGap + 1));
                // Prefer a field that m writes and t reads directly over one shared only through helpers
                // (e.g. `current` over a byte counter updated by count()).
                String best = null;
                int bestScore = -1;
                for (String f : new TreeSet<>(written)) {
                    if (!read.contains(f)) {
                        continue;
                    }
                    int score = (m.fieldsWritten.contains(f) ? 2 : 0) + (t.fieldsRead.contains(f) ? 1 : 0);
                    if (score > bestScore) {
                        best = f;
                        bestScore = score;
                    }
                }
                if (best != null) {
                    return new Edge(EdgeStatus.DATAFLOW, String.format(
                            "%s (%s) writes field `%s`, which %s (%s) reads%s", m.label(), m.location(), best,
                            t.label(), t.location(), bestScore == 3 ? "" : " (through helper calls)"), List.of())
                            .witnessed(m, t, List.of());
                }
            }
        }
        // 4. Indirect: reachable through up to maxGap omitted calls.
        Set<MethodInfo> targets = identitySet(b.candidates);
        Predicate<MethodInfo> goal = targets::contains;
        if (!b.external.isEmpty()) {
            Set<String> extNames = new LinkedHashSet<>();
            b.external.forEach(e -> extNames.add(e.name));
            goal = goal.or(m -> m.calls.stream().anyMatch(cs -> extNames.contains(cs.name)));
        }
        // At least one omitted call: a direct call was already tried above, and one the symbol
        // solver resolved to an unrelated class must not be re-admitted by name. An external hop b is
        // matched by name only, so the chain to it may not pass through calls on receivers of unknown
        // type (error.getMessage() must not lead to an unrelated module's map.computeIfAbsent()).
        // For an external b the goal is the in-tree method that calls it, which is itself omitted.
        // Calls on receivers typed outside the source tree may also be followed into in-tree overrides
        // (DISPATCH), each counting as one call; a chain without them is preferred.
        boolean external = b.candidates.isEmpty();
        List<MethodInfo> chain = external
                ? bfs(a.candidates, goal, 1, maxGap, true)
                : bfs(a.candidates, goal, 2, maxGap + 1);
        if (chain == null) {
            chain = external
                    ? bfs(a.candidates, goal, 1, maxGap, true, true)
                    : bfs(a.candidates, goal, 2, maxGap + 1, false, true);
        }
        if (chain != null) {
            List<String> labels = chain.stream().map(MethodInfo::label).toList();
            MethodInfo end = chain.get(chain.size() - 1);
            boolean endIsB = b.candidates.contains(end);
            String evidence = (chain.size() - (endIsB ? 2 : 1)) + " omitted call(s)";
            List<String> weak = new ArrayList<>();
            for (int i = 0; i + 1 < chain.size(); i++) {
                Optional<Map.Entry<CallSite, SourceIndex.Dispatch>> d = dispatchLink(chain.get(i), chain.get(i + 1));
                if (d.isPresent()) {
                    evidence += "; " + dispatchEvidence(chain.get(i), d.get().getKey(), d.get().getValue());
                    if (!d.get().getValue().confirmed()) {
                        weak.add(dispatchCaveat(chain.get(i), d.get().getKey(), d.get().getValue()));
                    }
                }
            }
            Edge e = new Edge(EdgeStatus.INDIRECT, evidence, labels)
                    .witnessed(chain.get(0), endIsB ? end : null, chain.subList(1, chain.size() - (endIsB ? 1 : 0)));
            return weak.isEmpty() ? e : e.withCaveat(String.join(" ", weak));
        }
        // Reversed order: b calls a directly. Reported before looking for weaker call-sequence evidence.
        Optional<Edge> reversed = directCall(b.candidates, a.candidates);
        if (reversed.isPresent()) {
            String ev = reversed.get().evidence().replaceFirst(" \\((resolved|name match)\\)$", "");
            return new Edge(EdgeStatus.MISSING, ev, List.of());
        }
        // 5. Call sequence: some method calls hop a and then hop b, or hop a
        //    creates the object that hop b is then invoked on (factory.createReader() → reader.next()).
        Optional<Edge> sibling = sibling(a.candidates, b.candidates);
        if (sibling.isPresent()) {
            return sibling.get();
        }
        Optional<Edge> creates = createsReceiver(a.candidates, b.candidates);
        if (creates.isPresent()) {
            return creates.get();
        }
        if (!a.external.isEmpty()) {
            return new Edge(EdgeStatus.UNCHECKED, "hop " + (a.hop.index + 1)
                    + " also names an external API whose body cannot be inspected", List.of());
        }
        if (!b.candidates.isEmpty() && b.candidates.stream().allMatch(t -> JDK_CALLBACKS.contains(t.name))) {
            return new Edge(EdgeStatus.UNCHECKED, "hop " + (b.hop.index + 1) + " is a callback such as hashCode() "
                    + "that JDK code (e.g. a HashMap) invokes implicitly", List.of());
        }
        return new Edge(EdgeStatus.MISSING, "", List.of());
    }

    /**
     * Hop a (within maxGap+1 calls) instantiates a class in the hierarchy that declares hop b, and b
     * is public API, so the caller can invoke it on the object a returns. Internal methods (e.g. a
     * protected expandEntity that only runs after a further next() call) do not qualify.
     */
    private Optional<Edge> createsReceiver(List<MethodInfo> from, List<MethodInfo> to) {
        Set<String> receivers = new java.util.HashSet<>();
        for (MethodInfo t : to) {
            if (!t.constructor && t.publicApi) {
                receivers.addAll(family(t.typeSimple));
            }
        }
        if (receivers.isEmpty()) {
            return Optional.empty();
        }
        // A method of the receiver's own class is invoked on an existing object, not a factory for it.
        List<MethodInfo> factories = from.stream().filter(m -> !receivers.contains(m.typeSimple)).toList();
        if (factories.isEmpty()) {
            return Optional.empty();
        }
        Predicate<MethodInfo> creates = m -> m.calls.stream()
                .anyMatch(cs -> cs.constructor && receivers.contains(cs.name));
        for (MethodInfo m : factories) {
            if (creates.test(m)) {
                return Optional.of(new Edge(EdgeStatus.SEQUENCE, createdEvidence(m, receivers), List.of())
                        .witnessed(m, null, List.of()));
            }
        }
        // Only follow calls whose receiver is known, so that an unrelated class that happens to
        // construct the same type (via a name-only match) is not taken as the factory.
        List<MethodInfo> chain = bfs(factories, creates, 1, maxGap + 1, true);
        if (chain == null) {
            return Optional.empty();
        }
        MethodInfo creator = chain.get(chain.size() - 1);
        return Optional.of(new Edge(EdgeStatus.SEQUENCE, createdEvidence(creator, receivers),
                chain.stream().map(MethodInfo::label).toList()).witnessed(chain.get(0), null, List.of()));
    }

    private static String createdEvidence(MethodInfo creator, Set<String> receivers) {
        for (CallSite cs : creator.calls) {
            if (cs.constructor && receivers.contains(cs.name)) {
                return String.format("%s creates a %s (%s:%d), on which the next hop is invoked",
                        creator.label(), cs.name, creator.file, cs.line);
            }
        }
        return creator.label() + " creates the receiver of the next hop";
    }

    /** How strongly an edge's evidence connects two hops (used to order a "via" pair). */
    private static int strength(Edge e) {
        return switch (e.status()) {
            case CALL, DISPATCH, INDIRECT, DATAFLOW -> 3;
            case SEQUENCE -> 2;
            case UNCHECKED -> 1;
            default -> 0;
        };
    }

    /** A method that calls both a candidate of hop a and a candidate of hop b. */
    private Optional<Edge> sibling(List<MethodInfo> from, List<MethodInfo> to) {
        if (from.isEmpty() || to.isEmpty()) {
            return Optional.empty();
        }
        Set<MethodInfo> fromSet = identitySet(from);
        for (Map.Entry<MethodInfo, CallSite> callerOfB : idx.callersOf(to, true)) {
            MethodInfo caller = callerOfB.getKey();
            for (CallSite cs : caller.calls) {
                if (cs.receiver == SourceIndex.Receiver.UNKNOWN) {
                    continue; // both calls must have a known receiver
                }
                for (MethodInfo t : idx.targetsOf(cs, caller)) {
                    if (fromSet.contains(t)) {
                        return Optional.of(new Edge(EdgeStatus.SEQUENCE, String.format(
                                "%s (%s) calls %s at line %d and %s at line %d", caller.label(), caller.location(),
                                t.label(), cs.line, callerOfB.getValue().name, callerOfB.getValue().line), List.of())
                                .witnessed(t, null, List.of()));
                    }
                }
            }
        }
        return Optional.empty();
    }

    private Optional<Edge> directCall(List<MethodInfo> from, List<MethodInfo> to) {
        if (to.isEmpty()) {
            return Optional.empty();
        }
        Set<MethodInfo> toSet = identitySet(to);
        Edge nameMatch = null;
        for (MethodInfo m : from) {
            for (CallSite cs : m.calls) {
                for (MethodInfo t : idx.targetsOf(cs, m)) {
                    if (!toSet.contains(t)) {
                        continue;
                    }
                    String where = m.label() + " calls " + t.label() + " at " + m.file + ":" + cs.line;
                    if (resolve && cs.arity >= 0) {
                        Optional<String> callee = idx.resolveCallee(m, cs);
                        if (callee.isPresent()) {
                            String simple = callee.get().substring(callee.get().lastIndexOf('.') + 1);
                            if (callee.get().equals(t.typeFqn) || family(t.typeSimple).contains(simple)) {
                                return Optional.of(new Edge(EdgeStatus.CALL, where + " (resolved)", List.of())
                                        .witnessed(m, t, List.of()));
                            }
                            continue; // resolves to an unrelated class
                        }
                    }
                    if (nameMatch == null) {
                        nameMatch = new Edge(EdgeStatus.CALL, where + " (name match)", List.of())
                                .witnessed(m, t, List.of());
                    }
                }
            }
        }
        return Optional.ofNullable(nameMatch);
    }

    /**
     * A call in a {@code from} method on a variable typed outside the source tree that may run a {@code to}
     * method by dynamic dispatch. Prefers a dispatch confirmed through resolved supertypes; the symbol solver,
     * when it resolves the call, fixes the overload.
     */
    private Optional<Edge> dispatchCall(List<MethodInfo> from, List<MethodInfo> to) {
        if (to.isEmpty()) {
            return Optional.empty();
        }
        Edge weak = null;
        for (MethodInfo m : from) {
            for (CallSite cs : m.calls) {
                if (!idx.externalReceiver(cs) || to.stream().noneMatch(t -> t.name.equals(cs.name))) {
                    continue;
                }
                SourceIndex.ResolvedCall rc = resolve ? idx.resolveCall(m, cs).orElse(null) : null;
                for (MethodInfo t : to) {
                    Optional<SourceIndex.Dispatch> d = idx.dispatch(cs, m, t, rc);
                    if (d.isEmpty()) {
                        continue;
                    }
                    Edge e = new Edge(EdgeStatus.DISPATCH, dispatchEvidence(m, cs, d.get()), List.of())
                            .witnessed(m, t, List.of());
                    if (d.get().confirmed()) {
                        return Optional.of(e);
                    }
                    if (weak == null) {
                        weak = e.withCaveat(dispatchCaveat(m, cs, d.get()));
                    }
                }
            }
        }
        return Optional.ofNullable(weak);
    }

    /** The dispatch by which {@code from} reaches {@code to} in a chain, if it is not an ordinary call edge. */
    private Optional<Map.Entry<CallSite, SourceIndex.Dispatch>> dispatchLink(MethodInfo from, MethodInfo to) {
        Map.Entry<CallSite, SourceIndex.Dispatch> weak = null;
        for (CallSite cs : from.calls) {
            if (idx.targetsOf(cs, from).contains(to)) {
                return Optional.empty();
            }
        }
        for (CallSite cs : from.calls) {
            Optional<SourceIndex.Dispatch> d = idx.dispatch(cs, from, to, null);
            if (d.isPresent() && d.get().confirmed()) {
                return Optional.of(Map.entry(cs, d.get()));
            }
            if (d.isPresent() && weak == null) {
                weak = Map.entry(cs, d.get());
            }
        }
        return Optional.ofNullable(weak);
    }

    private static String dispatchEvidence(MethodInfo m, CallSite cs, SourceIndex.Dispatch d) {
        MethodInfo t = d.target();
        String recv = d.receiverType().name() + (d.receiverType().loaded() != null
                ? " (outside the source tree)" : " (outside the source tree, not resolved)");
        String over = d.overridden() != null ? ", overriding " + d.overridden() : "";
        if (d.confirmed()) {
            return String.format("%s calls %s on a %s at %s:%d, which dispatches to %s (%s)%s: %s is a %s through %s "
                            + "(resolved)", m.label(), cs.name, recv, m.file, cs.line, t.label(), t.location(), over,
                    t.typeSimple, d.receiverType().name(), d.through());
        }
        return String.format("%s calls %s on a %s at %s:%d, which may dispatch to %s (%s)%s; %s's supertype %s "
                        + "could not be resolved, so %s is not confirmed to be a %s (unresolved ancestor)",
                m.label(), cs.name, recv, m.file, cs.line, t.label(), t.location(), over, t.typeSimple,
                String.join(", ", d.unresolved()), t.typeSimple, d.receiverType().name());
    }

    private static String dispatchCaveat(MethodInfo m, CallSite cs, SourceIndex.Dispatch d) {
        return String.format("rests on an unconfirmed dispatch: %s's supertype %s is outside the source tree and could "
                        + "not be resolved, so %s is taken to be what the call to %s on a %s at %s:%d runs because its "
                        + "name and parameter %s match.", d.target().typeSimple, String.join(", ", d.unresolved()),
                d.target().label(), cs.name, d.receiverType().name(), m.file, cs.line,
                d.overridden() != null ? "types" : "count");
    }

    /**
     * Shortest call chain from any start method to a goal method that uses between {@code minEdges}
     * and {@code maxEdges} calls.
     */
    private List<MethodInfo> bfs(Collection<MethodInfo> starts, Predicate<MethodInfo> goal, int minEdges, int maxEdges) {
        return bfs(starts, goal, minEdges, maxEdges, false);
    }

    /** As above; with {@code preciseOnly}, calls on a receiver of unknown type are not followed. */
    private List<MethodInfo> bfs(Collection<MethodInfo> starts, Predicate<MethodInfo> goal, int minEdges, int maxEdges,
                                 boolean preciseOnly) {
        return bfs(starts, goal, minEdges, maxEdges, preciseOnly, false);
    }

    /**
     * As above; with {@code dispatch}, a call on a variable typed outside the source tree is also followed
     * into the in-tree overrides it may run (see {@link SourceIndex#dispatch}).
     */
    private List<MethodInfo> bfs(Collection<MethodInfo> starts, Predicate<MethodInfo> goal, int minEdges, int maxEdges,
                                 boolean preciseOnly, boolean dispatch) {
        Map<MethodInfo, MethodInfo> parent = new IdentityHashMap<>();
        Map<MethodInfo, Integer> depth = new IdentityHashMap<>();
        Deque<MethodInfo> queue = new ArrayDeque<>();
        for (MethodInfo s : starts) {
            parent.put(s, null);
            depth.put(s, 0);
            queue.add(s);
        }
        int expanded = 0;
        while (!queue.isEmpty() && expanded < BFS_BUDGET) {
            MethodInfo cur = queue.poll();
            expanded++;
            int d = depth.get(cur);
            if (d >= Math.max(1, minEdges) && goal.test(cur)) {
                return unwind(parent, cur);
            }
            if (d >= maxEdges) {
                continue;
            }
            for (CallSite cs : cur.calls) {
                if (preciseOnly && cs.receiver == SourceIndex.Receiver.UNKNOWN) {
                    continue;
                }
                List<MethodInfo> targets = idx.targetsOf(cs, cur);
                if (dispatch && idx.externalReceiver(cs)) {
                    targets = new ArrayList<>(targets);
                    targets.addAll(idx.dispatchTargetsOf(cs, cur));
                }
                for (MethodInfo next : targets) {
                    Integer seen = depth.get(next);
                    // A goal first reached too early (e.g. by a rejected direct call) may be reached again
                    // through a longer route, but not through its own descendants (a cycle in `parent`).
                    boolean revisit = seen != null && seen < minEdges && d + 1 >= minEdges && goal.test(next)
                            && !onChain(parent, cur, next);
                    if (seen == null || revisit) {
                        parent.put(next, cur);
                        depth.put(next, d + 1);
                        queue.add(next);
                    }
                }
            }
        }
        return null;
    }

    /** True if {@code m} is {@code from} or one of its ancestors in the BFS tree. */
    private static boolean onChain(Map<MethodInfo, MethodInfo> parent, MethodInfo from, MethodInfo m) {
        for (MethodInfo x = from; x != null; x = parent.get(x)) {
            if (x == m) {
                return true;
            }
        }
        return false;
    }

    private static List<MethodInfo> unwind(Map<MethodInfo, MethodInfo> parent, MethodInfo end) {
        List<MethodInfo> chain = new ArrayList<>();
        for (MethodInfo m = end; m != null; m = parent.get(m)) {
            chain.add(0, m);
        }
        return chain;
    }

    private static Set<MethodInfo> identitySet(Collection<MethodInfo> c) {
        Set<MethodInfo> s = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        s.addAll(c);
        return s;
    }

    // ------------------------------------------------------------------
    // Sink
    // ------------------------------------------------------------------

    private static String normalizeSink(String sourcePath) {
        return sourcePath == null ? "" : sourcePath.trim().replace('\\', '/').replaceFirst("^\\./", "");
    }

    /** Indexed files that the target's source_path refers to. */
    private Set<String> findSinkFiles(String sink) {
        Set<String> sinkFiles = new TreeSet<>();
        if (sink.isEmpty()) {
            return sinkFiles;
        }
        for (String f : idx.byFile.keySet()) {
            if (f.equals(sink) || f.endsWith("/" + sink) || sink.endsWith("/" + f)) {
                sinkFiles.add(f);
            }
        }
        return sinkFiles;
    }

    /**
     * Orders a hop's candidates so that evidence prefers the most plausible declaration: one in the
     * vulnerable file, then one in the same package (e.g. the copy of a generated class next to the
     * vulnerable file rather than another release's copy), then public API methods.
     */
    private static void rankCandidates(List<MethodInfo> candidates, Set<String> sinkFiles, String sink,
                                       Set<String> writtenClasses) {
        String sinkDir = sink.contains("/") ? sink.substring(0, sink.lastIndexOf('/') + 1) : "";
        candidates.sort(Comparator
                .comparing((MethodInfo m) -> !writtenClasses.isEmpty() && !writtenClasses.contains(m.typeSimple))
                .thenComparing(m -> m.typeFqn.contains("$anon("))
                .thenComparing(m -> !sinkFiles.contains(m.file))
                .thenComparing(m -> -commonPrefix(m.file, sinkDir))
                .thenComparing(m -> !m.publicApi));
    }

    /**
     * The first hop must be where input enters. It is rejected only if it is private or package-private,
     * which no caller outside the library can invoke. A protected method, or a public method of a
     * non-public class that does not override a supertype method, is reported but accepted: framework
     * callbacks receive input that way.
     */
    private boolean checkEntry(HopResult first, List<String> diagnostics, List<String> warnings) {
        if (first.candidates.isEmpty()) {
            return true; // an external API; nothing to inspect
        }
        if (first.candidates.stream().anyMatch(m -> m.publicApi
                || ("public".equals(m.visibility) && m.overrides))) {
            return true;
        }
        MethodInfo m = first.candidates.get(0);
        if (first.candidates.stream().anyMatch(c -> "protected".equals(c.visibility) || "public".equals(c.visibility))) {
            warnings.add(String.format("Hop 1 `%s` (%s %s at %s) is not public API; if it is not a framework callback "
                            + "that receives the input, start the path at the public method that does.",
                    first.hop.raw, m.visibility, m.label(), m.location()));
            return true;
        }
        diagnostics.add(String.format("Hop 1 `%s` is not part of the public API (%s %s at %s), so input cannot "
                        + "enter there. Start the path at the public method through which input enters.%s",
                first.hop.raw, m.visibility, m.label(), m.location(), callerHint(first)));
        return false;
    }

    /**
     * With a harness, the first hop must be one of its @Fuzz methods, where the fuzzer's input enters; the
     * edge to the second hop is then checked in the harness code like any other.
     */
    private boolean checkHarnessEntry(HopResult first, List<String> diagnostics) {
        if (first.candidates.stream().anyMatch(m -> m.fuzzEntry)) {
            return true;
        }
        List<MethodInfo> entries = idx.fuzzEntries();
        List<String> reaching = new ArrayList<>();
        for (MethodInfo f : entries) {
            HopResult h = new HopResult(first.hop);
            h.candidates.add(f);
            h.status = HopStatus.RESOLVED;
            EdgeStatus s = edge(h, first).status();
            if (s == EdgeStatus.CALL || s == EdgeStatus.DISPATCH || s == EdgeStatus.INDIRECT
                    || s == EdgeStatus.DATAFLOW || s == EdgeStatus.SEQUENCE) {
                reaching.add(fuzzLabel(f));
            }
        }
        String hint = !reaching.isEmpty() ? " @Fuzz methods that reach hop 1: " + String.join(", ", reaching) + "."
                : entries.isEmpty() ? " The harness declares no @Fuzz method."
                : " The harness's @Fuzz methods: " + String.join(", ", entries.stream().map(CheckPath::fuzzLabel).toList()) + ".";
        diagnostics.add(String.format("Hop 1 `%s` is not a @Fuzz method of the fuzz harness. The fuzzer's input enters "
                + "through the harness, so the path must start there: begin it with the harness's @Fuzz method that "
                + "drives this target, then the method it calls.%s", first.hop.raw, hint));
        return false;
    }

    private static String fuzzLabel(MethodInfo f) {
        return f.typeSimple + "." + f.name + "(" + String.join(", ", f.paramTypes) + ")";
    }

    /**
     * Checks that the path passes through the declared vulnerable method. An in-source sink must be
     * declared in source_path and be one of the path's hops; a sink outside the source tree (a risk in
     * a dependency) must be named by one of the path's external hops.
     */
    private void checkDeclaredSink(List<HopResult> hops, String sinkSpec, Set<String> sinkFiles,
                                   Map<String, Object> end, List<String> diagnostics) {
        end.put("level", "method");
        end.put("sink_method", sinkSpec);
        List<Hop> parsed = HopParser.parse(sinkSpec);
        if (parsed.isEmpty()) {
            end.put("ok", false);
            diagnostics.add("The declared sink `" + sinkSpec + "` is not a method reference; write it as Class#method.");
            return;
        }
        HopResult s = resolveHop(parsed.get(0), null);
        if (s.status == HopStatus.UNRESOLVED || s.status == HopStatus.DROPPED) {
            end.put("ok", false);
            diagnostics.add("The declared sink `" + sinkSpec + "` does not match any method in the source tree."
                    + (s.unresolved.isEmpty() ? "" : suggest(s.unresolved.get(0).name)));
            return;
        }
        if (!s.candidates.isEmpty()) {
            List<MethodInfo> inFile = s.candidates.stream().filter(m -> sinkFiles.contains(m.file)).toList();
            if (inFile.isEmpty()) {
                end.put("ok", false);
                diagnostics.add(String.format("The declared sink `%s` is declared in %s, not in `source_path`.",
                        sinkSpec, declarations(s.candidates)));
                return;
            }
            Set<MethodInfo> target = identitySet(inFile);
            for (HopResult h : hops) {
                if (h.candidates.stream().anyMatch(target::contains)) {
                    end.put("sink_evidence", "hop " + (h.hop.index + 1) + " is " + inFile.get(0).label());
                    return;
                }
            }
            HopResult last = null;
            for (int i = hops.size() - 1; i >= 0 && last == null; i--) {
                if (!hops.get(i).candidates.isEmpty()) {
                    last = hops.get(i);
                }
            }
            List<MethodInfo> chain = last == null ? null : bfs(last.candidates, target::contains, 1, sinkDepth);
            end.put("ok", false);
            diagnostics.add(chain != null
                    ? String.format("The path does not reach its declared sink `%s` (%s). It is reachable via %s; "
                            + "extend the path to it, or correct the sink.", sinkSpec, inFile.get(0).location(),
                            String.join(" → ", chain.stream().map(MethodInfo::label).toList()))
                    : String.format("The path does not reach its declared sink `%s` (%s), and the sink is not "
                            + "reachable from the end of the path within %d calls.", sinkSpec, inFile.get(0).location(),
                            sinkDepth));
            return;
        }
        // A sink outside the source tree, e.g. a dependency method for a package-level risk.
        Set<String> names = new java.util.HashSet<>();
        s.external.forEach(r -> names.add(r.name));
        for (HopResult h : hops) {
            if (h.external.stream().anyMatch(r -> names.contains(r.name))) {
                end.put("sink_evidence", "hop " + (h.hop.index + 1) + " names " + sinkSpec + " (outside the source tree)");
                return;
            }
        }
        end.put("ok", false);
        diagnostics.add("The path does not reach its declared sink `" + sinkSpec + "`, which is outside the source "
                + "tree. Add the call into it after the project hop that invokes the library.");
    }

    /**
     * The path as resolved declarations: each hop with the declaration its edges' evidence uses (or its
     * best-ranked candidate), each connection with its kind and evidence, and the calls an INDIRECT
     * connection omits made explicit (provenance "checkpath").
     */
    private static List<Map<String, Object>> normalizedPath(List<HopResult> hops, List<Edge> edges) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < hops.size(); i++) {
            HopResult h = hops.get(i);
            // Prefer a declaration of the class the agent wrote, among those the edges' evidence uses.
            Set<String> written = new java.util.HashSet<>();
            h.hop.alternatives.forEach(ref -> {
                if (ref.className != null) {
                    written.add(ref.className);
                }
            });
            List<MethodInfo> witnesses = new ArrayList<>();
            if (i > 0 && edges.get(i - 1).to() != null) {
                witnesses.add(edges.get(i - 1).to());
            }
            if (i < edges.size() && edges.get(i).from() != null) {
                witnesses.add(edges.get(i).from());
            }
            MethodInfo chosen = witnesses.stream().filter(m -> written.contains(m.typeSimple)).findFirst()
                    .orElse(witnesses.isEmpty() ? (h.candidates.isEmpty() ? null : h.candidates.get(0)) : witnesses.get(0));
            Map<String, Object> hop = new LinkedHashMap<>();
            hop.put("kind", "hop");
            hop.put("written", h.hop.raw);
            hop.put("provenance", "agent");
            if (chosen != null) {
                hop.put("method", chosen.typeFqn + "#" + chosen.name + "(" + String.join(",", chosen.paramTypes) + ")");
                hop.put("location", chosen.location());
            } else if (!h.external.isEmpty()) {
                hop.put("method", h.external.get(0).raw);
                hop.put("location", "outside the source tree");
            }
            out.add(hop);
            if (i < edges.size()) {
                Edge e = edges.get(i);
                Map<String, Object> conn = new LinkedHashMap<>();
                conn.put("kind", "connection");
                conn.put("type", e.status().name());
                conn.put("evidence", e.evidence());
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("([\\w./$-]+\\.java:\\d+)").matcher(e.evidence());
                if (m.find()) {
                    conn.put("site", m.group(1));
                }
                out.add(conn);
                for (MethodInfo v : e.via()) {
                    Map<String, Object> omitted = new LinkedHashMap<>();
                    omitted.put("kind", "hop");
                    omitted.put("written", null);
                    omitted.put("provenance", "checkpath (omitted call)");
                    omitted.put("method", v.typeFqn + "#" + v.name + "(" + String.join(",", v.paramTypes) + ")");
                    omitted.put("location", v.location());
                    out.add(omitted);
                }
            }
        }
        return out;
    }

    /** The methods a path resolves to, hop by hop; equal signatures mean two targets share a path. */
    private static List<String> signature(List<HopResult> hops) {
        List<String> sig = new ArrayList<>();
        for (HopResult h : hops) {
            if (!h.candidates.isEmpty()) {
                MethodInfo m = h.candidates.get(0);
                sig.add(m.typeFqn + "#" + m.name + "(" + String.join(",", m.paramTypes) + ")");
            } else if (!h.external.isEmpty()) {
                sig.add("external:" + h.external.get(0).name);
            }
        }
        return sig;
    }

    private Map<String, Object> checkSink(List<HopResult> hops, String sink, Set<String> sinkFiles,
                                          List<String> diagnostics, List<String> warnings) {
        Map<String, Object> end = new LinkedHashMap<>();
        end.put("sink_file", sink);
        if (sink.isEmpty()) {
            end.put("ok", false);
            diagnostics.add("The target has no `source_path`; the vulnerable location must name a source file.");
            return end;
        }
        if (sinkFiles.isEmpty()) {
            end.put("ok", false);
            diagnostics.add("`source_path` " + sink + " is not a source file under the source root.");
            return end;
        }

        // The path must pass through the vulnerable file. It may continue past it, e.g. into the
        // JDK method where the cost is incurred (BigDecimal.toString, Inflater.inflate).
        for (int i = hops.size() - 1; i >= 0; i--) {
            HopResult h = hops.get(i);
            for (MethodInfo m : h.candidates) {
                if (sinkFiles.contains(m.file)) {
                    end.put("ok", true);
                    end.put("evidence", "hop " + (h.hop.index + 1) + " " + m.label() + " is declared in " + m.location());
                    return end;
                }
            }
        }
        // A hop written as SinkClass.inheritedMethod() dispatches on the vulnerable class even if the
        // method body is inherited.
        for (int i = hops.size() - 1; i >= 0; i--) {
            HopResult h = hops.get(i);
            for (MethodRef ref : h.hop.alternatives) {
                if (ref.className == null || ref.constructor || namesJdkClass(ref)) {
                    continue; // a JDK class of the same simple name is not the vulnerable class
                }
                Set<String> files = idx.typeFiles.getOrDefault(ref.className, Set.of());
                if (!java.util.Collections.disjoint(files, sinkFiles)
                        && (h.status == HopStatus.RESOLVED || h.status == HopStatus.EXTERNAL)) {
                    end.put("ok", true);
                    end.put("evidence", "hop " + (h.hop.index + 1) + " invokes " + ref.name + " on "
                            + ref.className + ", which is declared in " + sink);
                    return end;
                }
            }
        }

        HopResult last = null;
        for (int i = hops.size() - 1; i >= 0; i--) {
            if (!hops.get(i).candidates.isEmpty()) {
                last = hops.get(i);
                break;
            }
        }
        if (last == null) {
            end.put("ok", false);
            diagnostics.add("No hop of the path resolves to a method in the source tree, so it cannot reach "
                    + sink + ".");
            return end;
        }
        List<MethodInfo> chain = bfs(last.candidates, m -> sinkFiles.contains(m.file), 1, sinkDepth);
        end.put("ok", false);
        if (chain != null) {
            List<String> labels = chain.stream().map(m -> m.label() + " (" + m.location() + ")").toList();
            end.put("reachable_via", labels);
            diagnostics.add(String.format(
                    "The path stops at hop %d `%s`, which is not in %s. That file is reachable via %s (%d call(s)); "
                            + "extend the path so that it ends at the vulnerable location in %s.",
                    last.hop.index + 1, last.hop.raw, sink, String.join(" → ", labels), chain.size() - 1, sink));
        } else {
            diagnostics.add(String.format(
                    "The path stops at hop %d `%s`, and no method in %s is reachable from it within %d calls.",
                    last.hop.index + 1, last.hop.raw, sink, sinkDepth));
        }
        return end;
    }

    // ------------------------------------------------------------------
    // Reporting helpers
    // ------------------------------------------------------------------

    private String suggest(String name) {
        String lower = name.toLowerCase();
        int minPrefix = Math.max(5, (name.length() + 1) / 2);
        List<String> best = idx.allMethodNames().stream()
                .map(n -> Map.entry(n, levenshtein(n.toLowerCase(), lower)))
                .filter(e -> e.getValue() <= Math.max(2, name.length() / 4)
                        || commonPrefix(e.getKey().toLowerCase(), lower) >= minPrefix)
                .sorted(Comparator.comparingInt((Map.Entry<String, Integer> e) -> e.getValue())
                        .thenComparing(Map.Entry::getKey))
                .limit(3)
                .map(Map.Entry::getKey)
                .toList();
        if (best.isEmpty()) {
            return "";
        }
        List<String> shown = new ArrayList<>();
        for (String n : best) {
            MethodInfo m = idx.methodsNamed(n).get(0);
            shown.add(m.label() + " (" + m.location() + ")");
        }
        return " Closest declared methods: " + String.join(", ", shown) + ".";
    }

    private static String calleeHint(HopResult a) {
        Set<String> names = new TreeSet<>();
        for (MethodInfo m : a.candidates) {
            for (CallSite cs : m.calls) {
                names.add(cs.name);
            }
        }
        if (names.isEmpty()) {
            return "Hop " + (a.hop.index + 1) + " makes no calls.";
        }
        List<String> shown = names.stream().limit(15).toList();
        return "Hop " + (a.hop.index + 1) + " calls: " + String.join(", ", shown)
                + (names.size() > shown.size() ? ", …" : "") + ".";
    }

    /** Where hop b is called from: its direct callers and the callers of those, to suggest a missing hop. */
    private String callerHint(HopResult b) {
        if (b.candidates.isEmpty()) {
            return "";
        }
        List<Map.Entry<MethodInfo, CallSite>> callers = idx.callersOf(b.candidates);
        if (callers.isEmpty()) {
            return " Hop " + (b.hop.index + 1) + " has no callers in the source tree.";
        }
        Set<String> shown = new LinkedHashSet<>();
        for (Map.Entry<MethodInfo, CallSite> c : callers) {
            MethodInfo m = c.getKey();
            String entry = m.label() + " (" + m.file + ":" + c.getValue().line + ")";
            for (Map.Entry<MethodInfo, CallSite> up : idx.callersOf(List.of(m))) {
                if (!up.getKey().name.equals(m.name)) { // skip recursion and overload delegation
                    entry = up.getKey().label() + " → " + entry;
                    break;
                }
            }
            shown.add(entry);
            if (shown.size() == 4) {
                break;
            }
        }
        return " Hop " + (b.hop.index + 1) + " is called from: " + String.join("; ", shown)
                + (callers.size() > shown.size() ? "; …" : "") + ".";
    }

    private static int commonPrefix(String a, String b) {
        int n = Math.min(a.length(), b.length());
        int i = 0;
        while (i < n && a.charAt(i) == b.charAt(i)) {
            i++;
        }
        return i;
    }

    private static String declarations(List<MethodInfo> l) {
        List<String> shown = l.stream().limit(3).map(m -> m.label() + " (" + m.location() + ")").toList();
        return String.join(", ", shown) + (l.size() > shown.size() ? ", …" : "");
    }

    private static String typesOf(List<MethodInfo> l) {
        Set<String> types = new TreeSet<>();
        l.forEach(m -> types.add(m.typeSimple));
        return String.join(", ", types);
    }

    private static List<Map<String, Object>> hopsJson(List<HopResult> hops) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (HopResult r : hops) {
            Map<String, Object> h = new LinkedHashMap<>();
            h.put("index", r.hop.index + 1);
            h.put("raw", r.hop.raw);
            h.put("status", r.status.name());
            List<Map<String, Object>> cands = new ArrayList<>();
            for (MethodInfo m : r.candidates.stream().limit(8).toList()) {
                Map<String, Object> c = new LinkedHashMap<>();
                c.put("method", m.typeFqn + "#" + m.name + "(" + String.join(",", m.paramTypes) + ")");
                c.put("location", m.location());
                cands.add(c);
            }
            h.put("candidates", cands);
            if (r.candidates.size() > 8) {
                h.put("more_candidates", r.candidates.size() - 8);
            }
            if (!r.external.isEmpty()) {
                h.put("external", r.external.stream().map(e -> e.raw).toList());
            }
            if (!r.ignored.isEmpty()) {
                h.put("ignored_tokens", r.ignored);
            }
            out.add(h);
        }
        return out;
    }

    private static int levenshtein(String a, String b) {
        int[] prev = new int[b.length() + 1];
        int[] cur = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            prev[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            cur[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                cur[j] = Math.min(Math.min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            int[] t = prev;
            prev = cur;
            cur = t;
        }
        return prev[b.length()];
    }

    // ------------------------------------------------------------------
    // CLI
    // ------------------------------------------------------------------

    private static final String USAGE = """
            Usage: java -jar checkpath.jar --source-root DIR
                     (--register target_register.json [--target ID[,ID...]]
                      | --entrypoint "A.m() → B.n()" --sink-file REL/PATH.java [--sink-method C#m] [--target ID])
                     [--max-gap N] [--sink-depth N] [--no-resolve] [--require-sink] [--scope REL_DIR]... [--include-tests]
                     [--harness DIR]... [--plan guidance_plan.json] [--out report.json]

            --harness indexes the fuzz harness (a fixture's src/) as well; each path must then start at one of its
            @Fuzz methods, the report gives that method as "harness_entry", and plan locations in the harness fail.

            --plan also checks each target's guidance plan: its signal locations must resolve in the source
            tree (or be library methods) and are related to the target's path; the report gets "plans" and
            "plan_ok".

            Exit status: 0 = every target passes, 1 = some target fails, 2 = usage or I/O error.
            """;

    public static void main(String[] args) {
        try {
            System.exit(run(args));
        } catch (IllegalArgumentException e) {
            System.err.println("checkpath: " + e.getMessage());
            System.err.print(USAGE);
            System.exit(2);
        } catch (IOException e) {
            System.err.println("checkpath: " + e.getMessage());
            System.exit(2);
        }
    }

    @SuppressWarnings("unchecked")
    static int run(String[] args) throws IOException {
        String sourceRoot = null;
        String register = null;
        String entrypoint = null;
        String sinkFile = null;
        String sinkMethod = null;
        String targetFilter = null;
        String outFile = null;
        String planFile = null;
        int maxGap = 2;
        int sinkDepth = 6;
        boolean resolve = true;
        boolean requireSink = false;
        boolean includeTests = false;
        List<String> scopes = new ArrayList<>();
        List<Path> harnessDirs = new ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--source-root" -> sourceRoot = value(args, ++i, a);
                case "--register" -> register = value(args, ++i, a);
                case "--entrypoint" -> entrypoint = value(args, ++i, a);
                case "--sink-file" -> sinkFile = value(args, ++i, a);
                case "--sink-method" -> sinkMethod = value(args, ++i, a);
                case "--target" -> targetFilter = value(args, ++i, a);
                case "--out" -> outFile = value(args, ++i, a);
                case "--plan" -> planFile = value(args, ++i, a);
                case "--max-gap" -> maxGap = Integer.parseInt(value(args, ++i, a));
                case "--sink-depth" -> sinkDepth = Integer.parseInt(value(args, ++i, a));
                case "--scope" -> scopes.add(value(args, ++i, a));
                case "--harness" -> harnessDirs.add(Path.of(value(args, ++i, a)));
                case "--no-resolve" -> resolve = false;
                case "--require-sink" -> requireSink = true;
                case "--include-tests" -> includeTests = true;
                case "-h", "--help" -> {
                    System.out.print(USAGE);
                    return 0;
                }
                default -> throw new IllegalArgumentException("unknown argument " + a);
            }
        }
        if (sourceRoot == null) {
            throw new IllegalArgumentException("--source-root is required");
        }
        if ((register == null) == (entrypoint == null)) {
            throw new IllegalArgumentException("give exactly one of --register or --entrypoint");
        }
        Path root = Path.of(sourceRoot);
        if (!Files.isDirectory(root)) {
            throw new IOException("source root is not a directory: " + root);
        }
        for (Path h : harnessDirs) {
            if (!Files.isDirectory(h)) {
                throw new IOException("harness is not a directory: " + h);
            }
        }

        List<String[]> targets = new ArrayList<>(); // {id, entrypoint, source_path}
        if (register != null) {
            Object parsed = Json.parse(Files.readString(Path.of(register), StandardCharsets.UTF_8));
            List<Object> entries;
            if (parsed instanceof Map<?, ?> m) {
                Object t = m.get("ordered_targets");
                if (t == null) {
                    t = m.get("targets");
                }
                entries = t instanceof List<?> l ? (List<Object>) l : List.of();
            } else if (parsed instanceof List<?> l) {
                entries = (List<Object>) l;
            } else {
                entries = List.of();
            }
            Set<String> wanted = targetFilter == null ? null : Set.of(targetFilter.split(","));
            for (Object o : entries) {
                if (!(o instanceof Map<?, ?> e)) {
                    continue;
                }
                String id = String.valueOf(e.get("id"));
                if (wanted != null && !wanted.contains(id)) {
                    continue;
                }
                targets.add(new String[]{id, str(e.get("entrypoint")), str(e.get("source_path")), str(e.get("sink"))});
            }
            if (targets.isEmpty()) {
                throw new IllegalArgumentException("no targets found in " + register);
            }
        } else {
            targets.add(new String[]{targetFilter == null ? "V1" : targetFilter, entrypoint, sinkFile, sinkMethod});
        }

        long t0 = System.nanoTime();
        SourceIndex idx = new SourceIndex(root, scopes, includeTests, harnessDirs);
        double indexSeconds = (System.nanoTime() - t0) / 1e9;

        Map<String, Object> plans = null;
        if (planFile != null) {
            plans = new LinkedHashMap<>();
            Object parsed = Json.parse(Files.readString(Path.of(planFile), StandardCharsets.UTF_8));
            Object list = parsed instanceof Map<?, ?> m ? m.get("plans") : parsed;
            if (list instanceof List<?> l) {
                for (Object o : l) {
                    if (o instanceof Map<?, ?> p && p.get("target") != null) {
                        plans.put(String.valueOf(p.get("target")), p);
                    }
                }
            }
        }

        CheckPath checker = new CheckPath(idx, maxGap, sinkDepth, resolve);
        checker.requireSink = requireSink;
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> planResults = new ArrayList<>();
        boolean allOk = true;
        boolean planOk = true;
        for (String[] t : targets) {
            Map<String, Object> r = checker.check(t[0], t[1], t[2], t[3]);
            allOk &= "PASS".equals(r.get("status"));
            results.add(r);
            if (plans != null) {
                Map<String, Object> pr = checker.checkPlan(t[0], plans.get(t[0]));
                planOk &= "PASS".equals(pr.get("status"));
                planResults.add(pr);
            }
        }

        markDuplicates(results);
        int methods = idx.byName.values().stream().mapToInt(List::size).sum();
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("tool", "checkpath");
        report.put("version", VERSION);
        report.put("source_root", root.toAbsolutePath().normalize().toString());
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("files_parsed", idx.filesParsed);
        stats.put("files_failed", idx.filesFailed);
        stats.put("methods", methods);
        stats.put("harness_fuzz_methods", idx.fuzzEntries().stream().map(CheckPath::fuzzLabel).toList());
        stats.put("index_seconds", Math.round(indexSeconds * 10) / 10.0);
        stats.put("max_gap", maxGap);
        stats.put("sink_depth", sinkDepth);
        stats.put("symbol_resolution", resolve);
        report.put("index", stats);
        report.put("ok", allOk);
        report.put("targets", results);
        if (plans != null) {
            report.put("plan_ok", planOk);
            report.put("plans", planResults);
        }

        String json = Json.write(report) + "\n";
        if (outFile != null) {
            Files.writeString(Path.of(outFile), json, StandardCharsets.UTF_8);
        }
        System.out.print(json);
        return allOk && planOk ? 0 : 1;
    }

    /**
     * Flags targets whose path resolves to exactly the same methods as an earlier target of the same
     * register (e.g. a dependency-level target rewritten as a copy of V1). A warning, not a failure:
     * some targets legitimately share an entry point and differ only in the code they trigger.
     */
    @SuppressWarnings("unchecked")
    static void markDuplicates(List<Map<String, Object>> results) {
        Map<List<String>, String> seen = new LinkedHashMap<>();
        for (Map<String, Object> r : results) {
            List<String> sig = (List<String>) r.get("path_signature");
            if (sig == null || sig.isEmpty()) {
                continue;
            }
            String first = seen.putIfAbsent(sig, String.valueOf(r.get("target")));
            if (first != null) {
                r.put("duplicate_of", first);
                ((List<String>) r.get("warnings")).add("The path is identical to target " + first
                        + "'s; if this target's risk is different (e.g. in a library), describe the route specific to it.");
            }
        }
    }

    private static String value(String[] args, int i, String flag) {
        if (i >= args.length) {
            throw new IllegalArgumentException(flag + " needs a value");
        }
        return args[i];
    }

    private static String str(Object o) {
        return o == null ? "" : o.toString();
    }
}
