package dosguide.checkpath;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses the informal entry-point chain that Block 1 writes into the target
 * register into an ordered list of hops.
 *
 * <p>Hops are separated by arrows ({@code →}, {@code ->}, {@code =>}). Within one hop,
 * several method references are treated as alternatives. Tokens that are not method references (English words such as
 * {@code "loop"}) are kept as "bare words" and are dropped later if no method of that
 * name exists in the source tree.
 */
final class HopParser {

    /** One method reference written by the LLM. */
    static final class MethodRef {
        final String raw;
        /** Simple class name the method is attributed to, or null if none was given. */
        final String className;
        /** Enclosing class for nested references (Pattern$Node.match -> Pattern), else null. */
        final String outerName;
        /** Package prefix if the reference was fully qualified, else null. */
        final String packageName;
        /** Method name; for constructors, the simple type name. */
        final String name;
        /** Number of parameters if a parameter list was written, else -1. */
        final int arity;
        /** Simple names of the written parameter types (may be empty). */
        final List<String> paramTypes;
        final boolean constructor;
        /** True when written without parentheses and without a class qualifier. */
        final boolean bareWord;
        /**
         * True for an upper-case name without parentheses: a class, constant or method. It is kept only if a method of that name exists.
         */
        final boolean maybeNotMethod;
        /** Lower-case receiver written before the method (a field or variable name), else null. */
        final String receiverName;
        /** True if called on the previous reference's result, e.g. the matcher in compile(s).matcher(t). */
        boolean chained;

        MethodRef(String raw, String className, String outerName, String packageName, String name, int arity,
                  List<String> paramTypes, boolean constructor, boolean bareWord) {
            this(raw, className, outerName, packageName, name, arity, paramTypes, constructor, bareWord, false, null);
        }

        MethodRef(String raw, String className, String outerName, String packageName, String name, int arity,
                  List<String> paramTypes, boolean constructor, boolean bareWord, boolean maybeNotMethod,
                  String receiverName) {
            this.raw = raw;
            this.className = className;
            this.outerName = outerName;
            this.packageName = packageName;
            this.name = name;
            this.arity = arity;
            this.paramTypes = paramTypes;
            this.constructor = constructor;
            this.bareWord = bareWord;
            this.maybeNotMethod = maybeNotMethod;
            this.receiverName = receiverName;
        }
    }

    /** One hop of the path: one or more alternative method references. */
    static final class Hop {
        final int index;
        final String raw;
        final List<MethodRef> alternatives;
        /** True if this hop and the next were written as "A via B", which does not say who calls whom. */
        final boolean unorderedWithNext;

        Hop(int index, String raw, List<MethodRef> alternatives, boolean unorderedWithNext) {
            this.index = index;
            this.raw = raw;
            this.alternatives = alternatives;
            this.unorderedWithNext = unorderedWithNext;
        }
    }

    /** A segment of the chain after splitting on connectors. */
    record Seg(String text, boolean unorderedWithNext) {
    }

    private static final Pattern ARROW = Pattern.compile("\\s*(?:→|->|=>|⇒|⟶|➜)\\s*");

    /** A dotted identifier, optionally followed by a (possibly nested) parameter list. */
    private static final Pattern TOKEN = Pattern.compile(
            "([A-Za-z_$][\\w$]*(?:\\s*[.#]\\s*[A-Za-z_$][\\w$]*)*)\\s*(\\((?:[^()]|\\([^()]*\\))*\\))?");

    private static final Set<String> NOISE = Set.of(
            "new", "loop", "loops", "via", "and", "or", "then", "inner", "outer", "while", "for",
            "if", "else", "return", "calls", "call", "through", "into", "with", "the", "a", "an",
            "of", "on", "in", "to", "from", "each", "every", "per", "recursive", "recursion",
            "recursively", "repeated", "repeatedly", "etc", "path", "entry", "sink");

    private HopParser() {
    }

    static List<Hop> parse(String chain) {
        List<Hop> hops = new ArrayList<>();
        if (chain == null || chain.isBlank()) {
            return hops;
        }
        String[] segments = ARROW.split(chain.trim());
        for (String segment : segments) {
            for (Seg seg : splitConnectors(segment.trim())) {
                if (seg.text().isEmpty()) {
                    continue;
                }
                List<MethodRef> refs = parseSegment(seg.text());
                if (!refs.isEmpty()) {
                    hops.add(new Hop(hops.size(), seg.text(), refs, seg.unorderedWithNext()));
                }
            }
        }
        return hops;
    }

    private static final Pattern CALLER_AFTER = Pattern.compile("\\s+(?:called from|called by|invoked from|invoked by)\\s+",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern CALLEE_AFTER = Pattern.compile("\\s+(?:calling|which calls)\\s+", Pattern.CASE_INSENSITIVE);
    private static final Pattern VIA = Pattern.compile("\\s+via\\s+", Pattern.CASE_INSENSITIVE);

    /**
     * Splits connectors so that the stated relation is checked instead of both methods sharing one
     * hop: "A called from B" becomes [B, A], "A calling B" becomes [A, B], and "A via B" becomes
     * [A, B] marked unordered, because "via" is used both ways ("ensureCapacity() via appendInt()",
     * "new JSONObject(s) via stringToValue()"); CheckPath orders such a pair from the code.
     * Connectors inside parentheses are left alone.
     */
    static List<Seg> splitConnectors(String seg) {
        for (Pattern p : List.of(CALLER_AFTER, CALLEE_AFTER, VIA)) {
            Matcher m = p.matcher(seg);
            while (m.find()) {
                if (parenDepth(seg, m.start()) != 0) {
                    continue;
                }
                String left = seg.substring(0, m.start()).trim();
                String right = seg.substring(m.end()).trim();
                if (left.isEmpty() || right.isEmpty()) {
                    break;
                }
                List<Seg> l = splitConnectors(left);
                List<Seg> r = splitConnectors(right);
                List<Seg> out = new ArrayList<>();
                if (p == CALLER_AFTER) {
                    out.addAll(r);
                    out.addAll(l);
                } else if (p == CALLEE_AFTER) {
                    out.addAll(l);
                    out.addAll(r);
                } else {
                    out.addAll(l.subList(0, l.size() - 1));
                    out.add(new Seg(l.get(l.size() - 1).text(), true));
                    out.addAll(r);
                }
                return out;
            }
        }
        return List.of(new Seg(seg, false));
    }

    private static int parenDepth(String s, int end) {
        int depth = 0;
        for (int i = 0; i < end; i++) {
            if (s.charAt(i) == '(') {
                depth++;
            } else if (s.charAt(i) == ')') {
                depth--;
            }
        }
        return depth;
    }

    /** JVM constructor notation: JSONObject.<init>(String) is new JSONObject(String). */
    private static final Pattern JVM_INIT = Pattern.compile("\\s*[.#]\\s*<init>\\s*(?=\\()");

    private static List<MethodRef> parseSegment(String seg) {
        seg = JVM_INIT.matcher(seg).replaceAll("");
        List<MethodRef> refs = new ArrayList<>();
        // In a hop written as prose, all-lowercase bare words are English; camelCase ones are still
        // taken as method names.
        boolean prose = seg.replaceAll("\\((?:[^()]|\\([^()]*\\))*\\)", " ").trim().split("\\s+").length >= 2;
        Matcher m = TOKEN.matcher(seg);
        int prevEnd = -1;
        while (m.find()) {
            // A call chained on the previous call's result (Pattern.compile(s).matcher(t).find()):
            // its receiver is whatever the previous call returned, resolved later.
            boolean chained = prevEnd > 0 && seg.charAt(prevEnd - 1) == ')'
                    && seg.substring(prevEnd, m.start()).matches("\\s*\\.\\s*");
            prevEnd = m.end();
            String dotted = m.group(1).replaceAll("\\s+", "").replace('#', '.');
            String params = m.group(2);
            MethodRef ref = toRef(m.group(0).trim(), dotted, params);
            if (ref == null) {
                continue;
            }
            if (!chained && prose && ref.bareWord && !ref.maybeNotMethod
                    && ref.name.equals(ref.name.toLowerCase())) {
                continue;
            }
            ref.chained = chained;
            refs.add(ref);
        }
        return inheritQualifier(seg, refs);
    }

    /**
     * The unqualified alternative belongs to the same class as the qualified one. Applies only to alternatives separated by "/", "|" or "or", and
     * only when exactly one class is named in the hop.
     */
    private static List<MethodRef> inheritQualifier(String seg, List<MethodRef> refs) {
        if (refs.size() < 2 || !seg.matches(".*(/|\\||\\bor\\b).*")) {
            return refs;
        }
        List<MethodRef> qualified = refs.stream().filter(r -> r.className != null && !r.constructor).toList();
        if (qualified.stream().map(r -> r.className).distinct().count() != 1) {
            return refs;
        }
        MethodRef q = qualified.get(0);
        List<MethodRef> out = new ArrayList<>();
        for (MethodRef r : refs) {
            if (r.className == null && r.receiverName == null && !r.constructor && !r.bareWord && !r.chained) {
                out.add(new MethodRef(r.raw, q.className, q.outerName, q.packageName, r.name, r.arity,
                        r.paramTypes, false, false, r.maybeNotMethod, null));
            } else {
                out.add(r);
            }
        }
        return out;
    }

    private static MethodRef toRef(String raw, String dotted, String params) {
        // Treat nested-class separators as plain components: Pattern$Node.match -> Pattern, Node, match.
        String[] parts = dotted.split("[.$]");
        String last = parts[parts.length - 1];
        boolean hasParams = params != null;
        List<String> paramTypes = hasParams && !isProse(params) ? parseParamTypes(params) : List.of();
        // LLMs write "foo()" to mean "the method foo", not "the zero-argument overload",
        // so empty parentheses leave the arity unknown.
        int arity = paramTypes.isEmpty() ? -1 : paramTypes.size();

        if (parts.length == 1) {
            if (NOISE.contains(last.toLowerCase())) {
                return null;
            }
            if (hasParams && Character.isUpperCase(last.charAt(0))) {
                return new MethodRef(raw, last, null, null, last, arity, paramTypes, true, false);
            }
            if (!hasParams && Character.isUpperCase(last.charAt(0))) {
                // A class name, a constant or an upper-case method name.
                return new MethodRef(raw, null, null, null, last, arity, paramTypes, false, true, true, null);
            }
            return new MethodRef(raw, null, null, null, last, arity, paramTypes, false, !hasParams);
        }

        if (Character.isUpperCase(last.charAt(0))) {
            String pkg = joinLowercasePrefix(parts, parts.length - 1);
            String owner = outer(parts, parts.length - 2);
            if (!hasParams) {
                return new MethodRef(raw, owner, outer(parts, parts.length - 3), pkg, last, arity, paramTypes,
                        false, false, true, null);
            }
            // pkg.Foo(...) or Outer.Inner(...) -> a constructor, unless Outer declares a method of that name.
            return new MethodRef(raw, last, owner, pkg, last, arity, paramTypes, true, false);
        }

        String owner = parts[parts.length - 2];
        if (!Character.isUpperCase(owner.charAt(0))) {
            // A receiver field or variable, or a package.
            boolean receiver = parts.length == 2;
            return new MethodRef(raw, null, null, null, last, arity, paramTypes, false, false, false,
                    receiver ? owner : null);
        }
        String pkg = joinLowercasePrefix(parts, parts.length - 2);
        return new MethodRef(raw, owner, outer(parts, parts.length - 3), pkg, last, arity, paramTypes, false, false);
    }

    /** The component at {@code i} if it names a class (upper-case), else null. */
    private static String outer(String[] parts, int i) {
        if (i < 0 || !Character.isUpperCase(parts[i].charAt(0))) {
            return null;
        }
        return parts[i];
    }

    /** Joins the leading lower-case components (the package), or returns null if there are none. */
    private static String joinLowercasePrefix(String[] parts, int end) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < end; i++) {
            if (!Character.isLowerCase(parts[i].charAt(0))) {
                break;
            }
            if (sb.length() > 0) {
                sb.append('.');
            }
            sb.append(parts[i]);
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static final Set<String> PRIMITIVES = Set.of(
            "byte", "short", "int", "long", "char", "float", "double", "boolean", "var");

    /**
     * True if the parenthesized text is a comment rather than a parameter list, e.g.
     * "(mutual recursion)" or "(via all Number formatting methods)".
     */
    static boolean isProse(String params) {
        String inner = params.substring(1, params.length() - 1).trim();
        if (inner.isEmpty()) {
            return false;
        }
        for (String p : splitTopLevel(inner)) {
            String t = stripGenerics(p.trim().replaceAll("@\\w+(\\([^)]*\\))?\\s*", "")
                    .replaceAll("^final\\s+", "")).trim();
            if (t.isEmpty()) {
                continue;
            }
            String[] words = t.split("\\s+");
            String type = words[0].replace("...", "").replace("[]", "");
            String simple = type.substring(type.lastIndexOf('.') + 1);
            boolean typeLike = !simple.isEmpty() && (Character.isUpperCase(simple.charAt(0)) || PRIMITIVES.contains(simple));
            if (!typeLike || words.length > 2) {
                return true; // "type name" has at most two words
            }
        }
        return false;
    }

    /** Extracts simple type names from "(Message query, List<String> xs, byte[] b, int... n)". */
    static List<String> parseParamTypes(String params) {
        String inner = params.substring(1, params.length() - 1).trim();
        List<String> types = new ArrayList<>();
        if (inner.isEmpty()) {
            return types;
        }
        for (String p : splitTopLevel(inner)) {
            String t = p.trim().replaceAll("@\\w+(\\([^)]*\\))?\\s*", "");
            t = t.replaceAll("^final\\s+", "");
            t = stripGenerics(t).trim();
            if (t.isEmpty() || t.equals("...")) {
                continue;
            }
            String typeToken = t.split("\\s+")[0];
            String simple = typeToken.substring(typeToken.lastIndexOf('.') + 1);
            types.add(simple);
        }
        return types;
    }

    private static List<String> splitTopLevel(String s) {
        List<String> out = new ArrayList<>();
        int depth = 0;
        int start = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '<' || c == '(') {
                depth++;
            } else if (c == '>' || c == ')') {
                depth--;
            } else if (c == ',' && depth == 0) {
                out.add(s.substring(start, i));
                start = i + 1;
            }
        }
        out.add(s.substring(start));
        return out;
    }

    private static String stripGenerics(String s) {
        StringBuilder sb = new StringBuilder();
        int depth = 0;
        for (char c : s.toCharArray()) {
            if (c == '<') {
                depth++;
            } else if (c == '>') {
                depth--;
            } else if (depth == 0) {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
