package dosguide.checkpath;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.EnumDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.RecordDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.MethodReferenceExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.UnaryExpr;
import com.github.javaparser.ast.stmt.ExplicitConstructorInvocationStmt;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.resolution.declarations.ResolvedMethodDeclaration;
import com.github.javaparser.resolution.types.ResolvedType;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Lightweight index of a Java source tree: method declarations, their call sites,
 * the fields they read and write, and the declared type hierarchy.
 *
 * <p>The index keeps no ASTs. Call-site resolution with the JavaParser symbol solver
 * is done on demand by re-parsing the caller's file (see {@link #resolveCallee}).
 */
final class SourceIndex {

    /** A method or constructor declared in the source tree. */
    static final class MethodInfo {
        final String typeFqn;
        final String typeSimple;
        /** Simple names of the lexically enclosing types, innermost first (excluding typeSimple). */
        final List<String> outerTypes;
        final String name;
        final List<String> paramTypes;
        final boolean varargs;
        final String file;
        final int line;
        final boolean constructor;
        /** "public", "protected", "package" or "private" (interface members count as public). */
        String visibility = "package";
        /** True if the method is public and every enclosing type is public (part of the public API). */
        boolean publicApi;
        /** True if the method carries @Override, i.e. it can be reached through a supertype's method. */
        boolean overrides;
        /** True for a static method, which no call can reach by dynamic dispatch. */
        boolean isStatic;
        /** Type parameters in scope (the method's and its enclosing types'), e.g. T in accept(T). */
        Set<String> typeParams = Set.of();
        /** Simple name of the declared return type ("void" for none; the class itself for constructors). */
        String returnType;
        /** True if declared in the fuzz harness (see {@link #HARNESS_PREFIX}), not in the source tree. */
        boolean harness;
        /** True for a harness method annotated {@code @Fuzz}: where the fuzzer's input enters. */
        boolean fuzzEntry;
        final List<CallSite> calls = new ArrayList<>();
        final Set<String> fieldsWritten = new HashSet<>();
        final Set<String> fieldsRead = new HashSet<>();

        MethodInfo(String typeFqn, String typeSimple, List<String> outerTypes, String name, List<String> paramTypes,
                   boolean varargs, String file, int line, boolean constructor) {
            this.typeFqn = typeFqn;
            this.typeSimple = typeSimple;
            this.outerTypes = outerTypes;
            this.name = name;
            this.paramTypes = paramTypes;
            this.varargs = varargs;
            this.file = file;
            this.line = line;
            this.constructor = constructor;
        }

        int arity() {
            return paramTypes.size();
        }

        boolean acceptsArity(int n) {
            if (n < 0) {
                return true;
            }
            return n == arity() || (varargs && n >= arity() - 1);
        }

        String label() {
            return typeSimple + "#" + name + "(" + String.join(",", paramTypes) + ")";
        }

        String location() {
            return file + ":" + line;
        }
    }

    /** How the receiver of a call was determined. */
    enum Receiver {
        /** No receiver or {@code this}: the caller's own class hierarchy (or an enclosing class). */
        SELF,
        /** {@code super.m()}. */
        SUPER,
        /** A receiver whose declared type is known from a parameter, local, field or class name. */
        TYPED,
        /** Any other receiver expression; the call may dispatch to any class. */
        UNKNOWN
    }

    /** A call made inside a method body. */
    static final class CallSite {
        final String name;
        final int arity;
        final int line;
        final boolean constructor;
        final Receiver receiver;
        /** Simple name of the receiver's declared type when {@code receiver == TYPED}. */
        final String receiverType;
        /**
         * True if receiverType is the declared type of a variable or field (not a class named for a static
         * call, a {@code new} expression or a type parameter), so the object may be of any subtype.
         */
        boolean declaredReceiver;
        /** The receiver's declared type as written when it is qualified (javax.xml.stream.XMLInputFactory), else null. */
        String receiverQualified;

        CallSite(String name, int arity, int line, boolean constructor, Receiver receiver, String receiverType) {
            this.name = name;
            this.arity = arity;
            this.line = line;
            this.constructor = constructor;
            this.receiver = receiver;
            this.receiverType = receiverType;
        }
    }

    /** The package and imports of one file, to name the types it mentions. */
    record Imports(String pkg, Map<String, String> explicit, List<String> wildcards) {
    }

    /** A supertype outside the source tree that an in-tree type reaches through in-tree supertypes. */
    record ExternalAncestor(String name, Class<?> loaded) {
    }

    /** A type outside the source tree: its qualified name (simple if unknown) and the class, if it can be loaded. */
    record ExternalType(String name, Class<?> loaded) {
    }

    /** A call resolved by the symbol solver: where the called method is declared and its erased parameter types. */
    record ResolvedCall(String declaringType, String receiverType, List<String> paramErasures,
                        List<Boolean> paramTypeVars, boolean isStatic) {
    }

    /**
     * How a call on a receiver whose declared type is outside the source tree can reach an in-tree method by
     * dynamic dispatch. {@code through} names the resolved external supertype of the target's class that is
     * a subtype of the receiver type; when it is null the connection rests on {@code unresolved}, external
     * supertypes that could not be loaded and may lie between the target's class and the receiver type.
     */
    record Dispatch(MethodInfo target, ExternalType receiverType, String overridden, String through,
                    List<String> unresolved) {
        boolean confirmed() {
            return through != null;
        }
    }

    private static final Pattern PACKAGE = Pattern.compile("^\\s*package\\s+([\\w.]+)\\s*;", Pattern.MULTILINE);
    private static final Set<String> SKIP_DIRS = Set.of("target", "build", ".git", "node_modules", ".gradle", "out");
    /** Prefix of the file names of harness files, which lie outside the source root. */
    static final String HARNESS_PREFIX = "harness/";

    final Path root;
    /** Harness file name (HARNESS_PREFIX + path relative to its harness directory) -> absolute path. */
    private final Map<String, Path> harnessFiles = new HashMap<>();
    final Map<String, List<MethodInfo>> byName = new HashMap<>();
    final Map<String, List<MethodInfo>> byFile = new HashMap<>();
    /** Simple type name -> simple names of its declared direct supertypes. */
    final Map<String, Set<String>> supertypes = new HashMap<>();
    final Set<String> knownTypes = new HashSet<>();
    /** Simple type name -> (field name -> simple declared type). */
    final Map<String, Map<String, String>> fieldTypes = new HashMap<>();
    /** Simple type name -> files that declare a type of that name. */
    final Map<String, Set<String>> typeFiles = new HashMap<>();
    /** Simple type name -> (simple name of a direct supertype -> its qualified name, from the imports). */
    final Map<String, Map<String, String>> superFqns = new HashMap<>();
    /** Qualified names of all types declared in the source tree. */
    final Set<String> sourceTypeFqns = new HashSet<>();
    /** File -> its package and imports. */
    final Map<String, Imports> fileImports = new HashMap<>();
    /** "Type|Super" for each direct supertype that a declaration of Type names by an import or a qualified name. */
    private final Set<String> explicitSupers = new HashSet<>();
    int filesParsed;
    int filesFailed;

    private final JavaParser resolvingParser;
    private final LruCache cuCache = new LruCache(48);
    private final Map<String, Set<String>> familyCache = new HashMap<>();
    private final Map<String, List<ExternalAncestor>> externalAncestorCache = new HashMap<>();
    private final Map<String, Optional<Class<?>>> classCache = new HashMap<>();
    private final Map<String, List<Dispatch>> dispatchCache = new HashMap<>();

    /** Small access-ordered cache of compilation units parsed for symbol resolution. */
    private static final class LruCache extends LinkedHashMap<String, CompilationUnit> {
        private final int capacity;

        LruCache(int capacity) {
            super(64, 0.75f, true);
            this.capacity = capacity;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, CompilationUnit> eldest) {
            return size() > capacity;
        }
    }

    SourceIndex(Path root, List<String> scopes, boolean includeTests) throws IOException {
        this(root, scopes, includeTests, List.of());
    }

    /**
     * @param harnessDirs directories holding the fuzz harness (a fixture's src/). Their .java files are indexed
     *                    too, test sources included, named HARNESS_PREFIX + the path from the directory's parent
     *                    (harness/src/test/java/...).
     */
    SourceIndex(Path root, List<String> scopes, boolean includeTests, List<Path> harnessDirs) throws IOException {
        this.root = root.toAbsolutePath().normalize();
        List<Path> files = collectFiles(this.root, scopes, includeTests);
        for (Path dir : harnessDirs) {
            Path d = dir.toAbsolutePath().normalize();
            Path base = d.getParent() != null ? d.getParent() : d;
            for (Path f : collectFiles(d, List.of(), true)) {
                harnessFiles.put(HARNESS_PREFIX + base.relativize(f).toString().replace('\\', '/'), f);
            }
        }

        Set<Path> sourceRoots = new TreeSet<>();
        for (Path f : files) {
            inferSourceRoot(f).ifPresent(sourceRoots::add);
        }
        for (Path f : harnessFiles.values()) {
            inferSourceRoot(f).ifPresent(sourceRoots::add);
        }
        CombinedTypeSolver typeSolver = new CombinedTypeSolver(new ReflectionTypeSolver(true));
        for (Path sr : sourceRoots) {
            typeSolver.add(new JavaParserTypeSolver(sr));
        }
        ParserConfiguration cfg = new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21)
                .setSymbolResolver(new JavaSymbolSolver(typeSolver));
        this.resolvingParser = new JavaParser(cfg);

        JavaParser indexParser = new JavaParser(new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21));
        for (Path f : files) {
            indexFile(indexParser, f, this.root.relativize(f).toString().replace('\\', '/'), false);
        }
        for (Map.Entry<String, Path> e : new java.util.TreeMap<>(harnessFiles).entrySet()) {
            indexFile(indexParser, e.getValue(), e.getKey(), true);
        }
    }

    /** True if harness directories were indexed. */
    boolean hasHarness() {
        return !harnessFiles.isEmpty();
    }

    /** The harness's @Fuzz methods. */
    List<MethodInfo> fuzzEntries() {
        List<MethodInfo> out = new ArrayList<>();
        byName.values().forEach(ms -> ms.stream().filter(m -> m.fuzzEntry).forEach(out::add));
        out.sort(java.util.Comparator.comparing(MethodInfo::location));
        return out;
    }

    // ------------------------------------------------------------------
    // Building
    // ------------------------------------------------------------------

    private static List<Path> collectFiles(Path root, List<String> scopes, boolean includeTests) throws IOException {
        List<Path> starts = new ArrayList<>();
        if (scopes == null || scopes.isEmpty()) {
            starts.add(root);
        } else {
            for (String s : scopes) {
                starts.add(root.resolve(s).normalize());
            }
        }
        List<Path> files = new ArrayList<>();
        for (Path start : starts) {
            if (!Files.isDirectory(start)) {
                continue;
            }
            try (Stream<Path> walk = Files.walk(start)) {
                walk.filter(p -> p.toString().endsWith(".java"))
                        .filter(p -> !p.getFileName().toString().equals("module-info.java"))
                        .filter(p -> !p.getFileName().toString().equals("package-info.java"))
                        .filter(p -> keep(root.relativize(p), includeTests))
                        .forEach(files::add);
            }
        }
        Collections.sort(files);
        return files;
    }

    private static boolean keep(Path rel, boolean includeTests) {
        String s = "/" + rel.toString().replace('\\', '/');
        for (Path part : rel) {
            if (SKIP_DIRS.contains(part.toString())) {
                return false;
            }
        }
        if (!includeTests && (s.contains("/src/test/") || s.contains("/src/it/")
                || s.contains("/src/jmh/") || s.contains("/src/testFixtures/"))) {
            return false;
        }
        return true;
    }

    /** The directory that the file's package declaration is relative to. */
    private static Optional<Path> inferSourceRoot(Path file) {
        try {
            String head = readHead(file);
            Matcher m = PACKAGE.matcher(head);
            Path dir = file.getParent();
            if (m.find()) {
                String[] pkg = m.group(1).split("\\.");
                for (int i = pkg.length - 1; i >= 0 && dir != null; i--) {
                    if (!dir.getFileName().toString().equals(pkg[i])) {
                        return Optional.empty();
                    }
                    dir = dir.getParent();
                }
            }
            return Optional.ofNullable(dir);
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    private static String readHead(Path file) throws IOException {
        byte[] bytes = Files.readAllBytes(file);
        int n = Math.min(bytes.length, 8192);
        return new String(bytes, 0, n, StandardCharsets.UTF_8);
    }

    private void indexFile(JavaParser parser, Path file, String rel, boolean harness) {
        ParseResult<CompilationUnit> result;
        try {
            result = parser.parse(file);
        } catch (IOException | RuntimeException | StackOverflowError e) {
            filesFailed++;
            return;
        }
        Optional<CompilationUnit> cuOpt = result.getResult();
        if (cuOpt.isEmpty()) {
            filesFailed++;
            return;
        }
        filesParsed++;
        CompilationUnit cu = cuOpt.get();

        Map<String, String> imports = new HashMap<>();
        List<String> wildcards = new ArrayList<>();
        cu.getImports().forEach(im -> {
            if (!im.isAsterisk() && !im.isStatic()) {
                String fqn = im.getNameAsString();
                imports.put(fqn.substring(fqn.lastIndexOf('.') + 1), fqn);
            } else if (im.isAsterisk() && !im.isStatic()) {
                wildcards.add(im.getNameAsString());
            }
        });
        String pkg = cu.getPackageDeclaration().map(pd -> pd.getNameAsString() + ".").orElse("");
        fileImports.put(rel, new Imports(pkg.isEmpty() ? "" : pkg.substring(0, pkg.length() - 1), imports, wildcards));
        for (TypeDeclaration<?> td : cu.findAll(TypeDeclaration.class)) {
            String simple = td.getNameAsString();
            knownTypes.add(simple);
            td.getFullyQualifiedName().ifPresent(sourceTypeFqns::add);
            if (td instanceof ClassOrInterfaceDeclaration c) {
                Map<String, String> sf = superFqns.computeIfAbsent(simple, k -> new HashMap<>());
                java.util.stream.Stream.concat(c.getExtendedTypes().stream(), c.getImplementedTypes().stream())
                        .forEach(t -> {
                            String s = t.getNameAsString();
                            String fqn = t.getScope().isPresent()
                                    ? t.getScope().get().asString() + "." + s   // written qualified in the code
                                    : imports.getOrDefault(s, pkg + s);         // imported, else same package
                            sf.put(s, fqn);
                            if (t.getScope().isPresent() || imports.containsKey(s)) {
                                explicitSupers.add(simple + "|" + s);
                            }
                        });
            }
            typeFiles.computeIfAbsent(simple, k -> new HashSet<>()).add(rel);
            Map<String, String> fields = fieldTypes.computeIfAbsent(simple, k -> new HashMap<>());
            td.getFields().forEach(fd -> fd.getVariables().forEach(
                    v -> fields.put(v.getNameAsString(), simpleTypeName(v.getType().asString()).replace("[]", ""))));
            Set<String> supers = supertypes.computeIfAbsent(simple, k -> new HashSet<>());
            if (td instanceof ClassOrInterfaceDeclaration c) {
                c.getExtendedTypes().forEach(t -> supers.add(t.getNameAsString()));
                c.getImplementedTypes().forEach(t -> supers.add(t.getNameAsString()));
            } else if (td instanceof EnumDeclaration e) {
                e.getImplementedTypes().forEach(t -> supers.add(t.getNameAsString()));
            } else if (td instanceof RecordDeclaration r) {
                r.getImplementedTypes().forEach(t -> supers.add(t.getNameAsString()));
            }
        }

        for (MethodDeclaration md : cu.findAll(MethodDeclaration.class)) {
            add(md, md.getNameAsString(), false, rel, harness);
        }
        for (ConstructorDeclaration cd : cu.findAll(ConstructorDeclaration.class)) {
            add(cd, cd.getNameAsString(), true, rel, harness);
        }
    }

    private void add(CallableDeclaration<?> decl, String name, boolean ctor, String rel, boolean harness) {
        String[] owner = owner(decl);
        List<String> params = new ArrayList<>();
        boolean varargs = false;
        for (Parameter p : decl.getParameters()) {
            String t = simpleTypeName(p.getType().asString());
            params.add(p.isVarArgs() ? t + "..." : t);
            varargs = p.isVarArgs();
        }
        // The line of the method name, not of a preceding annotation such as @Override.
        int line = decl.getName().getBegin().map(pos -> pos.line)
                .orElse(decl.getBegin().map(pos -> pos.line).orElse(-1));
        MethodInfo mi = new MethodInfo(owner[0], owner[1], outerTypes(decl, owner[1]), name, params, varargs,
                rel, line, ctor);
        setVisibility(decl, mi);
        mi.returnType = decl instanceof MethodDeclaration md
                ? simpleTypeName(md.getType().asString()).replace("[]", "")
                : owner[1];
        mi.isStatic = decl.isStatic();
        mi.typeParams = typeParameters(decl);
        collectFacts(decl, mi);
        mi.harness = harness;
        // JQF's @Fuzz, written with or without its package.
        mi.fuzzEntry = harness && decl.getAnnotations().stream().anyMatch(a -> a.getName().getIdentifier().equals("Fuzz"));
        byName.computeIfAbsent(name, k -> new ArrayList<>()).add(mi);
        byFile.computeIfAbsent(rel, k -> new ArrayList<>()).add(mi);
    }

    private static void setVisibility(CallableDeclaration<?> decl, MethodInfo mi) {
        boolean inInterface = decl.getParentNode().filter(p -> p instanceof ClassOrInterfaceDeclaration c
                && c.isInterface()).isPresent();
        if (decl.isPublic() || (inInterface && !decl.isPrivate())) {
            mi.visibility = "public";
        } else if (decl.isProtected()) {
            mi.visibility = "protected";
        } else if (decl.isPrivate()) {
            mi.visibility = "private";
        }
        boolean typesPublic = true;
        Node n = decl.getParentNode().orElse(null);
        while (n != null) {
            if (n instanceof ObjectCreationExpr) {
                typesPublic = false; // anonymous class
                break;
            }
            if (n instanceof TypeDeclaration<?> td) {
                boolean memberOfInterface = td.getParentNode().filter(p -> p instanceof ClassOrInterfaceDeclaration c
                        && c.isInterface()).isPresent();
                if (!td.isPublic() && !memberOfInterface) {
                    typesPublic = false;
                    break;
                }
            }
            n = n.getParentNode().orElse(null);
        }
        mi.publicApi = typesPublic && "public".equals(mi.visibility);
        mi.overrides = decl.isAnnotationPresent("Override");
    }

    /** Simple names of the type declarations enclosing the declaring type, innermost first. */
    private static List<String> outerTypes(Node decl, String own) {
        List<String> out = new ArrayList<>();
        Node n = decl.getParentNode().orElse(null);
        boolean skippedOwn = false;
        while (n != null) {
            if (n instanceof TypeDeclaration<?> td) {
                if (!skippedOwn && td.getNameAsString().equals(own)) {
                    skippedOwn = true;
                } else {
                    out.add(td.getNameAsString());
                }
            }
            n = n.getParentNode().orElse(null);
        }
        return out;
    }

    /** Returns {fully-qualified owner, simple owner}. Anonymous classes use the implemented type's name. */
    private static String[] owner(Node decl) {
        Node n = decl.getParentNode().orElse(null);
        while (n != null) {
            if (n instanceof ObjectCreationExpr oce) {
                String enclosing = n.findAncestor(TypeDeclaration.class)
                        .map(td -> ((TypeDeclaration<?>) td).getFullyQualifiedName().orElse(""))
                        .orElse("");
                String simple = oce.getType().getNameAsString();
                return new String[]{enclosing + "$anon(" + simple + ")", simple};
            }
            if (n instanceof TypeDeclaration<?> td) {
                return new String[]{td.getFullyQualifiedName().orElse(td.getNameAsString()), td.getNameAsString()};
            }
            n = n.getParentNode().orElse(null);
        }
        return new String[]{"?", "?"};
    }

    static String simpleTypeName(String type) {
        StringBuilder sb = new StringBuilder();
        int depth = 0;
        for (char c : type.toCharArray()) {
            if (c == '<') {
                depth++;
            } else if (c == '>') {
                depth--;
            } else if (depth == 0) {
                sb.append(c);
            }
        }
        String t = sb.toString().trim();
        return t.substring(t.lastIndexOf('.') + 1);
    }

    /** Names of the type parameters declared by the method and by its enclosing types. */
    private static Set<String> typeParameters(CallableDeclaration<?> decl) {
        Set<String> out = new HashSet<>();
        decl.getTypeParameters().forEach(tp -> out.add(tp.getNameAsString()));
        Node n = decl.getParentNode().orElse(null);
        while (n != null) {
            if (n instanceof ClassOrInterfaceDeclaration c) {
                c.getTypeParameters().forEach(tp -> out.add(tp.getNameAsString()));
            } else if (n instanceof RecordDeclaration r) {
                r.getTypeParameters().forEach(tp -> out.add(tp.getNameAsString()));
            } else if (n instanceof CallableDeclaration<?> outer) {
                outer.getTypeParameters().forEach(tp -> out.add(tp.getNameAsString()));
            }
            n = n.getParentNode().orElse(null);
        }
        return out.isEmpty() ? Set.of() : out;
    }

    private static void collectFacts(CallableDeclaration<?> decl, MethodInfo mi) {
        Map<String, String> varTypes = declaredTypes(decl);
        Map<String, String> qualified = qualifiedTypes(decl);

        for (MethodCallExpr mce : decl.findAll(MethodCallExpr.class)) {
            Expression scope = mce.getScope().orElse(null);
            String[] recv = receiver(scope, varTypes);
            CallSite cs = new CallSite(mce.getNameAsString(), mce.getArguments().size(), lineOf(mce), false,
                    Receiver.valueOf(recv[0]), recv[1]);
            // Only a variable or field can hold an object of a subtype; a class named for a static call,
            // `new T()` or a type parameter cannot be dispatched on.
            String var = scope == null ? null
                    : scope.isNameExpr() ? scope.asNameExpr().getNameAsString()
                    : scope.isFieldAccessExpr() && scope.asFieldAccessExpr().getScope().isThisExpr()
                    ? scope.asFieldAccessExpr().getNameAsString() : null;
            if (cs.receiver == Receiver.TYPED && var != null && varTypes.containsKey(var)
                    && !mi.typeParams.contains(cs.receiverType)) {
                cs.declaredReceiver = true;
                cs.receiverQualified = qualified.get(var);
            }
            mi.calls.add(cs);
        }
        for (ObjectCreationExpr oce : decl.findAll(ObjectCreationExpr.class)) {
            String type = oce.getType().getNameAsString();
            mi.calls.add(new CallSite(type, oce.getArguments().size(), lineOf(oce), true, Receiver.TYPED, type));
        }
        for (ExplicitConstructorInvocationStmt ecis : decl.findAll(ExplicitConstructorInvocationStmt.class)) {
            String target = ecis.isThis() ? mi.typeSimple : superOf(decl).orElse("super");
            mi.calls.add(new CallSite(target, ecis.getArguments().size(), lineOf(ecis), true, Receiver.TYPED, target));
        }
        for (MethodReferenceExpr mre : decl.findAll(MethodReferenceExpr.class)) {
            String id = mre.getIdentifier();
            String[] recv = receiver(mre.getScope(), varTypes);
            if ("new".equals(id)) {
                String type = simpleTypeName(mre.getScope().toString());
                mi.calls.add(new CallSite(type, -1, lineOf(mre), true, Receiver.TYPED, type));
            } else {
                mi.calls.add(new CallSite(id, -1, lineOf(mre), false, Receiver.valueOf(recv[0]), recv[1]));
            }
        }

        Set<String> locals = new HashSet<>();
        decl.findAll(VariableDeclarator.class).forEach(v -> locals.add(v.getNameAsString()));
        decl.findAll(Parameter.class).forEach(p -> locals.add(p.getNameAsString()));

        // Targets of plain `x = ...` are writes only; compound `x += ...` both reads and writes x.
        Set<Node> pureWrites = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        for (AssignExpr ae : decl.findAll(AssignExpr.class)) {
            fieldName(ae.getTarget(), locals).ifPresent(mi.fieldsWritten::add);
            if (ae.getOperator() == AssignExpr.Operator.ASSIGN) {
                pureWrites.add(ae.getTarget());
                if (ae.getTarget() instanceof FieldAccessExpr fae) {
                    pureWrites.add(fae.getName());
                }
            }
        }
        for (UnaryExpr ue : decl.findAll(UnaryExpr.class)) {
            if (ue.getOperator().isPostfix() || ue.getOperator() == UnaryExpr.Operator.PREFIX_INCREMENT
                    || ue.getOperator() == UnaryExpr.Operator.PREFIX_DECREMENT) {
                fieldName(ue.getExpression(), locals).ifPresent(mi.fieldsWritten::add);
            }
        }
        for (NameExpr ne : decl.findAll(NameExpr.class)) {
            if (!locals.contains(ne.getNameAsString()) && !pureWrites.contains(ne)) {
                mi.fieldsRead.add(ne.getNameAsString());
            }
        }
        // Only this.f is a field of the same object; current.f belongs to another object.
        for (FieldAccessExpr fae : decl.findAll(FieldAccessExpr.class)) {
            if (!pureWrites.contains(fae) && (fae.getScope().isThisExpr() || fae.getScope().isSuperExpr())) {
                mi.fieldsRead.add(fae.getNameAsString());
            }
        }
    }

    /** Declared simple types of the parameters, locals and enclosing-class fields visible in a method. */
    private static Map<String, String> declaredTypes(CallableDeclaration<?> decl) {
        Map<String, String> types = new HashMap<>();
        Node n = decl.getParentNode().orElse(null);
        List<TypeDeclaration<?>> enclosing = new ArrayList<>();
        while (n != null) {
            if (n instanceof TypeDeclaration<?> td) {
                enclosing.add(td);
            }
            n = n.getParentNode().orElse(null);
        }
        // Outer fields first so that inner declarations shadow them.
        for (int i = enclosing.size() - 1; i >= 0; i--) {
            enclosing.get(i).getFields().forEach(fd -> fd.getVariables()
                    .forEach(v -> putType(types, v.getNameAsString(), v.getType().asString())));
        }
        for (Parameter p : decl.findAll(Parameter.class)) {
            putType(types, p.getNameAsString(), p.getType().asString());
        }
        for (VariableDeclarator v : decl.findAll(VariableDeclarator.class)) {
            putType(types, v.getNameAsString(), v.getType().asString());
        }
        return types;
    }

    /** As declaredTypes, but only the declarations whose type is written qualified (java.io.InputStream in). */
    private static Map<String, String> qualifiedTypes(CallableDeclaration<?> decl) {
        Map<String, String> types = new HashMap<>();
        Node n = decl.getParentNode().orElse(null);
        List<TypeDeclaration<?>> enclosing = new ArrayList<>();
        while (n != null) {
            if (n instanceof TypeDeclaration<?> td) {
                enclosing.add(td);
            }
            n = n.getParentNode().orElse(null);
        }
        java.util.function.BiConsumer<String, String> put = (name, type) -> {
            String t = stripGenerics(type).replace("[]", "").replace("...", "").trim();
            if (t.contains(".")) {
                types.put(name, t);
            } else {
                types.remove(name);
            }
        };
        for (int i = enclosing.size() - 1; i >= 0; i--) {
            enclosing.get(i).getFields().forEach(fd -> fd.getVariables()
                    .forEach(v -> put.accept(v.getNameAsString(), v.getType().asString())));
        }
        for (Parameter p : decl.findAll(Parameter.class)) {
            put.accept(p.getNameAsString(), p.getType().asString());
        }
        for (VariableDeclarator v : decl.findAll(VariableDeclarator.class)) {
            put.accept(v.getNameAsString(), v.getType().asString());
        }
        return types;
    }

    private static String stripGenerics(String type) {
        StringBuilder sb = new StringBuilder();
        int depth = 0;
        for (char c : type.toCharArray()) {
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

    private static void putType(Map<String, String> types, String name, String type) {
        String simple = simpleTypeName(type).replace("[]", "").replace("...", "");
        if (!simple.isEmpty() && !simple.equals("var") && Character.isUpperCase(simple.charAt(0))) {
            types.put(name, simple);
        } else {
            types.remove(name); // primitives or `var`: no class to dispatch on
        }
    }

    /** Classifies a call's receiver expression; returns {Receiver name, receiver type or null}. */
    private static String[] receiver(Expression scope, Map<String, String> varTypes) {
        if (scope == null || scope.isThisExpr()) {
            return new String[]{Receiver.SELF.name(), null};
        }
        if (scope.isSuperExpr()) {
            return new String[]{Receiver.SUPER.name(), null};
        }
        if (scope.isNameExpr()) {
            String name = scope.asNameExpr().getNameAsString();
            String t = varTypes.get(name);
            if (t != null) {
                return new String[]{Receiver.TYPED.name(), t};
            }
            if (Character.isUpperCase(name.charAt(0))) {
                return new String[]{Receiver.TYPED.name(), name}; // static call Foo.bar()
            }
            return new String[]{Receiver.UNKNOWN.name(), null};
        }
        if (scope.isFieldAccessExpr() && scope.asFieldAccessExpr().getScope().isThisExpr()) {
            String t = varTypes.get(scope.asFieldAccessExpr().getNameAsString());
            if (t != null) {
                return new String[]{Receiver.TYPED.name(), t};
            }
        }
        if (scope.isObjectCreationExpr()) {
            return new String[]{Receiver.TYPED.name(), scope.asObjectCreationExpr().getType().getNameAsString()};
        }
        if (scope.isTypeExpr()) {
            return new String[]{Receiver.TYPED.name(), simpleTypeName(scope.toString())};
        }
        return new String[]{Receiver.UNKNOWN.name(), null};
    }

    private static Optional<String> superOf(Node decl) {
        return decl.findAncestor(ClassOrInterfaceDeclaration.class)
                .flatMap(c -> c.getExtendedTypes().getFirst())
                .map(ClassOrInterfaceType::getNameAsString);
    }

    private static Optional<String> fieldName(Expression target, Set<String> locals) {
        if (target instanceof FieldAccessExpr fae) {
            return fae.getScope().isThisExpr() || fae.getScope().isSuperExpr()
                    ? Optional.of(fae.getNameAsString()) : Optional.empty();
        }
        if (target instanceof NameExpr ne && !locals.contains(ne.getNameAsString())) {
            return Optional.of(ne.getNameAsString());
        }
        return Optional.empty();
    }

    private static int lineOf(Node n) {
        return n.getBegin().map(p -> p.line).orElse(-1);
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    List<MethodInfo> methodsNamed(String name) {
        return byName.getOrDefault(name, List.of());
    }

    List<MethodInfo> constructorsOf(String typeSimple) {
        List<MethodInfo> out = new ArrayList<>();
        for (MethodInfo mi : methodsNamed(typeSimple)) {
            if (mi.constructor) {
                out.add(mi);
            }
        }
        return out;
    }

    /** The type itself plus all declared ancestors and descendants (by simple name). */
    Set<String> typeFamily(String typeSimple) {
        Set<String> cached = familyCache.get(typeSimple);
        if (cached == null) {
            cached = computeFamily(typeSimple);
            familyCache.put(typeSimple, cached);
        }
        return cached;
    }

    /** The type itself plus its declared ancestors. */
    Set<String> ancestors(String typeSimple) {
        Set<String> out = new HashSet<>();
        out.add(typeSimple);
        Deque<String> up = new ArrayDeque<>(List.of(typeSimple));
        while (!up.isEmpty()) {
            for (String s : supertypes.getOrDefault(up.pop(), Set.of())) {
                if (out.add(s)) {
                    up.push(s);
                }
            }
        }
        return out;
    }

    private Set<String> computeFamily(String typeSimple) {
        Set<String> family = new HashSet<>();
        family.add(typeSimple);
        Deque<String> up = new ArrayDeque<>(List.of(typeSimple));
        while (!up.isEmpty()) {
            for (String s : supertypes.getOrDefault(up.pop(), Set.of())) {
                if (family.add(s)) {
                    up.push(s);
                }
            }
        }
        boolean changed = true;
        Set<String> down = new HashSet<>(List.of(typeSimple));
        while (changed) {
            changed = false;
            for (Map.Entry<String, Set<String>> e : supertypes.entrySet()) {
                if (!down.contains(e.getKey()) && !Collections.disjoint(e.getValue(), down)) {
                    down.add(e.getKey());
                    changed = true;
                }
            }
        }
        family.addAll(down);
        return family;
    }

    /**
     * In-source methods a call site may dispatch to: same name and compatible arity, restricted
     * by the receiver. A typed receiver dispatches within its type's hierarchy; {@code this}/no
     * receiver within the caller's (or an enclosing class's) hierarchy; an unknown receiver to any class.
     */
    List<MethodInfo> targetsOf(CallSite cs, MethodInfo caller) {
        List<MethodInfo> base = new ArrayList<>();
        for (MethodInfo mi : methodsNamed(cs.name)) {
            // The library never calls into the harness; only harness code does.
            if (mi.harness && !caller.harness) {
                continue;
            }
            if (mi.constructor == cs.constructor && mi.acceptsArity(cs.arity)) {
                base.add(mi);
            }
        }
        if (base.isEmpty() || cs.constructor) {
            return base;
        }
        Set<String> allowed;
        switch (cs.receiver) {
            case SELF -> {
                allowed = new HashSet<>(typeFamily(caller.typeSimple));
                for (String o : caller.outerTypes) {
                    allowed.addAll(typeFamily(o));
                }
            }
            case SUPER -> allowed = ancestors(caller.typeSimple);
            case TYPED -> allowed = typeFamily(cs.receiverType);
            default -> {
                return base;
            }
        }
        List<MethodInfo> out = new ArrayList<>();
        for (MethodInfo mi : base) {
            if (allowed.contains(mi.typeSimple)) {
                out.add(mi);
            }
        }
        if (out.isEmpty() && cs.receiver == Receiver.SELF) {
            return base; // statically imported method, or inherited from a class outside the source tree
        }
        return out;
    }

    /** Fields written by the given methods and by same-hierarchy methods they call, within {@code depth} calls. */
    Set<String> fieldsWrittenClosure(Collection<MethodInfo> start, int depth) {
        return fieldClosure(start, depth, true);
    }

    /** Fields read by the given methods and by same-hierarchy methods they call, within {@code depth} calls. */
    Set<String> fieldsReadClosure(Collection<MethodInfo> start, int depth) {
        return fieldClosure(start, depth, false);
    }

    private Set<String> fieldClosure(Collection<MethodInfo> start, int depth, boolean writes) {
        Set<String> fields = new HashSet<>();
        Set<MethodInfo> seen = Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        List<MethodInfo> frontier = new ArrayList<>(start);
        seen.addAll(start);
        for (int d = 0; d <= depth && !frontier.isEmpty(); d++) {
            List<MethodInfo> next = new ArrayList<>();
            for (MethodInfo m : frontier) {
                fields.addAll(writes ? m.fieldsWritten : m.fieldsRead);
                Set<String> family = typeFamily(m.typeSimple);
                for (CallSite cs : m.calls) {
                    if (cs.receiver != Receiver.SELF && cs.receiver != Receiver.SUPER
                            && !(cs.constructor && family.contains(cs.name))) {
                        continue; // only calls on the same object (including this(...)/super(...))
                    }
                    for (MethodInfo t : targetsOf(cs, m)) {
                        if (family.contains(t.typeSimple) && seen.add(t)) {
                            next.add(t);
                        }
                    }
                }
            }
            frontier = next;
        }
        return fields;
    }

    Collection<String> allMethodNames() {
        return byName.keySet();
    }

    /**
     * True if {@code typeSimple} has an ancestor named {@code name} that is declared outside the source
     * tree, even when a different source type shares that simple name.
     */
    boolean externalAncestorNamed(String typeSimple, String name) {
        Deque<String> todo = new ArrayDeque<>(List.of(typeSimple));
        Set<String> seen = new HashSet<>();
        while (!todo.isEmpty()) {
            String t = todo.pop();
            if (!seen.add(t)) {
                continue;
            }
            Map<String, String> sf = superFqns.getOrDefault(t, Map.of());
            String fqn = sf.get(name);
            if (fqn != null && !sourceTypeFqns.contains(fqn)) {
                return true;
            }
            for (Map.Entry<String, String> e : sf.entrySet()) {
                if (sourceTypeFqns.contains(e.getValue())) {
                    todo.push(e.getKey());
                }
            }
        }
        return false;
    }

    /** Declared type of field {@code name} in {@code typeSimple} or one of its in-source ancestors. */
    Optional<String> fieldType(String typeSimple, String name) {
        for (String t : ancestors(typeSimple)) {
            String ft = fieldTypes.getOrDefault(t, Map.of()).get(name);
            if (ft != null) {
                return Optional.of(ft);
            }
        }
        return Optional.empty();
    }

    /** Methods anywhere in the source tree that have a call site dispatching to one of {@code targets}. */
    List<Map.Entry<MethodInfo, CallSite>> callersOf(Collection<MethodInfo> targets) {
        return callersOf(targets, false);
    }

    /** As above; with {@code preciseOnly}, call sites on a receiver of unknown type are ignored. */
    List<Map.Entry<MethodInfo, CallSite>> callersOf(Collection<MethodInfo> targets, boolean preciseOnly) {
        Set<String> names = new HashSet<>();
        targets.forEach(t -> names.add(t.name));
        Set<MethodInfo> tset = Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        tset.addAll(targets);
        List<Map.Entry<MethodInfo, CallSite>> out = new ArrayList<>();
        for (List<MethodInfo> ms : byName.values()) {
            for (MethodInfo m : ms) {
                for (CallSite cs : m.calls) {
                    if (!names.contains(cs.name) || (preciseOnly && cs.receiver == Receiver.UNKNOWN)) {
                        continue;
                    }
                    for (MethodInfo t : targetsOf(cs, m)) {
                        if (tset.contains(t)) {
                            out.add(Map.entry(m, cs));
                            break;
                        }
                    }
                }
            }
        }
        return out;
    }

    /**
     * Resolves the declaring type of a call site with the symbol solver.
     *
     * @return the qualified name of the callee's declaring type, or empty if the
     *         call cannot be resolved (e.g. it depends on a library that is not on the type path)
     */
    Optional<String> resolveCallee(MethodInfo caller, CallSite cs) {
        CompilationUnit cu = resolvingUnit(caller.file);
        if (cu == null) {
            return Optional.empty();
        }
        try {
            if (cs.constructor) {
                for (ObjectCreationExpr oce : cu.findAll(ObjectCreationExpr.class)) {
                    if (lineOf(oce) == cs.line && oce.getType().getNameAsString().equals(cs.name)) {
                        return Optional.of(oce.resolve().declaringType().getQualifiedName());
                    }
                }
                return Optional.empty();
            }
            for (MethodCallExpr mce : cu.findAll(MethodCallExpr.class)) {
                if (lineOf(mce) == cs.line && mce.getNameAsString().equals(cs.name)
                        && mce.getArguments().size() == cs.arity) {
                    return Optional.of(mce.resolve().declaringType().getQualifiedName());
                }
            }
        } catch (RuntimeException | StackOverflowError e) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    /** The file parsed with the symbol solver attached, or null if it cannot be parsed. */
    private CompilationUnit resolvingUnit(String rel) {
        CompilationUnit cu = cuCache.get(rel);
        if (cu == null) {
            try {
                Path file = harnessFiles.containsKey(rel) ? harnessFiles.get(rel) : root.resolve(rel);
                cu = resolvingParser.parse(file).getResult().orElse(null);
            } catch (IOException | RuntimeException | StackOverflowError e) {
                cu = null;
            }
            if (cu != null) {
                cuCache.put(rel, cu);
            }
        }
        return cu;
    }

    /**
     * Resolves a method call with the symbol solver: the called method's declaring type and erased parameter
     * types, and the receiver's static type. Empty if it cannot be resolved (e.g. a dependency type).
     */
    Optional<ResolvedCall> resolveCall(MethodInfo caller, CallSite cs) {
        if (cs.constructor || cs.arity < 0) {
            return Optional.empty();
        }
        CompilationUnit cu = resolvingUnit(caller.file);
        if (cu == null) {
            return Optional.empty();
        }
        try {
            for (MethodCallExpr mce : cu.findAll(MethodCallExpr.class)) {
                if (lineOf(mce) != cs.line || !mce.getNameAsString().equals(cs.name)
                        || mce.getArguments().size() != cs.arity) {
                    continue;
                }
                ResolvedMethodDeclaration d = mce.resolve();
                String recv = null;
                try {
                    if (mce.getScope().isPresent()) {
                        ResolvedType rt = mce.getScope().get().calculateResolvedType();
                        if (rt.isReferenceType()) {
                            recv = rt.asReferenceType().getQualifiedName();
                        }
                    }
                } catch (RuntimeException | StackOverflowError e) {
                    recv = null;
                }
                List<String> erasures = new ArrayList<>();
                List<Boolean> typeVars = new ArrayList<>();
                for (int i = 0; i < d.getNumberOfParams(); i++) {
                    ResolvedType pt = d.getParam(i).getType();
                    ResolvedType base = pt.isArray() ? pt.asArrayType().getComponentType() : pt;
                    typeVars.add(base.isTypeVariable());
                    erasures.add(simpleTypeName(pt.erasure().describe()));
                }
                return Optional.of(new ResolvedCall(d.declaringType().getQualifiedName(), recv, erasures, typeVars,
                        d.isStatic()));
            }
        } catch (RuntimeException | StackOverflowError e) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    // ------------------------------------------------------------------
    // Dispatch on receivers typed outside the source tree
    // ------------------------------------------------------------------

    /** Methods every object has; a call to one of them says nothing about the receiver's class. */
    private static final Set<String> OBJECT_METHODS = Set.of(
            "toString", "hashCode", "equals", "getClass", "clone", "finalize", "notify", "notifyAll", "wait");

    /** True if the call is made on a variable or field whose declared type is outside the source tree. */
    boolean externalReceiver(CallSite cs) {
        return !cs.constructor && cs.receiver == Receiver.TYPED && cs.declaredReceiver && cs.receiverType != null
                && !knownTypes.contains(cs.receiverType) && !OBJECT_METHODS.contains(cs.name);
    }

    /**
     * Loads a class outside the source tree through the platform class loader, which sees the JDK but not
     * the project's dependencies (they are not on CheckPath's class path). Nested classes may be written
     * with dots (java.util.Map.Entry).
     */
    Optional<Class<?>> loadClass(String name) {
        if (name == null || name.isEmpty() || sourceTypeFqns.contains(name)) {
            return Optional.empty();
        }
        return classCache.computeIfAbsent(name, n -> {
            String candidate = n;
            for (int i = 0; i < 3 && candidate != null; i++) {
                try {
                    return Optional.of(Class.forName(candidate, false, ClassLoader.getPlatformClassLoader()));
                } catch (ClassNotFoundException | LinkageError e) {
                    int dot = candidate.lastIndexOf('.');
                    candidate = dot < 0 ? null : candidate.substring(0, dot) + "$" + candidate.substring(dot + 1);
                }
            }
            return Optional.empty();
        });
    }

    /**
     * The type outside the source tree that {@code simple} names in {@code file}: the import or qualified name
     * when there is one (loaded if it is a JDK class), else a JDK class in java.lang or a wildcard-imported
     * package. A type that cannot be named this way keeps its simple name and is not loaded.
     */
    ExternalType externalType(String file, String simple, String qualified) {
        if (qualified != null) {
            String q = qualified;
            if (Character.isUpperCase(q.charAt(0))) {
                // Outer.Inner: Outer is imported or in java.lang.
                String outer = q.substring(0, q.indexOf('.'));
                ExternalType o = externalType(file, outer, null);
                q = (o.loaded() != null ? o.loaded().getName() : o.name()) + q.substring(q.indexOf('.'));
            }
            return new ExternalType(q, loadClass(q).orElse(null));
        }
        Imports im = fileImports.get(file);
        String fqn = im == null ? null : im.explicit().get(simple);
        if (fqn != null) {
            return new ExternalType(fqn, loadClass(fqn).orElse(null));
        }
        List<String> pkgs = new ArrayList<>(List.of("java.lang"));
        if (im != null) {
            pkgs.addAll(im.wildcards());
        }
        for (String p : pkgs) {
            Optional<Class<?>> c = loadClass(p + "." + simple);
            if (c.isPresent()) {
                return new ExternalType(c.get().getName(), c.get());
            }
        }
        return new ExternalType(simple, null);
    }

    /**
     * The supertypes outside the source tree that the declaring type of {@code m} reaches through its in-tree
     * supertypes (for an anonymous class of an external type, that type itself). A JDK supertype is loaded;
     * a dependency supertype is not, since dependencies are not on CheckPath's class path.
     */
    List<ExternalAncestor> externalAncestors(MethodInfo m) {
        if (!knownTypes.contains(m.typeSimple)) {
            if (!m.typeFqn.contains("$anon(")) {
                return List.of();
            }
            ExternalType t = externalType(m.file, m.typeSimple, null);
            return List.of(new ExternalAncestor(t.name(), t.loaded()));
        }
        return externalAncestorCache.computeIfAbsent(m.typeSimple, this::computeExternalAncestors);
    }

    private List<ExternalAncestor> computeExternalAncestors(String typeSimple) {
        Map<String, ExternalAncestor> out = new LinkedHashMap<>();
        Deque<String> todo = new ArrayDeque<>(List.of(typeSimple));
        Set<String> seen = new HashSet<>();
        while (!todo.isEmpty()) {
            String t = todo.pop();
            if (!seen.add(t)) {
                continue;
            }
            Map<String, String> fqns = superFqns.getOrDefault(t, Map.of());
            for (String s : supertypes.getOrDefault(t, Set.of())) {
                String fqn = fqns.get(s);
                boolean explicit = explicitSupers.contains(t + "|" + s);
                // An in-tree name that the declaration imports from elsewhere is external.
                if (knownTypes.contains(s) && !(explicit && fqn != null && !sourceTypeFqns.contains(fqn))) {
                    todo.push(s);
                    continue;
                }
                ExternalType et = null;
                if (explicit && fqn != null) {
                    et = new ExternalType(fqn, loadClass(fqn).orElse(null));
                } else {
                    for (String file : typeFiles.getOrDefault(t, Set.of())) {
                        ExternalType c = externalType(file, s, null);
                        if (et == null || (et.loaded() == null && c.loaded() != null)) {
                            et = c;
                        }
                    }
                }
                if (et == null) {
                    et = new ExternalType(s, null);
                }
                out.putIfAbsent(et.name(), new ExternalAncestor(et.name(), et.loaded()));
            }
        }
        return List.copyOf(out.values());
    }

    /**
     * In-tree methods that a call on a receiver typed outside the source tree may reach by dynamic dispatch
     * (see {@link #dispatch}). Parameter types are compared with the receiver type's overloads of the same
     * arity, since the argument types are not resolved here.
     */
    List<MethodInfo> dispatchTargetsOf(CallSite cs, MethodInfo caller) {
        if (!externalReceiver(cs)) {
            return List.of();
        }
        ExternalType recv = externalType(caller.file, cs.receiverType, cs.receiverQualified);
        String key = recv.name() + "#" + cs.name + "/" + cs.arity + (caller.harness ? "/h" : "");
        List<Dispatch> ds = dispatchCache.computeIfAbsent(key, k -> {
            List<Dispatch> out = new ArrayList<>();
            for (MethodInfo t : methodsNamed(cs.name)) {
                dispatch(cs, caller, t, null).ifPresent(out::add);
            }
            return out;
        });
        List<MethodInfo> out = new ArrayList<>(ds.size());
        ds.forEach(d -> out.add(d.target()));
        return out;
    }

    /**
     * Whether the call {@code cs} in {@code caller}, made on a variable or field whose declared type R is
     * outside the source tree, can run the in-tree method {@code t} by dynamic dispatch. {@code t} must have
     * the call's name and arity and be able to override (not static, private or a constructor). Then:
     * <ul>
     * <li>If R is a JDK class, R must declare an overridable method of that name whose parameter types t
     *     repeats (the overload the symbol solver resolved, when {@code rc} is given), and the dispatch is
     *     confirmed if some external supertype of t's class is a JDK class assignable to R.</li>
     * <li>Otherwise, if some external supertype of t's class cannot be loaded (a dependency), it may be a
     *     subtype of R. The dispatch is then accepted unconfirmed if t overrides a method declared outside
     *     the source tree: it carries {@code @Override}, or no in-tree supertype declares it.</li>
     * </ul>
     * A dependency receiver type cannot be a supertype of a JDK class, so it needs an unloaded supertype too.
     */
    Optional<Dispatch> dispatch(CallSite cs, MethodInfo caller, MethodInfo t, ResolvedCall rc) {
        if (!externalReceiver(cs) || !t.name.equals(cs.name) || t.constructor || t.isStatic
                || "private".equals(t.visibility) || "package".equals(t.visibility)
                || !t.acceptsArity(cs.arity) || (t.harness && !caller.harness)) {
            return Optional.empty();
        }
        if (rc != null && (rc.isStatic() || sourceTypeFqns.contains(rc.declaringType()))) {
            return Optional.empty();
        }
        ExternalType recv = rc != null && rc.receiverType() != null && !sourceTypeFqns.contains(rc.receiverType())
                ? new ExternalType(rc.receiverType(), loadClass(rc.receiverType()).orElse(null))
                : externalType(caller.file, cs.receiverType, cs.receiverQualified);
        if (recv.loaded() == Object.class) {
            return Optional.empty();
        }
        List<ExternalAncestor> ext = externalAncestors(t);
        if (ext.isEmpty()) {
            return Optional.empty();
        }
        String overridden = null;
        if (recv.loaded() != null) {
            Optional<java.lang.reflect.Method> m = overridable(recv.loaded(), cs.arity, t, rc);
            if (m.isEmpty()) {
                return Optional.empty();
            }
            overridden = m.get().getDeclaringClass().getName() + "#" + m.get().getName() + "("
                    + String.join(",", java.util.Arrays.stream(m.get().getParameterTypes())
                    .map(Class::getSimpleName).toList()) + ")";
            for (ExternalAncestor a : ext) {
                if (a.loaded() != null && recv.loaded().isAssignableFrom(a.loaded())) {
                    return Optional.of(new Dispatch(t, recv, overridden, a.name(), List.of()));
                }
            }
        }
        List<String> unresolved = ext.stream().filter(a -> a.loaded() == null).map(ExternalAncestor::name).toList();
        if (unresolved.isEmpty() || !overridesExternally(t)) {
            return Optional.empty();
        }
        return Optional.of(new Dispatch(t, recv, overridden, null, unresolved));
    }

    /**
     * The method of {@code r} (declared or inherited) that {@code t} would override: same name, a parameter
     * count matching the call, not static, final or private, at least as visible as t allows, and the
     * same erased parameter types as t (a type variable matches any type). With {@code rc}, only the
     * overload the call was resolved to.
     */
    private static Optional<java.lang.reflect.Method> overridable(Class<?> r, int arity, MethodInfo t, ResolvedCall rc) {
        if (java.lang.reflect.Modifier.isFinal(r.getModifiers())) {
            return Optional.empty(); // String, StringBuilder: no subclass exists
        }
        if (rc != null && !paramsMatch(rc.paramErasures(), rc.paramTypeVars(), t)) {
            return Optional.empty(); // the call resolves to another overload
        }
        Deque<Class<?>> todo = new ArrayDeque<>(List.of(r));
        Set<Class<?>> seen = new HashSet<>();
        while (!todo.isEmpty()) {
            Class<?> k = todo.pop();
            if (!seen.add(k)) {
                continue;
            }
            java.lang.reflect.Method[] declared;
            try {
                declared = k.getDeclaredMethods();
            } catch (LinkageError | SecurityException e) {
                continue;
            }
            for (java.lang.reflect.Method m : declared) {
                int mod = m.getModifiers();
                if (!m.getName().equals(t.name) || m.isBridge() || m.isSynthetic()
                        || java.lang.reflect.Modifier.isStatic(mod) || java.lang.reflect.Modifier.isFinal(mod)
                        || java.lang.reflect.Modifier.isPrivate(mod)
                        || !(java.lang.reflect.Modifier.isPublic(mod) || java.lang.reflect.Modifier.isProtected(mod))
                        || (java.lang.reflect.Modifier.isPublic(mod) && !"public".equals(t.visibility))) {
                    continue;
                }
                int n = m.getParameterCount();
                if (n != t.arity() || (arity >= 0 && arity != n && !(m.isVarArgs() && arity >= n - 1))) {
                    continue;
                }
                List<String> erasures = new ArrayList<>();
                List<Boolean> typeVars = new ArrayList<>();
                try {
                    java.lang.reflect.Type[] generic = m.getGenericParameterTypes();
                    for (int i = 0; i < n; i++) {
                        java.lang.reflect.Type g = generic.length == n ? generic[i] : m.getParameterTypes()[i];
                        if (g instanceof java.lang.reflect.GenericArrayType ga) {
                            g = ga.getGenericComponentType();
                        }
                        typeVars.add(g instanceof java.lang.reflect.TypeVariable<?>);
                        erasures.add(m.getParameterTypes()[i].getSimpleName());
                    }
                } catch (RuntimeException | LinkageError e) {
                    continue;
                }
                if (rc != null && !erasures.equals(rc.paramErasures())) {
                    continue;
                }
                if (paramsMatch(erasures, typeVars, t)) {
                    return Optional.of(m);
                }
            }
            if (k.getSuperclass() != null) {
                todo.push(k.getSuperclass());
            }
            todo.addAll(List.of(k.getInterfaces()));
        }
        return Optional.empty();
    }

    /** True if t's declared parameter types are the given erased types (a type variable on either side matches). */
    private static boolean paramsMatch(List<String> erasures, List<Boolean> typeVars, MethodInfo t) {
        if (erasures.size() != t.paramTypes.size()) {
            return false;
        }
        for (int i = 0; i < erasures.size(); i++) {
            String p = t.paramTypes.get(i).replace("...", "[]");
            String base = p.replace("[]", "");
            if (typeVars.get(i) || t.typeParams.contains(base)) {
                continue;
            }
            if (!p.equals(erasures.get(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * True if t can override a method declared outside the source tree: it carries @Override, or no in-tree
     * supertype of its class declares a method of the same name and arity (so it does not merely override
     * an in-tree one, nor is it hidden behind one).
     */
    private boolean overridesExternally(MethodInfo t) {
        if (t.overrides) {
            return true;
        }
        Set<String> supers = new HashSet<>(ancestors(t.typeSimple));
        supers.remove(t.typeSimple);
        supers.retainAll(knownTypes);
        for (MethodInfo m : methodsNamed(t.name)) {
            if (!m.constructor && m.arity() == t.arity() && supers.contains(m.typeSimple)) {
                return false;
            }
        }
        return true;
    }
}
