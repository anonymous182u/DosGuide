/**
 * @name Regex with repeatable group matched against untrusted input (StackOverflow DoS)
 * @description java.util.regex recurses roughly once per repetition of a quantified
 *              group `(...)*`, `(...)+`, `(...){n,}`. A long untrusted input drives the
 *              recursion depth to the input length and overflows the JVM stack with an
 *              uncaught StackOverflowError.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id java/regex-recursion-soe
 * @tags security external/cwe/cwe-674 external/cwe/cwe-400
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import RegexFlow::PathGraph

bindingset[re]
predicate dangerousRegexText(string re) {
  re.regexpMatch("(?s).*\\)\\s*[*+].*") or
  re.regexpMatch("(?s).*\\)\\s*\\{[0-9]+,[0-9]*\\}.*")
}

class RegexPatternArg extends Expr {
  RegexPatternArg() {
    exists(MethodCall ma, Method m | ma.getMethod() = m |
      (
        m.getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
        m.hasName(["compile", "matches"]) and this = ma.getArgument(0)
      )
      or
      m.getDeclaringType() instanceof TypeString and
      m.hasName(["matches", "replaceAll", "replaceFirst", "split"]) and
      this = ma.getArgument(0)
    )
  }
}

predicate dangerousRegexSubject(Expr subject) {
  exists(MethodCall ma, Method m | ma.getMethod() = m |
    m.getDeclaringType() instanceof TypeString and
    m.hasName(["matches", "replaceAll", "replaceFirst"]) and
    dangerousRegexText(ma.getArgument(0).(CompileTimeConstantExpr).getStringValue()) and
    subject = ma.getQualifier()
  )
  or
  exists(MethodCall ma, Method m | ma.getMethod() = m |
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
    m.hasName("matches") and
    dangerousRegexText(ma.getArgument(0).(CompileTimeConstantExpr).getStringValue()) and
    subject = ma.getArgument(1)
  )
  or
  exists(MethodCall compile, Method cm, Variable pat, MethodCall matcher |
    compile.getMethod() = cm and
    cm.getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
    cm.hasName("compile") and
    dangerousRegexText(compile.getArgument(0).(CompileTimeConstantExpr).getStringValue()) and
    pat.getAnAssignedValue() = compile and
    matcher.getQualifier() = pat.getAnAccess() and
    matcher.getMethod().hasName("matcher") and
    subject = matcher.getArgument(0)
  )
}

module RegexConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    src instanceof RemoteFlowSource
    or
    exists(Parameter p |
      src.asParameter() = p and
      p.getCallable().isPublic() and
      p.getType() instanceof TypeString
    )
  }

  predicate isSink(DataFlow::Node sink) { dangerousRegexSubject(sink.asExpr()) }
}

module RegexFlow = TaintTracking::Global<RegexConfig>;

from RegexFlow::PathNode source, RegexFlow::PathNode sink
where
  RegexFlow::flowPath(source, sink) and
  not sink.getNode().getLocation().getFile().getRelativePath()
      .regexpMatch("(?i).*/(test|tests|benchmark|benchmarks|jmh|example|examples|sample|samples|demo|demos|mock|mocks|fixture|fixtures|generated|gen)/.*")
select sink.getNode(), source, sink,
  "Untrusted value from $@ is matched against a regex with a repeatable group; a long input can overflow the stack (StackOverflowError).",
  source.getNode(), "this source"
