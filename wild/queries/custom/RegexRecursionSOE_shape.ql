/**
 * @name Regex constant with a repeatable group (StackOverflow-prone) — shape only
 * @description High-recall companion to java/regex-recursion-soe: flags every
 *              java.util.regex entrypoint whose pattern is a compile-time constant
 *              containing a group closed then quantified (`)*`, `)+`, `){n,}`), WITHOUT
 *              requiring a proven taint path.
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 7.5
 * @precision low
 * @id java/regex-recursion-soe-shape
 * @tags security external/cwe/cwe-674 external/cwe/cwe-400
 */

import java

bindingset[re]
predicate dangerousRegexText(string re) {
  re.regexpMatch("(?s).*\\)\\s*[*+].*") or
  re.regexpMatch("(?s).*\\)\\s*\\{[0-9]+,[0-9]*\\}.*")
}

predicate regexEntrypoint(MethodCall ma, string re) {
  exists(Method m | m = ma.getMethod() |
    (
      m.getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
      m.hasName(["compile", "matches"])
      or
      m.getDeclaringType() instanceof TypeString and
      m.hasName(["matches", "replaceAll", "replaceFirst", "split"])
    ) and
    re = ma.getArgument(0).(CompileTimeConstantExpr).getStringValue()
  )
}

from MethodCall ma, string re
where
  regexEntrypoint(ma, re) and dangerousRegexText(re) and
  not ma.getFile().getRelativePath()
      .regexpMatch("(?i).*/(test|tests|benchmark|benchmarks|jmh|example|examples|sample|samples|demo|demos|mock|mocks|fixture|fixtures|generated|gen)/.*")
select ma,
  "Regex constant with a repeatable group can recurse to the input length and overflow the stack: " + re
