/**
 * @name Untrusted string parsed into BigDecimal/BigInteger (CPU/memory DoS)
 * @description An untrusted string reaches `new BigDecimal(String)` or
 *              `new BigInteger(String)`, or a tainted exponent reaches BigDecimal.pow /
 *              scaleByPowerOfTen / movePointRight. A literal like "1e+99999" forces a
 *              huge coefficient allocation, and large exponents blow up CPU/heap.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id java/bignumber-abuse-from-input
 * @tags security external/cwe/cwe-400
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import BigNumFlow::PathGraph

predicate bigNumberStringSink(Expr arg) {
  exists(ClassInstanceExpr cie |
    cie.getConstructedType().hasQualifiedName("java.math", ["BigDecimal", "BigInteger"]) and
    arg = cie.getArgument(0) and
    arg.getType() instanceof TypeString
  )
}

predicate bigNumberExponentSink(Expr arg) {
  exists(MethodCall ma |
    ma.getMethod().getDeclaringType().hasQualifiedName("java.math", "BigDecimal") and
    ma.getMethod().hasName(["pow", "scaleByPowerOfTen", "movePointRight", "movePointLeft"]) and
    arg = ma.getArgument(0)
  )
}

module BigNumConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    src instanceof RemoteFlowSource
    or
    exists(Parameter p |
      src.asParameter() = p and
      p.getCallable().isPublic() and
      (p.getType() instanceof TypeString or p.getType() instanceof IntegralType)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    bigNumberStringSink(sink.asExpr()) or bigNumberExponentSink(sink.asExpr())
  }
}

module BigNumFlow = TaintTracking::Global<BigNumConfig>;

from BigNumFlow::PathNode source, BigNumFlow::PathNode sink
where
  BigNumFlow::flowPath(source, sink) and
  not sink.getNode().getLocation().getFile().getRelativePath()
      .regexpMatch("(?i).*/(test|tests|benchmark|benchmarks|jmh|example|examples|sample|samples|demo|demos|mock|mocks|fixture|fixtures|generated|gen)/.*")
select sink.getNode(), source, sink,
  "Untrusted value from $@ reaches a BigDecimal/BigInteger construction or exponent; a crafted numeric literal can exhaust CPU/heap.",
  source.getNode(), "this source"
