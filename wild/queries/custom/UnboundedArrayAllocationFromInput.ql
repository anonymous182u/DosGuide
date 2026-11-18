/**
 * @name Array/collection allocated from an unvalidated input-declared size (OOM)
 * @description A size/length value read from an untrusted binary stream or buffer
 *              (e.g. DataInput.readInt, ByteBuffer.getInt) flows into an array creation
 *              dimension or a pre-sized collection with no upper-bound check. A tiny
 *              crafted header (declared count) forces a huge allocation -> OutOfMemoryError
 *              or NegativeArraySizeException.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id java/unbounded-alloc-from-input
 * @tags security external/cwe/cwe-789 external/cwe/cwe-400
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.controlflow.Guards
import AllocFlow::PathGraph

predicate inputLengthRead(MethodCall ma) {
  exists(Method m | m = ma.getMethod() |
    (
      m.getDeclaringType().getASupertype*().hasQualifiedName("java.io", "DataInput") and
      m.hasName(["readInt", "readShort", "readUnsignedShort", "readLong", "readUnsignedByte"])
    )
    or
    (
      m.getDeclaringType().hasQualifiedName("java.nio", "ByteBuffer") and
      m.hasName(["getInt", "getShort", "getLong"])
    )
    or
    (
      m.getReturnType() instanceof IntegralType and
      m.getNumberOfParameters() <= 1 and
      m.getName()
          .regexpMatch("(?i)read(unsigned|u)?(int|long|short|var(unsigned|u)?int|length|len|size|count).*")
    )
  )
}

predicate sizedAllocation(Expr sizeArg) {
  exists(ArrayCreationExpr ace | sizeArg = ace.getADimension())
  or
  exists(ClassInstanceExpr cie |
    cie.getConstructedType()
        .getSourceDeclaration()
        .getASupertype*()
        .hasQualifiedName("java.util", ["ArrayList", "HashMap", "HashSet", "Vector"]) and
    sizeArg = cie.getArgument(0) and
    sizeArg.getType() instanceof IntegralType
  )
  or
  exists(MethodCall ma |
    ma.getMethod().hasName("allocate") and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.nio", ["ByteBuffer", "CharBuffer"]) and
    sizeArg = ma.getArgument(0)
  )
}

module AllocConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { inputLengthRead(src.asExpr()) }

  predicate isSink(DataFlow::Node sink) { sizedAllocation(sink.asExpr()) }

  predicate isBarrier(DataFlow::Node node) {
    exists(Guard g, Expr checked |
      g.controls(node.asExpr().getBasicBlock(), _) and
      g.(ComparisonExpr).getAnOperand() = checked and
      node.asExpr() = checked
    )
  }
}

module AllocFlow = TaintTracking::Global<AllocConfig>;

from AllocFlow::PathNode source, AllocFlow::PathNode sink
where
  AllocFlow::flowPath(source, sink) and
  not sink.getNode().getLocation().getFile().getRelativePath()
      .regexpMatch("(?i).*/(test|tests|benchmark|benchmarks|jmh|example|examples|sample|samples|demo|demos|mock|mocks|fixture|fixtures|generated|gen)/.*")
select sink.getNode(), source, sink,
  "Allocation size flows from an input-declared length read at $@ with no bound check; a crafted header can force a huge allocation (OOM).",
  source.getNode(), "this read"
