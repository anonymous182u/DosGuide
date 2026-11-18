/**
 * @name Unconditional loop with no exit (CWE-835)
 * @description An unconditional loop (`while(true)` / `for(;;)`) whose body contains no
 *              break/return/throw/yield that could ever exit it — a guaranteed
 *              non-terminating loop. If it is reachable on an untrusted-input path (e.g. a
 *              request handler that never returns), the thread spins forever (DoS).
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.9
 * @precision low
 * @id java/infinite-loop
 * @tags security external/cwe/cwe-835 external/cwe/cwe-400
 */

import java

predicate hasExit(LoopStmt loop) {
  exists(Stmt s |
    s.getParent+() = loop and
    (
      s instanceof BreakStmt or
      s instanceof ReturnStmt or
      s instanceof ThrowStmt or
      s instanceof YieldStmt
    )
  )
}

predicate unconditional(LoopStmt loop) {
  loop.(WhileStmt).getCondition().(CompileTimeConstantExpr).getBooleanValue() = true
  or
  loop.(DoStmt).getCondition().(CompileTimeConstantExpr).getBooleanValue() = true
  or
  (loop instanceof ForStmt and not exists(loop.(ForStmt).getCondition()))
  or
  loop.(ForStmt).getCondition().(CompileTimeConstantExpr).getBooleanValue() = true
}

from LoopStmt loop
where
  loop.getCompilationUnit().fromSource() and
  not loop.getFile().getRelativePath().matches("%/test/%") and
  unconditional(loop) and
  not hasExit(loop)
select loop,
  "Unconditional loop (while(true)/for(;;)) with no break/return/throw/yield that can exit it; if reachable from untrusted input the thread never terminates."
