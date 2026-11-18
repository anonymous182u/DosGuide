/**
 * @name Self-recursive method without a monotonic depth bound (StackOverflow DoS)
 * @description A method that calls itself where no recursive call passes a bounded,
 *              monotonically changing integer (a depth counter or a shrinking size) that
 *              is compared in the method. Such recursion descends once per level of a
 *              structure in its input; deeply nested untrusted input drives the recursion
 *              to the input's nesting depth and overflows the JVM stack with an uncaught
 *              StackOverflowError (CWE-674 / CWE-400).
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision low
 * @id java/uncontrolled-recursion
 * @tags security external/cwe/cwe-674 external/cwe/cwe-400
 */

import java

predicate selfRecursiveCall(Callable c, Call call) {
  call.getCallee().getSourceDeclaration() = c.getSourceDeclaration() and
  call.getEnclosingCallable().getSourceDeclaration() = c.getSourceDeclaration()
}

predicate hasMonotonicBound(Callable c) {
  exists(Parameter p, Call call, Expr arg |
    p.getCallable().getSourceDeclaration() = c.getSourceDeclaration() and
    p.getType() instanceof IntegralType and
    selfRecursiveCall(c, call) and
    arg = call.getAnArgument() and
    arg.getAChildExpr*() = p.getAnAccess() and
    (
      arg instanceof AddExpr or arg instanceof SubExpr or
      arg instanceof PreIncExpr or arg instanceof PostIncExpr or
      arg instanceof PreDecExpr or arg instanceof PostDecExpr
    ) and
    exists(ComparisonExpr ce |
      ce.getEnclosingCallable().getSourceDeclaration() = c.getSourceDeclaration() and
      ce.getAnOperand() = p.getAnAccess()
    )
  )
}

from Callable c, Call call
where
  selfRecursiveCall(c, call) and
  not hasMonotonicBound(c) and
  c.fromSource() and
  not c.getFile().getRelativePath().matches("%/test/%") and
  not c.getName().regexpMatch("(?i)(equals|hashcode|tostring|compareto|clone)")
select call,
  "Method '" + c.getName() +
    "' recurses into itself with no monotonic depth/size bound; deeply nested input can overflow the stack (StackOverflowError)."
