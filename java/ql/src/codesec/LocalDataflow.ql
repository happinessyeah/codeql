/**
 * @name Cross-site scripting
 * @description Writing user input directly to a web page
 *              allows for a cross-site scripting vulnerability.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/local
 * @tags security
 *       external/cwe/cwe-079/local
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.XSS
import DataFlow::PathGraph

from MethodAccess call, Expr expr, DataFlow::Node source, DataFlow::Node sink
where
  validMethod(call) and
  call.getArgument(0).getType() = expr.getType() and
  DataFlow::localFlow(source, sink) and
  source.asExpr() instanceof StringLiteral and
  sink.asExpr() = expr
select source.asExpr(), sink.asExpr(), call.getCallee().getReturnType()

predicate validMethod(MethodAccess m) { m.getMethod().getDeclaringType().hasName("PrintWriter") }
