/**
 * @name Cross-site scripting
 * @description Writing user input directly to a web page
 *              allows for a cross-site scripting vulnerability.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/Css/new
 * @tags security
 *       external/cwe/cwe-079/css
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.XSS
import DataFlow::PathGraph

predicate validMethod(MethodAccess m) { m.getMethod().getDeclaringType().hasName("PrintWriter") }

class CSSSource extends DataFlow::Node {
  CSSSource() {
    exists(MethodAccess ma |
      ma.getQualifier().getType().hasName("Properties") and this.asExpr() = ma
    )
  }
}

class CSSSink extends DataFlow::Node {
  CSSSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("println") and
      this.asExpr() = ma.getAnArgument()
    )
  }
}

class XSSConfig extends TaintTracking::Configuration {
  XSSConfig() { this = "XSSConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof CSSSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof CSSSink }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, XSSConfig conf
where conf.hasFlowPath(source, sink)
select source.getNode(), source, sink,
  // , "Cross-site scripting vulnerability due to $@.",
  sink.getNode()
