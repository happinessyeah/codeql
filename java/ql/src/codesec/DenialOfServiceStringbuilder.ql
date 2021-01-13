/**
 * @name 拒绝服务: StringBuilder
 * @description 将不受信任的数据附加到使用默认支持数组大小进行初始化的 StringBuilder 实例会导致 JVM 过度使用堆内存空间.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/StringBuilder
 * @tags security
 *       external/cwe/cwe-079
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.codesec.StringBuilder
import DataFlow::PathGraph

/** 污点函数匹配. */
private class DefaultStringBuilderSink extends DataFlow::Node {
  DefaultStringBuilderSink() {
    // exists(Method m |
    //   m.getDeclaringType().(StringBuilderSink).isSinkType()
    // ) and
    // exists(Method m, StringBuilderSink s | s.isSinkMethodName(m.getACallee().getName())) and
    exists(Method m | m.getName().matches("bad"))
  }
}

class StringbuilderConfig extends TaintTracking::Configuration {
  StringbuilderConfig() { this = "stringbuilderConfig" }

  override predicate isSource(DataFlow::Node source) { 1 = 1 }

  override predicate isSink(DataFlow::Node sink) { sink instanceof DefaultStringBuilderSink }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, StringbuilderConfig conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Denial of Service: StringBuilder $@.", source.getNode(),
  "user-provided value"
