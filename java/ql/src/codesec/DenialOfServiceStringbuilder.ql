/**
 * @name 拒绝服务: StringBuilder
 * @description 将不受信任的数据附加到使用默认支持数组大小进行初始化的 StringBuilder 实例会导致 JVM 过度使用堆内存空间.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/StringBuilder
 * @tags security
 *       external/stringBuilder
 */

import java
import semmle.code.java.dataflow.FlowSources
// import semmle.code.java.codesec.StringBuilder
import DataFlow::PathGraph

/** 污点函数匹配. */
class StringBuilderSink extends DataFlow::Node {
  StringBuilderSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("append") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      ma.getNumArgument() = 1 and
      this.asExpr() = ma
    )
  }
}

class StringBuilderSource extends DataFlow::Node {
  StringBuilderSource() {
    exists(ClassInstanceExpr cls |
      cls.getType().hasName("StringBuilder") and
      cls.getNumArgument() = 0 and
      this.asExpr() = cls
    )
  }
}

class StringbuilderConfig extends TaintTracking::Configuration {
  StringbuilderConfig() { this = "stringbuilderConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof StringBuilderSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof StringBuilderSink }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, StringbuilderConfig conf
where conf.hasFlowPath(source, sink)
select source.getNode(), source, sink, sink.getNode()
