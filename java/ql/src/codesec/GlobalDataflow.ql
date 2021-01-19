import java
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

//（正式版本）：查找全局数据流中的 拒绝服务：strbuilder缺陷
class Source extends DataFlow::Node {
  Source() {
    exists(ClassInstanceExpr src |
      src.getConstructedType().hasQualifiedName("java.lang", "StringBuilder") and
      this.asExpr() = src
    )
  }
}

class Sink extends DataFlow::Node {
  Sink() {
    exists(MethodAccess ma, Type type |
      (
        (
          ma.getMethod().hasName("append") and
          ma.getNumArgument() = 1 and
          ma.getAnArgument().getType() = type and
          (type.getTypeDescriptor() = "Ljava/lang/String;" or type.getTypeDescriptor() = "[C")
          or
          ma.getMethod().hasName("insert") and
          ma.getNumArgument() = 2 and
          ma.getArgument(1).getType() = type and
          (type.getTypeDescriptor() = "Ljava/lang/String;" or type.getTypeDescriptor() = "[C")
          or
          ma.getMethod().hasName("replace") and
          ma.getNumArgument() = 3 and
          ma.getArgument(2).getType() = type and
          (type.getTypeDescriptor() = "Ljava/lang/String;" or type.getTypeDescriptor() = "[C")
        ) and
        (
          ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") or
          ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuffer")
        ) and
        this.asExpr() = ma.getQualifier()
      )
    )
  }
}

class MyDataFlowConfiguration extends DataFlow::Configuration {
  MyDataFlowConfiguration() { this = "MyDataFlowConfiguration" }

  override predicate isSource(DataFlow::Node source) { source instanceof Source }

  override predicate isSink(DataFlow::Node sink) { sink instanceof Sink }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, MyDataFlowConfiguration conf
where conf.hasFlowPath(source, sink)
select source.getNode(), source, sink, sink.getNode()
