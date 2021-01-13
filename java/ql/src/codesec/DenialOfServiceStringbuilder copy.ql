/**
 * @name 拒绝服务: StringBuilder
 * @description 将不受信任的数据附加到使用默认支持数组大小进行初始化的 StringBuilder 实例会导致 JVM 过度使用堆内存空间.
 * @kind problem
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

from Class c, StringBuilderSink s
where
  c.getAMethod().getACallee().getDeclaringType() instanceof StringBuilderSink 
  and
  s.isSinkMethodName(c.getAMethod().getACallee().getName())
select c.getAMethod(), c.getAMethod() + "," + c.getAMethod().getLocation()
// select c.getAMethod().getACallee().getName(), c.getAMethod().getACallee().getDeclaringType()
