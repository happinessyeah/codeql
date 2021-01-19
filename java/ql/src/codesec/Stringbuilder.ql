/**
 * @name 拒绝服务: StringBuilder
 * @description 将不受信任的数据附加到使用默认支持数组大小进行初始化的 StringBuilder 实例会导致 JVM 过度使用堆内存空间.
 * @kindproblem
 * @problem.severity error
 * @precision high
 * @id java/StringBuilder
 * @tags security
 *       external/cwe/cwe-079
 */

import java

from Constructor constructor, Call call
where
  constructor.getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
  call.getCallee().hasName("append") and
  constructor.hasNoParameters() and
//   constructor.getNumberOfParameters() = 1 and
  constructor.getName() = call.getQualifier().getType().getName()//stringbuilder.append
select call.getLocation(), constructor.getName(), call.getQualifier().getType()