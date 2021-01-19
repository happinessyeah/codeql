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

//Step 1,先确定污点函数及参数
//ma.getMethod().getDeclaringType().getQualifiedName():获取方法限定类型	java.lang.StringBuilder
// from MethodAccess ma
// where
//   ma.getMethod().hasName("append") and
//   ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
//   ma.getNumArgument() = 1
// select ma
//Step 2,查找到达污点函数位置的所有可能来源
// from MethodAccess ma, StringLiteral src
// where
//   ma.getMethod().hasName("append") and
//   ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
//   ma.getNumArgument() = 1 and
//   DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(ma.getArgument(0)))
// select src
//----------------------------------------
//Step 1, 先确定污点，这儿的污点其实不是参数，而是stringBuilder.append方法//ma.getMethod().getDeclaringType().getQualifiedName():获取方法限定类型	java.lang.StringBuilder
// from MethodAccess ma
// where
//   (
//     (
//       ma.getMethod().hasName("append") and
//       ma.getNumArgument() = 1
//       or
//       ma.getMethod().hasName("insert") and
//       ma.getNumArgument() = 2
//       or
//       ma.getMethod().hasName("replace") and
//       ma.getNumArgument() = 3
//     ) and
//     (
//       ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") or
//       ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuffer")
//     )
//   )
// select ma
//Step 2 version2.1,查找到达污点函数位置的所有可能来源
// from MethodAccess ma, ClassInstanceExpr src
// where
//   ma.getMethod().hasName("append") and
//   ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
//   ma.getNumArgument() = 1 and
//   DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(ma.getQualifier()))
// select src,src.getType()
//---------------------------------------------------------------
//Step 2 version2.2,查找到达污点函数位置的所有可能来源（这个只找本地数据流）
// from MethodAccess ma, ClassInstanceExpr src
// where
//   (
//     (
//       ma.getMethod().hasName("append") and
//       ma.getNumArgument() = 1
//       or
//       ma.getMethod().hasName("insert") and
//       ma.getNumArgument() = 2
//       or
//       ma.getMethod().hasName("replace") and
//       ma.getNumArgument() = 3
//     ) and
//     (
//       ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") or
//       ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuffer")
//     )
//   ) and
//   DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(ma.getQualifier()))
// select src, src.getType(),src.getConstructedType().getQualifiedName()
//-----------------------------------------------------------------------
from MethodAccess ma
where
  ma.getMethod().hasName("append") and
  ma.getNumArgument() = 1
select ma,ma.getAnArgument(),ma.getAnArgument().getType(),ma.getAnArgument().getType().getTypeDescriptor()