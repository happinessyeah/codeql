//查询字符串作为方法第一个参数的代码
// from Call call, StringLiteral src
// where
//   DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(call.getArgument(0)))
// select src, call.getCallee().getName(),call.getArgument(0)
// 查询
// from ExprStmt stmt, Method c
// where c.hasName("bad")
// select stmt.getExpr().getLocation(),stmt.getExpr()
//-------------------------------------------------
//查询response.getWriter().println(data);
//call.getCallee().getParameterType(0) 第一个参数类型(String)
//call.getCallee().getQualifiedName() 限定名称（PrintWriter.println）
//call.getQualifier() (getWriter(...))
//call.getQualifier().getType()调用的类型 PrintWriter
/**
 * sink
 */

import java
import semmle.code.java.dataflow.DataFlow

// from Call call
// where
//   call.getCallee().hasName("println") and
//   call.getCallee().getParameterType(0).hasName("String") and
//   call.getQualifier().getType().hasName("PrintWriter")
// select call
//data = properties.getProperty("data");
//----------------------------------------------
// from Call call
// where
//   call.getCallee().hasName("getProperty") and
//   call.getQualifier().getType().hasName("Properties")
// select call.getCallee().getReturnType()
//--------------------------------------------------------------
// 数据流雏形
// from MethodAccess call, Expr expr
// where
//   validMethod(call) and
//   call.getArgument(0).getType() = expr.getType() and
//   exists(DataFlow::Node source, DataFlow::Node sink |
//     DataFlow::localFlow(source, sink) and
//     source.asExpr() instanceof StringLiteral and
//     sink.asExpr() = expr
//   )
// select call, call.getMethod().getDeclaringType(), call.getMethod(), call.getArgument(0),
//   call.getArgument(0).getType()
//----------------------------------------------
//查询source
// from AssignExpr expr,ExprStmt stmt
// where stmt.getExpr()=expr
// select expr,expr.getRhs(),expr.getDest(),expr.getDest().getType(),expr.getRhs().(Call).getCallee().getQualifiedName()
//----------------------------------------------------
/**
 * 简易版：调用了println方法,且第一个参数为污点参数
 */
// from MethodAccess ma
// where
//   ma.getMethod().hasName("println") and
//   ma.getNumArgument() = 1
// select ma.getAnArgument()
//******************************* *source
// from AssignExpr ar
// where
//   ar.getDest().getType().hasName("String") and
//   ar.getRhs().(Call).getCallee().hasName("getProperty")
// select ar.getDest()
//******************************************** *
/**
 * /**
 * 简易版：找到所有到达污点函数prinln，进入第一个参数的可能来源
 */
from MethodAccess ma, MethodAccess src
where
  ma.getMethod().hasName("println")
   and
  ma.getNumArgument() = 1 and
  DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(ma.getArgument(0)))
select src,src.getQualifier().getType().getName()
predicate validMethod(MethodAccess m) { m.getMethod().getDeclaringType().hasName("PrintWriter") }
