import java

class StringBuilderSink extends Class {
  StringBuilderSink() {
    hasQualifiedName("java.lang", "StringBuilder") or hasQualifiedName("java.lang", "StringBuffer")
  }

  /**
   * 判断调用的方法名是否是污点函数方法
   */
  predicate isSinkMethodName(string methodName) {
    methodName = "append"
    or
    methodName = "insert"
    or
    methodName = "replace"
  }

  /**
   * 判断方法类型是否匹配
   */
  predicate isSinkType() {
     hasQualifiedName("java.lang", "StringBuilder") or hasQualifiedName("java.lang", "StringBuffer")
  }
}
