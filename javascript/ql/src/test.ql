import javascript
from Expr dollarArg,CallExpr dollarCall
where dollarCall.getCalleeName() = "write" and
    dollarCall.getReceiver().toString() = "document" and
    dollarArg = dollarCall.getArgument(0)
select dollarArg