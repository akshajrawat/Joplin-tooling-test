/**
 * @name eval() usage in Joplin plugin
 * @description Plugin uses eval() for dynamic code execution.
 * @kind problem
 * @problem.severity error
 * @id joplin/eval-usage
 * @tags security joplin
 */

import javascript

from CallExpr evalCall
where evalCall.getCalleeName() = "eval"
select evalCall, "eval() detected. Dynamic code execution must not appear in a Joplin plugin."
