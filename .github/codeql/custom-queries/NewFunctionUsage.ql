/**
 * @name new Function() usage in Joplin plugin
 * @description Plugin uses new Function() for dynamic code execution.
 * @kind problem
 * @problem.severity error
 * @id joplin/new-function-usage
 * @tags security joplin
 */

import javascript

from NewExpr newFunc
where newFunc.getCalleeName() = "Function"
select newFunc, "new Function() detected. Dynamic code execution must not appear in a Joplin plugin."
