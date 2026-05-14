/**
 * @name Dynamic code execution in Joplin plugin
 * @description Plugin uses eval() or new Function() for dynamic code execution.
 *              This is always dangerous and should not appear in any Joplin plugin.
 * @kind problem
 * @problem.severity error
 * @id joplin/dynamic-code-execution
 * @tags security
 *       joplin
 */

import javascript

from Expr dangerous
where
  // Direct eval() call
  dangerous.(CallExpr).getCalleeName() = "eval"
  or
  // new Function(...) call
  dangerous.(NewExpr).getCalleeName() = "Function"
select dangerous,
  "Dynamic code execution via '" +
  dangerous.(CallExpr).getCalleeName() +
  "' detected. This must not appear in a Joplin plugin."
