/**
 * @name child_process usage in Joplin plugin
 * @description Plugin requires the child_process module, allowing it to spawn system processes.
 *              This is a high-risk pattern in a plugin context.
 * @kind problem
 * @problem.severity error
 * @id joplin/child-process-usage
 * @tags security
 *       joplin
 */

import javascript

from CallExpr requireCall
where
  requireCall.getCalleeName() = "require" and
  requireCall.getArgument(0).getStringValue() = "child_process"
select requireCall,
  "Direct child_process usage detected. Plugins must not spawn system processes."
