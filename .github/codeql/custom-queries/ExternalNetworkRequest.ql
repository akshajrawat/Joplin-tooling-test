/**
 * @name External network request in Joplin plugin
 * @description Plugin makes a fetch() call that may exfiltrate note data.
 *              Flags all fetch() calls except provably safe localhost strings.
 * @kind problem
 * @problem.severity warning
 * @id joplin/external-network-request
 * @tags security joplin
 */

import javascript

from CallExpr call
where
  call.getCalleeName() = "fetch" and
  // Only exclude when the URL argument IS a known localhost string literal.
  // Dynamic URLs (variables) are also flagged since we cannot verify them statically.
  not exists(string url |
    url = call.getArgument(0).getStringValue() |
    url.matches("http://localhost%") or
    url.matches("http://127.0.0.1%") or
    url.matches("https://localhost%")
  )
select call,
  "fetch() call detected. Verify this is not sending note content to an external server."
