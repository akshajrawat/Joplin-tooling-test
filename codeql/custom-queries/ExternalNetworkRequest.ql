/**
 * @name External network request in Joplin plugin
 * @description Plugin makes a network request to an external URL which may exfiltrate note data.
 * @kind problem
 * @problem.severity warning
 * @id joplin/external-network-request
 * @tags security
 *       joplin
 */

import javascript

/**
 * Holds if the string value is a localhost address.
 */
predicate isLocalhost(string url) {
  url.matches("http://localhost%") or
  url.matches("http://127.0.0.1%") or
  url.matches("https://localhost%")
}

from CallExpr call, string callee
where
  (
    // fetch() calls
    callee = "fetch" and
    call.getCalleeName() = callee
    or
    // XMLHttpRequest.open() calls
    callee = "open" and
    call.getCalleeName() = callee and
    call.getReceiver().(NewExpr).getCalleeName() = "XMLHttpRequest"
  ) and
  // Exclude localhost calls
  not isLocalhost(call.getArgument(0).getStringValue())
select call,
  "External network call '" + callee + "()' detected. Verify this is not exfiltrating note content."
