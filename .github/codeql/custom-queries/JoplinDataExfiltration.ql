/**
 * @name Joplin data exfiltration pattern
 * @description A function accesses joplin.data AND makes an external network call.
 *              This is a co-occurrence pattern indicating possible note exfiltration.
 * @kind problem
 * @problem.severity error
 * @id joplin/data-exfiltration
 * @tags security joplin
 */

import javascript

/**
 * A call to joplin.data.get/post/put/delete
 */
class JoplinDataAccess extends CallExpr {
  JoplinDataAccess() {
    this.getCallee().(PropAccess).getBase().(PropAccess).getPropertyName() = "data" and
    this.getCallee().(PropAccess).getBase().(PropAccess).getBase().(VarAccess).getName() = "joplin"
  }
}

/**
 * An outbound network call via fetch()
 */
class ExternalFetchCall extends CallExpr {
  ExternalFetchCall() {
    this.getCalleeName() = "fetch" and
    // Exclude localhost
    not this.getArgument(0).getStringValue().matches("http://localhost%") and
    not this.getArgument(0).getStringValue().matches("http://127.0.0.1%")
  }
}

from ExternalFetchCall fetchCall, JoplinDataAccess dataCall, Function sharedFunction
where
  fetchCall.getEnclosingFunction() = sharedFunction and
  dataCall.getEnclosingFunction() = sharedFunction
select fetchCall,
  "fetch() call appears in the same function as joplin.data access at line " +
  dataCall.getLocation().getStartLine().toString() +
  ". Review for possible note content exfiltration."
