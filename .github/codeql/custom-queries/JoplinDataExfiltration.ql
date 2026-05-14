/**
 * @name Joplin data exfiltration pattern
 * @description Data retrieved from joplin.data API flows into an external network call.
 *              This is a high-confidence exfiltration pattern.
 * @kind path-problem
 * @problem.severity error
 * @id joplin/data-exfiltration
 * @tags security
 *       joplin
 */

import javascript
import DataFlow::PathGraph

/**
 * A call to the Joplin data API (joplin.data.get, joplin.data.post, etc.)
 */
class JoplinDataCall extends DataFlow::CallNode {
  JoplinDataCall() {
    this.getCalleeNode().asExpr().(PropAccess).getBase().(PropAccess).getPropertyName() = "data" and
    this.getCalleeNode().asExpr().(PropAccess).getBase().(PropAccess).getBase().(VarAccess).getName() = "joplin"
  }
}

/**
 * A call to fetch() or axios that represents an external network call.
 */
class ExternalNetworkCall extends DataFlow::CallNode {
  ExternalNetworkCall() {
    this.getCalleeName() = "fetch" or
    this.getCalleeName() = "post" or
    this.getCalleeName() = "put"
  }
}

/**
 * Tracks data from joplin.data API calls flowing into external network calls.
 */
class JoplinExfiltrationConfig extends TaintTracking::Configuration {
  JoplinExfiltrationConfig() { this = "JoplinExfiltrationConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof JoplinDataCall
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(ExternalNetworkCall call |
      sink = call.getAnArgument()
    )
  }
}

from JoplinExfiltrationConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Data from joplin.data API flows into an external network call. Possible exfiltration of note content."
