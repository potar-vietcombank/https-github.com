/**
 * @name Log Injection
 * @description Building log entries from user-controlled sources is vulnerable to
 *              insertion of forged log entries by a malicious user.
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @id js/log-injection
 * @tags security
 *       external/cwe/cwe-117
 */

import javascript
import DataFlow::PathGraph

from DataFlow::PathNode source, DataFlow::PathNode sink
where none()
select sink.getNode(), source, sink, "$@ flows to log entry.", source.getNode(),
  "User-provided value"
