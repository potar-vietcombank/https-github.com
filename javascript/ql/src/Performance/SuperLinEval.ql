/**
 * @name Super lin regexp
 * @description Super lin regexp
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id js/lin-redos
 * @tags security
 *       external/cwe/cwe-730
 *       external/cwe/cwe-400
 */

import semmle.javascript.security.performance.SuperlinearBackTracking

from PolynomialBackTrackingTerm t
select t.getRootTerm(), "Has superliniear regexp"
