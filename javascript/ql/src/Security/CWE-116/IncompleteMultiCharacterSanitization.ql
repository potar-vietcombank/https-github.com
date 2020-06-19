/**
 * @name Incomplete multi-character sanitization
 * @description A sanitizer that removes a sequence of characters may reintroduce the dangerous sequence.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id js/incomplete-multi-character-sanitization
 * @tags correctness
 *       security
 *       external/cwe/cwe-116
 *       external/cwe/cwe-020
 */

import javascript

/**
 * A regexp term that matches substrings that should be replaced with the empty string.
 */
class EmptyReplaceRegExpTerm extends RegExpTerm {
  EmptyReplaceRegExpTerm() {
    exists(StringReplaceCall replace |
      [replace.getRawReplacement(), replace.getCallback(1).getAReturn()].mayHaveStringValue("") and
      this = replace.getRegExp().getRoot().getAChild*()
    ) and
    // avoid anchored terms
    not exists(RegExpAnchor a | a.getRootTerm() = this.getRootTerm())
  }
}

/**
 * Gets a short string that is in the prefix language of `t`
 */
string getShortPrefix(EmptyReplaceRegExpTerm t) { result = getShortPrefix_internal(t, 0, false) }

/**
 * Gets a short string that is in the prefix language of `t`, following a limited `depth` additional successor terms
 */
string getShortPrefix_internal(EmptyReplaceRegExpTerm t, int depth, boolean inner) {
  inner = [true, false] and
  exists(int maxDepth |
    // a regexp that requires matching more than 5 successors is unrealistically complicated for a sanitizer
    maxDepth = 5 and
    depth = [0 .. maxDepth]
  |
    // can always stop matching at the top level
    result = "" and inner = false
    or
    depth < maxDepth and
    exists(string left |
      t.isNullable() and left = ""
      or
      t.getAMatchedString() = left
      or
      (
        t instanceof RegExpOpt or
        t instanceof RegExpStar or
        t instanceof RegExpPlus or
        t instanceof RegExpGroup or
        t instanceof RegExpAlt
      ) and
      // (not accumulating the depth for this recursion)
      left = getShortPrefix_internal(t.getAChild(), depth + 1, true)
    |
      if exists(t.getSuccessor())
      then result = left + getShortPrefix_internal(t.getSuccessor(), depth + 1, inner)
      else result = left
    )
  )
}

/**
 * Holds if `t` may match the dangerous `prefix` and some suffix, indicating intent to prevent a vulnerablity of kind `kind`.
 */
predicate matchesDangerousPrefix(EmptyReplaceRegExpTerm t, string prefix, string kind) {
  prefix = getShortPrefix(t) and
  (
    kind = "path injection" and
    // upwards navigation
    prefix = ["/..", "../"] and
    not t.getSuccessor*().getAMatchedString().regexpMatch("(?i).*[a-z0-9_-]+.*") // explicit path name mentions make this an unlikely sanitizer
    or
    kind = "HTML element injection" and
    (
      // comments
      prefix = "<!--" and
      not t.getSuccessor*().getAMatchedString().regexpMatch("(?i).*[a-z0-9_]+.*") // explicit comment content mentions make this an unlikely sanitizer
      or
      // specific tags
      prefix = "<" + ["iframe", "script", "cript", "scrip", "style"] // the `cript|scrip` case has been observed in the wild several times
    )
  )
  or
  kind = "HTML attribute injection" and
  prefix =
    [
      // ordinary event handler prefix
      "on",
      // angular prefixes
      "ng-", "ng:", "data-ng-", "x-ng-"
    ] and
  (
    // explicit matching: `onclick` and `ng-bind`
    t.getAMatchedString().regexpMatch("(?i)" + prefix + "[a-z]+")
    or
    // regexp-based matching: `on[a-z]+`
    exists(EmptyReplaceRegExpTerm start | start = t.getAChild() |
      start.getConstantValue().regexpMatch("(?i)[^a-z]*" + prefix) and
      isCommonWordMatcher(start.getSuccessor())
    )
  )
}

/**
 * Holds if `t` is a common pattern for matching words
 */
predicate isCommonWordMatcher(RegExpTerm t) {
  exists(RegExpTerm quantified | quantified = t.(RegExpQuantifier).getChild(0) |
    // [a-z]+ and similar
    quantified
        .(RegExpCharacterClass)
        .getAChild()
        .(RegExpCharacterRange)
        .isRange(["a", "A"], ["z", "Z"])
    or
    // \w+ or [\w]+
    [quantified, quantified.(RegExpCharacterClass).getAChild()]
        .(RegExpCharacterClassEscape)
        .getValue() = "w"
  )
}

from
  StringReplaceCall replace, EmptyReplaceRegExpTerm regexp, EmptyReplaceRegExpTerm dangerous,
  string prefix, string kind
where
  regexp = replace.getRegExp().getRoot() and
  dangerous.getRootTerm() = regexp and
  // only warn about the longest match (presumably the most descriptive)
  prefix = max(string m | matchesDangerousPrefix(dangerous, m, kind) | m order by m.length()) and
  // only warn once per kind
  not exists(EmptyReplaceRegExpTerm other |
    other = dangerous.getAChild+() or other = dangerous.getPredecessor+()
  |
    matchesDangerousPrefix(other, _, kind)
  ) and
  // don't flag replace operations in a loop
  not replace.getAMethodCall*().flowsTo(replace.getReceiver())
select replace,
  "This string may still contain a substring that starts matching at $@, which may cause a " + kind +
    " vulnerability.", dangerous, prefix
