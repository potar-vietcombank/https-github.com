/**
 * Provides implementation classes  modeling various methods of deallocation
 * (`free`, `delete` etc). See `semmle.code.cpp.models.interfaces.Deallocation`
 * for usage information.
 */

import semmle.code.cpp.models.interfaces.Deallocation

/**
 * A deallocation function such as `free`.
 */
private class StandardDeallocationFunction extends DeallocationFunction {
  int freedArg;

  StandardDeallocationFunction() {
    exists(string name |
      hasGlobalName(["free", "realloc", "CRYPTO_free", "CRYPTO_secure_free"]) and
      freedArg = 0
      or
      hasGlobalOrStdName([
          "ExFreePoolWithTag", "ExDeleteTimer", "IoFreeMdl", "IoFreeWorkItem",
          "IoFreeErrorLogEntry", "MmFreeContiguousMemory", "MmFreeContiguousMemorySpecifyCache",
          "MmFreeNonCachedMemory", "MmFreeMappingAddress", "MmFreePagesFromMdl",
          "MmUnmapReservedMapping", "MmUnmapLockedPages", "LocalFree", "GlobalFree", "VirtualFree",
          "CoTaskMemFree", "SysFreeString", "LocalReAlloc", "GlobalReAlloc", "CoTaskMemRealloc",
          "kmem_free"
        ]) and
      freedArg = 0
      or
      hasGlobalOrStdName([
          "ExFreeToLookasideListEx", "ExFreeToPagedLookasideList", "ExFreeToNPagedLookasideList",
          "pool_put", "pool_cache_put"
        ]) and
      freedArg = 1
      or
      hasGlobalOrStdName(["HeapFree", "HeapReAlloc"]) and
      freedArg = 2
    )
  }

  override int getFreedArg() { result = freedArg }
}

/**
 * An deallocation expression that is a function call, such as call to `free`.
 */
private class CallDeallocationExpr extends DeallocationExpr, FunctionCall {
  DeallocationFunction target;

  CallDeallocationExpr() { target = getTarget() }

  override Expr getFreedExpr() { result = getArgument(target.getFreedArg()) }
}

/**
 * An deallocation expression that is a `delete` expression.
 */
private class DeleteDeallocationExpr extends DeallocationExpr, DeleteExpr {
  DeleteDeallocationExpr() { this instanceof DeleteExpr }

  override Expr getFreedExpr() { result = getExpr() }
}

/**
 * An deallocation expression that is a `delete []` expression.
 */
private class DeleteArrayDeallocationExpr extends DeallocationExpr, DeleteArrayExpr {
  DeleteArrayDeallocationExpr() { this instanceof DeleteArrayExpr }

  override Expr getFreedExpr() { result = getExpr() }
}
