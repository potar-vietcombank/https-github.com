#!/bin/sh

# Disable the CLR tracer for the extractor
exec env COR_ENABLE_PROFILING=0 CORECLR_ENABLE_PROFILING=0 "$SEMMLE_PLATFORM_TOOLS/csharp/Semmle.Extraction.CSharp.Driver" "$@"
