@echo off

setlocal
    rem Disable the CLR tracer for the extractor
    set COR_ENABLE_PROFILING=0
    set CORECLR_ENABLE_PROFILING=0
    type NUL && "%CODEQL_EXTRACTOR_CSHARP_ROOT%/tools/%CODEQL_PLATFORM%/Semmle.Extraction.CSharp.Driver.exe" %*
    exit /b %ERRORLEVEL%
endlocal

