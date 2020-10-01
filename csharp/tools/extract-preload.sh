#!/bin/bash
echo extract-preload.sh: Called with arguments: "$@"

extractor="$CODEQL_EXTRACTOR_CSHARP_ROOT/tools/extract.sh"

for i in "$@"
do
  shift
  if [[ `basename -- "$i"` =~ csc.exe|mcs.exe|csc.dll ]]
  then
    echo extract-preload.sh: exec $extractor --cil $@
    exec "$extractor" --compiler $i --cil $@
  fi
done

echo extract-preload.sh: Not a compiler invocation
