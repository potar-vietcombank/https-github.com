#!/bin/bash
echo extract-csharp.sh: Called with arguments: "$@"

extractor=$ODASA_TOOLS/extract.sh

for i in "$@"
do
  shift
  if [[ `basename -- "$i"` =~ csc.exe|mcs.exe|csc.dll ]]
  then
    echo extract-csharp.sh: exec $extractor --cil $@
    exec "$extractor" --compiler $i --cil $@
  fi
done

echo extract-csharp.sh: Not a compiler invocation
