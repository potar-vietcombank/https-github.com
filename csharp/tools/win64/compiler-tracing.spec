**\fakes*.exe:
**\moles*.exe:
**\Semmle.Extraction.CSharp.Driver.exe:
  order compiler
  trace no
**\csc*.exe:
  invoke ${config_dir}\..\extract.cmd
  prepend --compiler
  prepend "${compiler}"
  prepend --cil
