# ksRPC_anlaysis_script
---
RPC static analysis script

## YOU NEED
---

* PowerShell
* IDA with IDAPython plugin
* Windows SDK(for debuggie support)
* Visual Studio(if you want to build NtApiDotNet.dll by yourself)

## HOW TO USE
---

1. Set symbol path in enviroment variables(_NT_SYMBOL_PATH), or you need to use symchk.exe to download symbols(in my script I comment it)
2. Copy IDA directory to my script directory and rename it to "IDA", or you can add IDA path to enviroment variables.
3. Confirm that NtApiDotNet.dll and NtObjectManager.dll in my script directory
4. NtApiDotNet is a open source project which developed by James Forshaw, you can build and custom it by yourself(https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/tree/master/NtApiDotNet)
5. Config $DbgHelpPath and $SymbolPath
6. Config sensitive functions in TargetList.txt, these function names need to be the same as those shown in IDA
7. Config IDAPython script recursion depth in LogicAnalyze.py(default 10 and 7)
7. Run ksRPC_analysis_script.ps1 in Powershell

## Result
---
You will get "RPC Servers idb\Server's RPC interfaces\sensitive function code path file" in Path\to\script\RPCServerDB\[RPCServerName], sensitive function code path is stored in SpecialFinals.txt
