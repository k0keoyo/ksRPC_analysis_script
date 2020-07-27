#Initialize parameters of script
[void][reflection.assembly]::LoadFile("$PSScriptRoot\NtApiDotNet.dll")
[void][reflection.assembly]::LoadFile("$PSScriptRoot\NtObjectManager.dll")

$DbgHelpPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll" #You need config dbghelp.dll path
$SymbolPath = "srv*c:\symbols*http://msdl.microsoft.com/download/symbols" #You need config your symbol path
#set enviroment path of symchk (default: C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe)
Write-Output "Check symbol in \SYSTEM32, it will take some time..."
#$env:Path = $env:Path + ";C:\Program Files (x86)\Windows Kits\10\Debuggers\x64" //enable if need
#[System.Diagnostics.Process]::Start("symchk.exe","/s srv*c:\symbols*http://msdl.microsoft.com/download/symbols c:\windows\system32\*.exe").waitforexit()
#[System.Diagnostics.Process]::Start("symchk.exe","/s srv*c:\symbols*http://msdl.microsoft.com/download/symbols c:\windows\system32\*.dll").waitforexit()

#gain all dll full path (may be will accessibleservice in future)
$FullPathArray = New-Object -TypeName System.Collections.ArrayList
Write-Output "[!]Get All DLL && exe Full path in \SYSTEM32"
Get-ChildItem "C:\Windows\System32" | ForEach-Object -Process{
    if($_.Extension -eq ".dll" -or  $_.Extension -eq ".exe"){
        $FullPathArray.add($_.FullName) | Out-Null
    }
}

#check if rpc server and record infomation/path
if(Test-Path -Path "$PSScriptRoot\RPCServerDB"){
    Remove-Item $PSScriptRoot\RPCServerDB\* -Force
}
Write-Output "[!]Get All RPC server..."
$ParseClients = $false
$RpcServerBasicInfo = ""
$DEFullPathIDA = ""
$dbRPCServerFullPath = New-Object -TypeName System.Collections.ArrayList #for ida analyze
$dbRPCServerGUID = New-Object -TypeName System.Collections.ArrayList #just for dbfile name
Write-Output "[!]Create RPC ServerDatabase directory"
if(-not(Test-Path -Path "$PSScriptRoot\RPCServerDB")){
    mkdir "$PSScriptRoot\RPCServerDB" | Out-Null
}

Write-Output "[!]Process catch RPC Server!"
foreach($FullPath in $FullPathArray){
    $InterfaceID = ""
    $RpcDLLName = ""
try{
    $RpcServerBasicInfo = [NtApiDotNet.Win32.RpcServer]::ParsePeFile($FullPath, $DbgHelpPath, $SymbolPath, $ParseClients)  
    if(!$RpcServerBasicInfo){
        Continue
    }
    $RpcServerBasicInfoText = $RpcServerBasicInfo.FormatAsText(1)
    $Text = ((($RpcServerBasicInfoText.Split("}"))[-2].Split("{"))[1].Split("\n"))[1]
    if(!$Text){
        Continue  #if no interface
    }
    $InterfaceID = "Target"
    $RpcDLLName = (($FullPath.Split("."))[0].Split("\"))[-1]
    New-Item "$PSScriptRoot\RPCServerDB\$RpcDLLName\IDL-$InterfaceID.txt" -ItemType file -Force | Out-Null
    Out-File -FilePath "$PSScriptRoot\RPCServerDB\$RpcDLLName\IDL-$InterfaceID.txt" -InputObject $RpcServerBasicInfoText | Out-Null
    Copy-Item $RpcServerBasicInfo.FilePath -Destination "$PSScriptRoot\RPCServerDB\$RpcDLLName\$RpcDLLName.dll" -Recurse | Out-Null
    $dbRPCServerFullPath.add("$PSScriptRoot\RPCServerDB\$RpcDLLName\$RpcDLLName.dll") | Out-Null
    $dbRPCServerGUID.add($RpcServerBasicInfo.InterfaceId) | Out-Null
    }
catch{
    Continue
    }
}

Write-Output "[!]Catch RPC Server success..."
Write-Output "[!]Start Analyze..."
Write-Output "[+]Check IDA Enviroment Path..."
$env:Path = $env:Path + ";$PSScriptRoot\IDA" # You need to confirm IDA path
foreach($RpcSAnalyzeFullPath in $dbRPCServerFullPath){
    #IDAPython script for analyze code path in RPC Server
    $AnalyzeTargetName = (($RpcSAnalyzeFullPath.Split("."))[0].Split("\"))[-1]
    Write-Output "[+]Focus on ***$AnalyzeTargetName***"
    if(-not(Test-Path -Path "$PSScriptRoot\RPCServerDB\$AnalyzeTargetName")){
        mkdir "$PSScriptRoot\RPCServerDB\$AnalyzeTargetName" | Out-Null
    }
    New-Item "$PSScriptRoot\RPCServerDB\$AnalyzeTargetName\IDA-AnalyzeResult.txt" -ItemType file -Force | Out-Null
    [System.Diagnostics.Process]::Start("idaq64.exe","-c -A -S""$PSScriptRoot\LogicAnalyze.py"" $RpcSAnalyzeFullPath").WaitForExit(100000) | Out-Null #IDA-AnalyzeResult will save in AnalyzeTargetName path

    $AnalyzeResult = Get-Content "$PSScriptRoot\RPCServerDB\$AnalyzeTargetName\IDA-AnalyzeResult.txt"
    if(!$AnalyzeResult){
        Write-Output "[-]Some Error!Check $AnalyzeTargetName"
        Continue
    }
    foreach($line in $AnalyzeResult){
        $ResultFunction = (($line.Split("]"))[0].Split("["))[-1]
        $ResultPathWalker = ($line.Split("]"))[-1]
        if($ResultFunction.Contains("?")){
            $ResultFunction = ($ResultFunction.Split("?"))[1]
        }
        if($ResultFunction.Contains("@")){
            $ResultFunction = ($ResultFunction.Split("@"))[0]
        }
        $selectGUID = $dbRPCServerGUID[[Array]::IndexOf($dbRPCServerFullPath,$RpcSAnalyzeFullPath)]#get index of GUID for IDL File Name
        if(!$ResultFunction){
            Continue
        }
        if(Select-String "$PSScriptRoot\RPCServerDB\$AnalyzeTargetName\IDL-Target.txt" -pattern $ResultFunction){
            $linewrite = $ResultFunction + "["+ $ResultPathWalker + "]"
            $linewrite >> $PSScriptRoot\RPCServerDB\$AnalyzeTargetName\SpeicialFinal.txt 
        }
        
    }
    Write-Output "[!]Analyze  ***$AnalyzeTargetName***  Complete!"
}

Write-Output "[!]Finish All Analyze.."

   



