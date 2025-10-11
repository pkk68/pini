#requires -version 5.0
# 
# Revision:
#   2025-10-11: 0.03.20251011 - testnet2, vmmemwsl on win11
#   2024-10-18: 0.03.20241018 - testnet2
#   2021-09-13: 0.02.20210913 - pi-consensus - testnet1
# dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
# dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
#
$DATE = Get-Date
$FileLogDate = (Get-Date -f yyyy-MM-dd-HH-mm-ss)
$global:CurrentNodeName = "PiNode"
# pinetwork/pi-node-docker:latest
#$global:CurrentContainer = "pi-consensus"
#
# pinetwork/pi-node-docker:community-v1.0-p19.6
#
$global:CurrentContainer = "testnet2"
Set-Variable -Name PICONTAINER -Value $global:CurrentContainer -Option Constant, AllScope -Force
Set-Variable -Name HTTP_PORT -Value "11626" -Option Constant, AllScope -Force

$PIDIR = "C:\Users\$env:UserName\AppData\Roaming\Pi Network"
$PiNodeEntry = @{ NodeName = "GD"; `
NodeType = " watcher"; `
StellarBuild = "StellarCoreBuild"; `
ErrorRate = "0"; `
NetworkPhase = "Pi Testnet2"; `
LedgeAge = "1"; `
LocalBlkNum = "3000000"; `
QuorumLedger = "3000000"; `
LastBlkNum = "3000000"; `
QuorumState = "null"; `
AuthenPeers = "64"; `
PendingPeers = "8"; `
ProtocolVersion = "19"; `
ConsensusState = "Synced"; `
QuorumNodeAgreed = "3"; `
QuorumIntersection = "true"; `
NetworkLatency = "3"; `
startedOn = "3"; `
ClosedTime = "0"
}

$global:verbose=$false
$global:computerip=$null
$global:routerip=$null
$global:computername=$null
$VERSION = "0.03.20251011"
# testnet1 working directory
# $StellarConfig = "$PIDIR\docker_volumes\stellar\core\etc\stellar-core.cfg"
# testnet2 working directory
$t2="testnet_2"
$StellarConfig = "$PIDIR\docker_volumes\$t2\stellar\core\etc\stellar-core.cfg"
$Ptmp = ".\peer-$FileLogDate.tmp"
$global:OutputFile = ".\PeerIP-$FileLogDate.csv"

$options = @{
    opt1 = [bool] 0
}
$help = @"
    PINode Information usage: pini [-h] [-v]
 
    Pi Node Information v.0.03.20251011
 
    Pi Node script tool to collect Pi Node information
 
    Options:         
        -v,--verbose    Verbose     Debug information for further investigation
        -h,--help       Help        Prints helper
"@

function Parse-Option ($argv, $options)
{
    $opts = @()
    if (!$argv) { return $null }
    
    foreach ($arg in $argv)
    {
        if ($arg -like '-*') { $opts += $arg }
    }
    $argv = [Collections.ArrayList]$argv
    if ($opts) 
    {
        foreach ($opt in $opts)
        {
            if ($opt -eq '-v' -or $opt -eq '--verbose')
            {
                $options.opt1 = [bool] 1
            }
            else
            {
                Write-Host $help -ForegroundColor Cyan
                break 1;
            }
            $argv.Remove($opt)
        }
    }
    return [array]$argv,$options
}

function Write-Log
{
    Param ([string]$logstring)
    Add-content $LogFile -value $logstring
}

function Save-TextToLogFile
{
    param ([string]$Text, [string]$Log)

    # Check if the text file exists
    if (Test-Path $Text)
    {
        # Read the content of the text file
        $content = Get-Content $Text
        
        # Append the content to the log file
        Add-Content -Path $Log -Value $content
        #Write-Host "Content saved to log file: $Log"
    }
    else
    {
        Write-Host "Text file does not exist: $Text"
        Write-Log "Text file does not exist: $Text"
    }
}

function Run-Command ($command)
{

    if ($command[0] -eq '"')
    {
        Invoke-Expression "& $command"
    }
    else
    {
        Invoke-Expression $command
    }
}

function Is-AppRunning ($opt)       
{       
    if ([string]::IsNullOrEmpty($opt)) {Write-Error "ERROR: Invalid application"}
    Get-Process $opt | Out-Null
    if (-Not $?)
    {
        $msg = "ERROR: $opt not found!"
        Write-Warning -Message $msg -Category ObjectNotFound
    }
}

function Check-RunWindowsVer 
{
    $osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
    $buildNumber = [int]($osVersion.Split('.')[2])

    if ($buildNumber -ge 22000)
    {
        Is-AppRunning("vmmemwsl")
    }
    elseif ($buildNumber -ge 10240 -and $buildNumber -lt 22000)
    {
        Is-AppRunning("vmmem")
    }
    else
    {
        Write-Log "Unknown Windows version"
    }
}

function Get-ValueFromKeyPattern
{
    param (
        [string]$FilePath,
        [string]$KeyPattern
    )
    
    # Ensure the file exists
    if (-not (Test-Path $FilePath))
    {
        Write-Error "File not found: $FilePath"
        return
    }
    #Write-Host "Checking text file $FilePath with $KeyPattern"

    # Read the file line by line
    foreach ($line in Get-Content -Path $FilePath)
    {
        #Write-Host "Checking $line ..."
        # Check if the line matches the key pattern
        if ($line -match "$KeyPattern\s*[:=]\s*(.+)")
        {
            return $matches[1]
        }
    }

    Write-Output "Key pattern not found in file."
}

function Check-PiPort ($addr, $paddr)       
{
    $text=-join("Check default opened Pi ports for ", [string]$addr, [string]$paddr)
    Write-Log $text
    $PortRange = 31400..31409
    if ($global:verbose -eq $false)
    {
        $PortRange = 31401..31403
    }
    Write-Host "Checking default Pi ports status for$addr $paddr..."
    $cn = $computername
    ForEach ($p in $PortRange)
    {
        $r = (Test-NetConnection -ComputerName "$cn" -Port $p).TcpTestSucceeded
        if($r)
        {
            $msg = "           port $p open"
            Write-Host $msg -f Green
        }
        else
        {
            $msg = "           port $p close"
            if ($p -eq 31402)
            {
                Write-Host $msg -f Red
            }
            else
            {
                Write-Warning $msg
            }
         }
         $msg | Out-File -Append -Encoding utf8 -FilePath $LogFile
    }
    Write-Log ""
}

function Get-PublicIP
{
    $cip = ""
    $lastIP = "C:\ProgramData\TEMP\pip.txt"
    if (-Not (Test-Path -Path $lastIP -PathType Leaf))
    {
        New-Item -Path "$lastIP" -ItemType File
        $cip = (Invoke-WebRequest -uri "http://ifconfig.me/ip").Content
        Set-Content "$lastIP" "$cip"
    }
    $ip0 = Get-Item -Path "$lastIP" | Get-Content -Tail 1
    
    $counter = 0
    # Check current Pi Node processes
    $sites = @('http://ifconfig.me/ip', 'http://ident.me', 'http://ipinfo.io/ip')
    foreach ($i in $sites)
    {
        $ipx = (Invoke-WebRequest -uri "$i").Content
        $rc = Compare-Subnets -ipa "$ip0" -ipb "$ipx" -mask 255.255.255.0
        if (-Not $rc)
        {
            $msg = "Computer restart, new public ip address"
            Write-Host $msg -ForegroundColor Red
            Set-Content "$lastIP" "$ipx"
        }
        else
        {
            $counter++
        }
    }

    if ([int]$counter -eq 3)
    {
        $global:routerip = $ip0
    }
}


function Check-VirtualizationAndHyperV
{
    # Check virtualization status
    $virtualizationInfo = systeminfo | Select-String "Virtualization Enabled In Firmware"
    if ($virtualizationInfo -match "Yes")
    {
        Write-Host "✅ Virtualization is enabled in firmware."
    } elseif ($virtualizationInfo -match "No")
    {
        Write-Host "❌ Virtualization is NOT enabled in firmware."
    }
    else
    {
        Write-Host "⚠️ Unable to determine virtualization status."
    }

    # Check Hyper-V support
    $hyperVInfo = systeminfo | Select-String "Hyper-V Requirements"
    if ($hyperVInfo)
    {
        $requirementsMet = $true
        foreach ($line in $hyperVInfo)
        {
            if ($line -match "No")
            {
                $requirementsMet = $false
                break
            }
        }

        if ($requirementsMet)
        {
            Write-Host "✅ Hyper-V is supported and all requirements are met."
        }
        else
        {
            Write-Host "⚠️ Hyper-V is NOT fully supported or some requirements are missing."
        }
    }
    else
    {
        Write-Host "⚠️ Unable to determine Hyper-V support."
    }
}


function Get-OSInformation
{
    Write-Log "Check OS details information"
    Write-Host "Checking OS details information"
    $osinfo = Get-WmiObject Win32_OperatingSystem
    $osinfo | Out-File -Append -Encoding utf8 -FilePath $LogFile
    
    Write-Host "           System configuration"
    if ($global:verbose -eq $false)
    {
        $sysinfo = SystemInfo /fo csv | ConvertFrom-Csv | Select OS*, System*, Hotfix* | Format-List
        $sysinfo | Out-File -Append -Encoding utf8 -FilePath $LogFile
    }
    else
    {
        SystemInfo | Out-File -Append -Encoding utf8 -FilePath $LogFile
    }
    Write-Host "           Computer information"
    if ($global:verbose -eq $true)
    {
        $cc="Get-ComputerInfo"
        $windowsOnly=""
        #$windowsOnly=" -Property Windows*"
        $c = -join($cc, " ", $windowsOnly)
        Run-Command($c) | Out-File -Append -Encoding utf8 -FilePath $LogFile
    }
    else
    {
        $wininfo = gcim Win32_ComputerSystem | fl *
        $wininfo | Out-File -Append -Encoding utf8 -FilePath $LogFile
    }
    $computername = hostname

    Write-Host "           Top 10 running processes"
    Write-Log "Top 10 processes with largest working set size"
    $top10Process = Get-Process | sort -desc ws | select -first 10
    $top10Process | Out-File -Append -Encoding utf8 -FilePath $LogFile

    Write-Host "           Local disk"
    Write-Log "Local disk"
    $ld = Get-WmiObject -Class Win32_LogicalDisk -ComputerName "$computername" | where-object {$_.DriveType -eq 3}
    $ld | Out-File -Append -Encoding utf8 -FilePath $LogFile
    
    $IP4 = ipconfig | findstr IPv4
    $IP4 = $IP4 | findstr 192.168
    $ip = $IP4.Split(":")
    $global:computerip = $ip[1]
    
    # Checking public ip address
    Get-PublicIP
    Write-Host "           IP address"

    Check-PiPort($global:computerip, $global:routerip)
    
    # Docker 3.5.2 version 20.10.7, build f0df350
    # Docker 3.6.0 version 20.10.8, build 3967b7d
    # Turn off the "What's next?" message
    # Settings | General | uncheck Show CLI hints
    #   Show CLI hints
    #   Get CLI hints and tips when running Docker commands in the CLI.
    Write-Log "-> docker --version"
    $d = docker --version
    $d | Out-File -Append -Encoding utf8 -FilePath $LogFile
    Write-Host "$d"
    Write-Log "-> docker version"
    $d = docker version
    $d | Out-File -Append -Encoding utf8 -FilePath $LogFile
    Write-Log "List all containers"
    $d = docker ps -a
    $d | Out-File -Append -Encoding utf8 -FilePath $LogFile
    Write-Host "$d"

    Write-Log "-> docker-compose  --version"
    $d = docker-compose  --version
    $d | Out-File -Append -Encoding utf8 -FilePath $LogFile
    Write-Host "$d"

    Write-Host "           Pi App & vmmem"
    Check-RunWindowsVer
    Check-VirtualizationAndHyperV
    Is-AppRunning("Pi Network")
    Is-AppRunning("wsl")
    Write-Log "wsl --list --verbose"
    $d = wsl --list --verbose
    $d | Out-File -Append -Encoding ASCII -FilePath $LogFile
    Write-Host "           " -NoNewLine
    
}

function Get-CPUInfo
{
    <#
    .SYNOPSIS
        Returns CPU information including physical cores and logical processors.
    
    .DESCRIPTION
        Uses Win32_Processor WMI class to query the number of cores and logical processors
        across all CPUs. Works on Windows 10 and later.

    .EXAMPLE
        PS> Get-CPUInfo

        PhysicalCores LogicalProcessors
        ------------- -----------------
                  8                16
    #>

    try
    {
        $cpuData = Get-CimInstance Win32_Processor

        $physicalCores     = ($cpuData | Measure-Object -Property NumberOfCores -Sum).Sum
        $logicalProcessors = ($cpuData | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        Write-Log "physicalCores     $physicalCores"
        Write-Log "logicalProcessors $logicalProcessors"
        #Write-Host "physicalCores     $physicalCores"
        #Write-Host "logicalProcessors $logicalProcessors"

        [PSCustomObject]@{
            PhysicalCores     = $physicalCores
            LogicalProcessors = $logicalProcessors
        }
    }
    catch
    {
        Write-Error "Failed to retrieve CPU info: $_"
    }
}

function Get-PiProcess ($opt)
{
    $cc="Get-Process"
    $ll='| sort-object CPU'
    $c = -join($cc, " ", $opt, " ", $ll)
    Write-Log "$c"
    Run-Command($c) | Out-File -Append -Encoding utf8 -FilePath $LogFile

}

function dshWrapper ($opt)
{
    $cc="docker exec -ti $PICONTAINER stellar-core http-command"
    $c = -join($cc, " ", $opt)
    Write-Log "-> $c"
    Run-Command($c) | Out-File -Append -Encoding utf8 -FilePath $LogFile
}

function dshCore ($opt)
{
    $cc="docker exec -ti $PICONTAINER stellar-core"
    $c = -join($cc, " ", $opt)
    Write-Log "-> $c"
    Run-Command($c) | Out-File -Append -Encoding utf8 -FilePath $LogFile
}

function dockerWrapper ($opt)
{
    Write-Host ""
    $cc="docker "
    $c = -join($cc, " ", $opt)
    Write-Log "-> $c"
    Run-Command($c) | Out-File -Append -Encoding utf8 -FilePath $LogFile
}

function dockerWrapper2 ($opt)
{
    $cc="docker "
    $c = -join($cc, " ", $opt, " ", $PICONTAINER)
    Write-Log "-> $c"
    Run-Command($c) | Out-File -Append -Encoding utf8 -FilePath $LogFile
}

function Get-ConsensusValue ($Fn, $pattern)
{
    $tmp = $null
    if ([string]::IsNullOrEmpty($pattern)) {Write-Error "ERROR: Invalid pattern"}
    
    if (-Not(Test-Path -Path $Fn -PathType Leaf))
    {
        $msg = "File not found"
        Write-Error $msg -ForegroundColor Red
    }
    if ($pattern -eq "startedOn")
    {
        $tmp=bash -c "cat $Fn | grep -w $pattern | cut -d ':' -f2-"
    }
    else
    {
        $tmp=bash -c "cat $Fn | grep -w $pattern | cut -d ':' -f 2"
    }
    if ($pattern -ne "state" -and $tmp -ne "Synced!")
    {
        $tmp=$tmp -replace ".$"
    } 
    
    return $tmp
}

function Compare-Subnets
{
    param (
    [parameter(Mandatory=$true)]
    [Net.IPAddress]
    $ipa,
     
    [parameter(Mandatory=$true)]
    [Net.IPAddress]
    $ipb,
     
    [parameter()]
    [alias("SubnetMask")]
    [Net.IPAddress]
    $mask ="255.255.255.0"
    )
    
    $ret = $false
    if (($ipa.address -band $mask.address) -eq ($ipb.address -band $mask.address))
    {
        $ret = $true
    }
    return $ret
}

function Write-Host2-With-Color ([String[]]$text, [ConsoleColor[]]$color)       
{
    for ($i = 0; $i -lt $text.Length; $i++)
    {
        Write-Host $text[$i] -Foreground $color[$i] -NoNewLine
    }
    Write-Host ""
}

function Backup-Files ($file, $log)     
{
    if (Test-Path -Path $file -PathType Leaf)
    {
        Get-Content $file | Out-File -Append -Encoding utf8 -FilePath $LogFile
    }
    Write-Log ""
}

function Start-Sleeps($seconds)
{
    $doneDT = (Get-Date).AddSeconds($seconds)
    while($doneDT -gt (Get-Date))
    {
        $secondsLeft = $doneDT.Subtract((Get-Date)).TotalSeconds
        $percent = ($seconds - $secondsLeft) / $seconds * 100
        Write-Progress -Activity "Sleeping" -Status "Sleeping..." -SecondsRemaining $secondsLeft -PercentComplete $percent
        [System.Threading.Thread]::Sleep(500)
    }
    Write-Progress -Activity "Sleeping" -Status "Sleeping..." -SecondsRemaining 0 -Completed
}

function Sleep-Progress($seconds)
{
    $s = 0
    do
    {
        $p = [math]::Round(100 - (($seconds - $s) / $seconds * 100));
        Write-Progress -Activity "Waiting..." -Status "$p% Complete:" -SecondsRemaining ($seconds - $s) -PercentComplete $p;
        [System.Threading.Thread]::Sleep(500)
        $s++
    }
    while($s -lt $seconds)
}    


function Get-IPInfo
{
  Param([string]$IPAddress) 
  $request = Invoke-RestMethod -Method Get -Uri "http://ip-api.com/json/$IPAddress"
  [PSCustomObject]@{
    IP      = $request.query
    City    = $request.city
    Zip     = $request.zip
    Country = $request.country
    Isp     = $request.isp
  }
}

function Get-PeerData ([int]$AuthenPeer)
{
    Write-Log "-> docker exec -ti $PICONTAINER stellar-core http-command peers"
    $d = docker exec -ti $PICONTAINER stellar-core http-command peers
    $d | Out-File -Append -Encoding utf8 -FilePath $LogFile
    $d | Out-File -Append -Encoding utf8 -FilePath $Ptmp
    (Get-Content $Ptmp | Select-Object -Skip 12) | Set-Content $Ptmp

    $Results = @()
    $Hosts = @()
    if (-Not (Test-Path -Path $Ptmp -PathType Leaf))
    {
        Write-Log "WARNING: Cannot create peer temp file"
        Remove-Item -Path ".\peer*.tmp" -Force
        return;
    }
    $Lines =  Get-Content $Ptmp
    #Checking each line for each ip address
    foreach ($Line in $Lines)
    {
        $IP = $Object1 = $null
        $IP = ($Line  |  Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches).Matches.Value
        # Invalid ip addr format or default pi network gateway
        if ([string]::IsNullOrEmpty($IP) -or $IP -match "172.17.0.1") {Write-Host "." -NoNewLine}
        elseif($IP -notmatch "0.0.0.0")
        {
            # Valid ip addr
            $Object1 = New-Object PSObject -Property @{ 
            IPAddress = $IP
            }
            $Results += $Object1
        }
    }
    #Check ip duplication
    $IPUnique = $Results | Select-Object IPAddress -Unique
    $i = 0
    #Check full ip address data
    foreach ($Item in $IPUnique)
    { 
        $i++
        if ($i -gt 20)
        {
            # Just loop a set of 20 ip addresses only
            # then wait for max 8 outgoing connections
 
            # Wait 1 min
            #Start-Sleep -Seconds 60
            Sleep-Progress 60
            $i = 0
        }
        Get-IPInfo($Item.IPAddress) | Select-Object IP, City, Zip, Country, Isp | Export-Csv $global:OutputFile -NoTypeInformation -Append
        if ($i -gt [int]$AuthenPeer -and $global:verbose -eq $false)
        {
            break;
        }
        #Write-Host "." -NoNewLine 
    }
    Remove-Item -Path $Ptmp -Force
}


###############################################################################
#                       S C R I P T  E X E C U T I O N                        #
###############################################################################
$Title = "Pi node information v$VERSION"
#$Title2 = "     with latest protocol 19 for $global:CurrentContainer"


$argv,$options = Parse-Option $args $options
if ($options.opt1)
{
    $global:verbose=$true
}

New-Item -Path 'C:\' -Name "$global:CurrentNodeName-$FileLogDate.txt" -ItemType File | Out-Null
$LogFile = "C:\$global:CurrentNodeName-$FileLogDate.txt"
$Ftmp = "tmp$(Get-Date -Format 'yyyy-MMM-dd-hh-mm-ss-tt').tmp"
$Ptmp = "peer$(Get-Date -Format 'yyyy-MMM-dd-hh-mm-ss-tt').tmp"

Write-Host ""
Write-Host $Title -ForegroundColor Magenta
#Write-Host $Title2 -ForegroundColor Magenta
Write-Host ""
Write-Log $Title
#Write-Log $Title2

Get-OSInformation
Get-CPUInfo

Write-Log "Windows PowerShell"
$v = (Get-Host).Version
$v | Out-File -Append -Encoding utf8 -FilePath $LogFile

# Check current Pi Node processes
$checkPiProcess = "docker*", "pi*", "vpnkit*", "wsl*"
$checkPiProcess | ForEach-Object {Write-Host "$_ " -NoNewline; Get-PiProcess($_)}
    
$StellarCore = docker exec -ti $PICONTAINER bash -c "curl localhost:$HTTP_PORT"
if ([string]::IsNullOrEmpty($StellarCore)) {Write-Warning "stellar-core main page cannot be fetched"}
$StellarCore | Out-File -Append -Encoding utf8 -FilePath $LogFile

# According to Stellar documenation, currently we have 03 type of nodes:
# archiver (watcher), basic and full validator
# you will still watch SCP and see all the data in the network but will not send validation messages.
$PiNodeEntry["NodeType"] = " watcher"
if (Test-Path -Path $StellarConfig -PathType Leaf)
{
    # https://developers.stellar.org/docs/run-core-node/
    # https://developers.stellar.org/docs/run-core-node/configuring/
    # https://github.com/stellar/stellar-core/blob/master/docs/software/admin.md
    $tmp = Get-ChildItem -Path $StellarConfig | Select-String -Pattern 'NODE_IS_VALIDATOR=' -CaseSensitive
    $type = ($tmp -split '=')[1]
    if ($type -eq "true") {$PiNodeEntry["NodeType"] = " validator"}
}

Write-Host "`nChecking Pi node & $global:CurrentContainer container ..."
# "info", "peers", "bans", "metrics", "quorum", "quorum?transitive=true", "getcursor", "scp"
# set the log level
Write-Log "-> docker exec -ti $PICONTAINER stellar-core http-command ll?level=debug"
$s = docker exec -ti $PICONTAINER stellar-core http-command ll?level=debug
$s | Out-File -Append -Encoding utf8 -FilePath $LogFile

Write-Log "-> docker exec -ti $PICONTAINER stellar-core http-command info"
$cmd = docker exec -ti $PICONTAINER bash -c "stellar-core http-command info"
$cmd | Out-File -Append -Encoding utf8 -FilePath $LogFile
$cmd | Out-File -Append -Encoding utf8 -FilePath $Ftmp
if (-Not (Test-Path -Path $Ftmp -PathType Leaf))
{
    Write-Error "ERROR: Cannot fetch $global:CurrentContainer information"
    Remove-Item -Path .\tmp*.tmp -Force
    throw "exit"
}
(Get-Content $Ftmp | Select-Object -Skip 12) | Set-Content $Ftmp
$ff = $Ftmp
$PiNodeEntry["NodeName"] = bash -c "cat $ff | grep node| grep G| cut -d ':' -f 2 | cut -c 3-7"
$Splash="Welcome"
Write-Host "$Splash" -NoNewline

$key = "network"
$PiNodeEntry["NetworkPhase"] = Get-ConsensusValue $ff $key

$text = " instance is connecting to"
if ([string]::IsNullOrEmpty($PiNodeEntry["NodeName"])) {Write-Host "$global:CurrentNodeName"}
else
{
    $name=-join(" ", $PiNodeEntry["NodeName"])
    Write-Host $name -NoNewline -f Green
    Write-Host $PiNodeEntry["NodeType"] -NoNewline -f Magenta
    $t=-join(" ", $PiNodeEntry["NodeName"], " ", $PiNodeEntry["NodeType"])
    $tt=-join($Splash, $t, $text, $PiNodeEntry["NetworkPhase"])
    Write-Log $tt
    Write-Host $text $PiNodeEntry["NetworkPhase"]
}
Write-Host "`n"

# List port mappings or a specific mapping for the container
$dockerContainerCommand = "port", "inspect"
$dockerContainerCommand | ForEach-Object {Write-Host "$_ " -NoNewline; dockerWrapper2($_)}

# Displays system wide information regarding the Docker installation.
#   show all containers with its size
$dockerCommand = "-D info", "context ls", "network ls --no-trunc", "image list", "ps --all --size"
$dockerCommand | ForEach-Object {Write-Host "$_ " -NoNewline; dockerWrapper($_)}

# Run a batch of stellar core http commands
$stellarHttpCommand = "info", "peers", "bans", "metrics", `
                      "quorum", "quorum?transitive=true", `
                      "getcursor", "scp", "upgrades?mode=get", `
                      "ll"
$stellarHttpCommand | ForEach-Object { Write-Host "$_ " -NoNewline; dshWrapper($_)}

Write-Log "Get-PSDrive C"
$s = Get-PSDrive C
$s | Out-File -Append -Encoding utf8 -FilePath $LogFile

Write-Host "`n"
$text = ""
$key = "ledger"
$PiNodeEntry["QuorumLedger"] = Get-ConsensusValue $ff $key
$text=-join("Quorum ledger:", [string]$PiNodeEntry["QuorumLedger"])
Write-Host $text
Write-Log $text

$key = "num"
$PiNodeEntry["LocalBlkNum"] = Get-ConsensusValue $ff $key
$text=-join("Local blocknum:", [string]$PiNodeEntry["LocalBlkNum"])
Write-Host $text
Write-Log $text

# The last ledger in which the transitive closure was checked for quorum intersection. 
# This will reset when the node boots and 
#     whenever a node in the transitive quorum changes its quorum set. 
# It may lag behind the last-closed ledger by a few ledgers 
#     depending on the computational cost of checking quorum intersection.
$key = "last_check_ledger"
$PiNodeEntry["LastBlkNum"] = Get-ConsensusValue $ff $key
$text=-join("Last blocknum:", [string]$PiNodeEntry["LastBlkNum"])
Write-Host $text
Write-Log $text

$key = "age"
$tmp = Get-ConsensusValue $ff $key
$state = "Green"
$ts =  [timespan]::fromseconds($tmp)
$PiNodeEntry["LedgeAge"] = $ts.ToString("hh\:mm\:ss\,fff")
if ([int]$tmp -gt 10) {$state = "Red"}
$text=-join("Time to latest block: ", $PiNodeEntry["LedgeAge"])
Write-Host2-With-Color -text "Time to latest block: ", $PiNodeEntry["LedgeAge"] -color White, "$state"
Write-Log $text

# connections that are not fully established yet
$key = "pending_count"
$PiNodeEntry["PendingPeers"] = Get-ConsensusValue $ff $key
if ($PiNodeEntry["PendingPeers"] -eq " ") {$PiNodeEntry["PendingPeers"] = 0}
$text=-join("Pending connections: ", [string]$PiNodeEntry["AuthenPeers"])
Write-Host $text
Write-Log $text
$key = "authenticated_count"
$PiNodeEntry["AuthenPeers"] = Get-ConsensusValue $ff $key
$text=-join("Live outgoing/incoming connections:", [string]$PiNodeEntry["AuthenPeers"])
Write-Host $text
Write-Log $text

$key = "protocol_version"
$PiNodeEntry["ProtocolVersion"] = Get-ConsensusValue $ff $key
$text=-join("Stellar-core protocol version:", [string]$PiNodeEntry["ProtocolVersion"])
Write-Host2-With-Color -text "Stellar-core protocol version:", $PiNodeEntry["ProtocolVersion"] -color White, "Magenta"
Write-Log $text

#$key = "history_failure_rate"
#$PiNodeEntry["ErrorRate"] = Get-ConsensusValue $ff $key
#$text=-join("Session error rate:", $PiNodeEntry["ErrorRate"])
#Write-Host $text
#Write-Log $text

$key = "critical"
$PiNodeEntry["QuorumIntersection"] = Get-ConsensusValue $ff $key
$state = "Red"
if ($PiNodeEntry["QuorumIntersection"] -match "null") {$PiNodeEntry["QuorumIntersection"] = " Healthy"; $state = "Green"}
$text=-join("Quorum state:", $PiNodeEntry["QuorumIntersection"])
Write-Log $text
Write-Host2-With-Color -text "Quorum state:", $PiNodeEntry["QuorumIntersection"] -color White, "$state"

# We have 04 states i.e: N/A, Catching up, Joining SCP, Synced!
$key = "state"
$tmp = Get-ConsensusValue $ff $key
if ([string]::IsNullOrEmpty($tmp)) {$tmp = "N/A"; Write-Host "ERROR: Cannot check state" -ForegroundColor Red}
else
{
    #Write-Host "$tmp"
    if ($tmp -match "Catching up" -or $tmp -match "Joining SCP")
    {
        $tmp = bash -c "cat $ff | grep checkpoints"
        if ([string]::IsNullOrEmpty($tmp))
        {
            Write-Host "Warning: Catching or Joining SCP state" -ForegroundColor Red
            $tmp = " Catching up"
        }
        else
        {
            $tmp = $tmp.trim()
        }
    }
}
$PiNodeEntry["ConsensusState"] = $tmp
$text=-join("Consensus state:", [string]$PiNodeEntry["ConsensusState"])
Write-Log $text
Write-Host2-With-Color -text "Consensus state:", $PiNodeEntry["ConsensusState"] -color White, Green

$state = "Green"
$key = "intersection"
$tmp = Get-ConsensusValue $ff $key
if ($tmp -eq " false") {$state = "Red"; $tmp = "network split. Quorum misconfigured"}
$PiNodeEntry["QuorumIntersection"] = $tmp
$text=-join("intersection:", [string]$PiNodeEntry["QuorumIntersection"])
Write-Host2-With-Color -text "Quorum intersection:", $PiNodeEntry["QuorumIntersection"] -color White, "$state"
Write-Log $text

$key = "missing"
$tmp = Get-ConsensusValue $ff $key
if ([int]$tmp -gt 0) {$state = "Red"; Write-Host "Number of missing node: $tmp" -ForegroundColor Red}
Write-Log "Number of missing node:$tmp"

$key = "agree"
$tmp = Get-ConsensusValue $ff $key
if ([string]::IsNullOrEmpty($tmp)) {$tmp = 0; Write-Host "ERROR: Cannot check node agreed" -ForegroundColor Red}
$PiNodeEntry["QuorumNodeAgreed"] = $tmp
switch ([int]$tmp)
{
    0 {$state = "Magenta"}
    1 {$state = "Red"}
    2 {$state = "Yellow"}
    default {$state = "Green"}
}
$text=-join("Now ", $tmp, " Pi node(s) agreed with yours")
Write-Host $text -ForegroundColor $state
Write-Log $text

$key = "lag_ms"
$tmp = Get-ConsensusValue $ff $key
if ([string]::IsNullOrEmpty($tmp)) {Write-Host "ERROR: Cannot check network latency" -ForegroundColor Red}
else
{
    switch ([int]$tmp)
    {
        # G. 114 [protocol] recommendation
        {$_ -le 150} {$state = "Green"}
        {$_ -ge 151 -and $_ -le 230} {$state = "Yellow"}
        {$_ -ge 231 -and $_ -le 330} {$state = "Red"}
        {$_ -ge 331 -and $_ -le 530} {$state = "Magenta"}
        default {$state = "DarkMagenta"}
    }
    $PiNodeEntry["NetworkLatency"] = $tmp
    $text=-join("Network latency:", [string]$PiNodeEntry["NetworkLatency"], "ms")
    Write-Host2-With-Color -text "Network latency: ", $PiNodeEntry["NetworkLatency"], " ms" -color White, "$state", White
    Write-Log $text
}
Write-Host ""
Write-Host "Docker NETwork Input/Output"
# "table {{.ID}}\t{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
Write-Log "docker stats $PICONTAINER"
$s=docker stats $PICONTAINER --format "table {{.NetIO}}\t{{.CPUPerc}}\t{{.MemUsage}}" --no-stream --no-trunc
$s | Out-File -Append -Encoding utf8 -FilePath $LogFile
$s

Write-Host ""
$key = "startedOn"
$PiNodeEntry["startedOn"] = Get-ConsensusValue $ff $key
$text=-join("Docker restart date:", [string]$PiNodeEntry["startedOn"])
Write-Host2-With-Color -text "Docker restart date: ", $PiNodeEntry["startedOn"] -color White, Green
Write-Log $text

$disk=Get-PSDrive C|Select-Object Free
$d=$disk.Free/1GB
$state = "Green"
switch ([int]$d)
{
    {$_ -gt 150} {$state = "Green"}
    {$_ -le 150 -and $_ -gt 100} {$state = "Yellow"}
    {$_ -le 100 -and $_ -gt 50}  {$state = "Red"}
    {$_ -le 50  -and $_ -gt 10} {$state = "Magenta"}
    default {$state = "DarkMagenta"}
}
Write-Host2-With-Color -text "HDD free space: ", $d, " GB" -color White, "$state", Green
Write-Log "HDD free space: $d GB"

Write-Log " "
Write-Log "netstat -aonb | findstr 3140"
$s=(netstat -aonb | findstr 3140)
$s | Out-File -Append -Encoding utf8 -FilePath $LogFile

# Fetch docker log
$dockerContainerCommand = "logs --details"
$dockerContainerCommand | ForEach-Object {dockerWrapper2($_)}

Write-Log "User preferences json file"
Save-TextToLogFile -Text "$PIDIR\user-preferences.json" -Log $LogFile
Write-Log " "

Write-Log "Docker compose json file"
Save-TextToLogFile -Text "$PIDIR\docker-compose.json" -Log $LogFile
Write-Log " "

Write-Log "testnet2 env file"
Save-TextToLogFile -Text "$PIDIR\testnet2.env" -Log $LogFile
Write-Log " "

Write-Log "stellar env file"
Save-TextToLogFile -Text "$PIDIR\stellar.env" -Log $LogFile
Write-Log " "

# stellar\core\etc\stellar-core.cfg
# https://github.com/stellar/stellar-core/blob/1812c4fc355cc1d878ad8e2bb62352f4e28cd2ea/docs/stellar-core_example.cfg#L203
Write-Log "stellar core file stellar-core.cfg"
if (Test-Path -Path $StellarConfig -PathType Leaf)
{
    Get-Content $StellarConfig -Raw | Out-File -Append -Encoding utf8 -FilePath $LogFile
}

$seed = Get-ValueFromKeyPattern -FilePath $StellarConfig -KeyPattern "NODE_SEED"
Write-Log "Node seed $seed"
# Run a batch of stellar core commands
$dockerCoreCommand = "convert-id $seed", "version"
$dockerCoreCommand | ForEach-Object {Write-Host "$_ " -NoNewline; dshCore($_)}

Write-Log ""
if ($global:verbose -eq $true)
{
    Write-Host "`n"
    Write-Host "Saving Node Id, peer ipaddr to log...Wait a moment please"
    # Backticks for line breaks
    #dir $PIDIR\docker_volumes\stellar\postgresql\data\base -Recurse | `
    # testnet1
    #dir $PIDIR\docker_volumes\stellar\postgresql\data\base | `
    # testnet2
    dir $PIDIR\docker_volumes\$t2\stellar\postgresql\data\base | `
        Select-String -pattern $PiNodeEntry["NodeName"] | `
        Select-Object -Last 1 | `
        Out-File -Append -Encoding utf8 -FilePath $LogFile
        
}

# Check authenticated peer ip addresses
Get-PeerData ($PiNodeEntry["AuthenPeers"])

Write-Host "`nDone! Double check log at $LogFile ..."
dir $Logfile
if (Test-Path -Path $Ftmp -PathType Leaf)
{
    #Remove-Item -Path .\tmp*.tmp -Force
    Remove-Item -Path $Ftmp -Force
}
Write-Host ""
Write-Host "Success!"
exit 0
