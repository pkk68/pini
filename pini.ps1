#requires -version 5.0
$DATE = Get-Date
$FileLogDate = (Get-Date -f yyyy-MM-dd-HH-mm-ss)
$global:CurrentNodeName = "PiNode"
Set-Variable -Name PICONTAINER -Value "pi-consensus" -Option Constant, AllScope -Force
Set-Variable -Name HTTP_PORT -Value "11626" -Option Constant, AllScope -Force

$PIDIR = "C:\Users\$env:UserName\AppData\Roaming\Pi Network"
$PiNodeEntry = @{ NodeName = "GD"; `
NodeType = " watcher"; `
StellarBuild = "StellarCoreBuild"; `
ErrorRate = "0"; `
NetworkPhase = "Pi Testnet"; `
LedgeAge = "1"; `
LocalBlkNum = "3000000"; `
QuorumLedger = "3000000"; `
LastBlkNum = "3000000"; `
QuorumState = "null"; `
AuthenPeers = "64"; `
PendingPeers = "8"; `
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
$VERSION = "0.02.20210913"
$StellarConfig = "$PIDIR\docker_volumes\stellar\core\etc\stellar-core.cfg"

$options = @{
    opt1 = [bool] 0
}
$help = @"
    PINode Information usage: pini [-h] [-v]
 
    Pi Node Information v.0.02.20210913
 
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
        Write-Error -Message $msg -Category ObjectNotFound
    }
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
    $d = docker --version
    $d | Out-File -Append -Encoding utf8 -FilePath $LogFile
    Write-Host "$d"
    $d = docker version
    $d | Out-File -Append -Encoding utf8 -FilePath $LogFile

    $d = docker-compose  --version
    $d | Out-File -Append -Encoding utf8 -FilePath $LogFile
    Write-Host "$d"

    Write-Host "           Pi App & vmmem"
    Is-AppRunning("vmmem")
    Is-AppRunning("Pi Network")
    Write-Host "           " -NoNewLine
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
    Write-Log "$c"
    Run-Command($c) | Out-File -Append -Encoding utf8 -FilePath $LogFile
}
function dockerWrapper ($opt)
{
    Write-Host ""
    $cc="docker "
    $c = -join($cc, " ", $opt)
    Write-Log "$c"
    Run-Command($c) | Out-File -Append -Encoding utf8 -FilePath $LogFile
}
function dockerWrapper2 ($opt)
{
    $cc="docker "
    $c = -join($cc, " ", $opt, " ", $PICONTAINER)
    Write-Log "$c"
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

###############################################################################
#                       S C R I P T  E X E C U T I O N                        #
###############################################################################
$Title = "Pi node information v$VERSION"


$argv,$options = Parse-Option $args $options
if ($options.opt1)
{
    $global:verbose=$true
}

New-Item -Path 'C:\' -Name "$CurrentNodeName-$FileLogDate.txt" -ItemType File | Out-Null
$LogFile = "C:\$CurrentNodeName-$FileLogDate.txt"
$Ftmp = "tmp$(get-date -Format 'yyyy-MMM-dd-hh-mm-ss-tt').tmp"

Write-Host ""
Write-Host $Title -ForegroundColor Magenta
Write-Host ""
Write-Log $Title

Get-OSInformation

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
$PiNodeEntry["NodeType"] = " watcher"
if (Test-Path -Path $StellarConfig -PathType Leaf)
{
    # https://developers.stellar.org/docs/run-core-node/
    # https://developers.stellar.org/docs/run-core-node/configuring/
    $tmp = Get-ChildItem -Path $StellarConfig | Select-String -Pattern 'NODE_IS_VALIDATOR=' -CaseSensitive
    $type = ($tmp -split '=')[1]
    if ($type -eq "true") {$PiNodeEntry["NodeType"] = " validator"}
}

Write-Host "`nChecking Pi node & pi-consensus..."
docker exec -ti $PICONTAINER bash -c "stellar-core http-command info" | Out-File -Append -Encoding utf8 -FilePath $Ftmp
if (-Not (Test-Path -Path $Ftmp -PathType Leaf))
{
    Write-Error "ERROR: Cannot fetch pi-consensus information"
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
if ([string]::IsNullOrEmpty($PiNodeEntry["NodeName"])) {Write-Host "$CurrentNodeName"}
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

Write-Log "docker exec -ti $PICONTAINER stellar-core http-command ll?level=debug"
$s = docker exec -ti $PICONTAINER stellar-core http-command ll?level=debug
$s | Out-File -Append -Encoding utf8 -FilePath $LogFile

# List port mappings or a specific mapping for the container
$dockerContainerCommand = "port", "inspect"
$dockerContainerCommand | ForEach-Object {Write-Host "$_ " -NoNewline; dockerWrapper2($_)}

# Displays system wide information regarding the Docker installation.
$dockerCommand = "-D info", "context ls", "network ls --no-trunc", "ps --all --size"
$dockerCommand | ForEach-Object {Write-Host "$_ " -NoNewline; dockerWrapper($_)}

# Run a batch of stellar core http commands
$stellarHttpCommand = "info", "peers", "bans", "metrics", "quorum", "quorum?transitive=true", "getcursor", "scp"
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

$key = "history_failure_rate"
$PiNodeEntry["ErrorRate"] = Get-ConsensusValue $ff $key
$text=-join("Session error rate:", $PiNodeEntry["ErrorRate"])
Write-Host $text
Write-Log $text

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
if ([string]::IsNullOrEmpty($tmp)) {Write-Host "ERROR: Cannot check state" -ForegroundColor Red}
else
{
    #Write-Host "$tmp"
    if ($tmp -match "Catching up" -or $tmp -match "Joining SCP")
    {
        $tmp = bash -c "cat $ff | grep checkpoints"
        if ([string]::IsNullOrEmpty($tmp))
        {
            Write-Host "Warning: Catching or joining SCP state" -ForegroundColor Red
            $tmp = "Catching up"
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
$text=-join("Now", $tmp, " Pi node(s) agreed with yours")
Write-Host $text -ForegroundColor $state
Write-Log $text

$key = "lag_ms"
$tmp = Get-ConsensusValue $ff $key
if ([string]::IsNullOrEmpty($tmp)) {Write-Host "ERROR: Cannot check network latency" -ForegroundColor Red}
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

Write-Log "netstat -aonb | findstr 3140"
$s=(netstat -aonb | findstr 3140)
$s | Out-File -Append -Encoding utf8 -FilePath $LogFile

# Fetch docker log
$dockerContainerCommand = "logs --details"
$dockerContainerCommand | ForEach-Object {dockerWrapper2($_)}

$UserPreferences = "$PIDIR\user-preferences.json"
if (Test-Path -Path $UserPreferences -PathType Leaf)
{
    Get-Content $UserPreferences | Out-File -Append -Encoding utf8 -FilePath $LogFile
}
Write-Log " "

if (Test-Path -Path $StellarConfig -PathType Leaf)
{
    Get-Content $StellarConfig | Out-File -Append -Encoding utf8 -FilePath $LogFile
}
Write-Log ""
if ($global:verbose -eq $true)
{
    Write-Host "Saving Node Id to log...Wait 2 minutes please"
    # Backticks for line breaks
    dir $PIDIR\docker_volumes\stellar\postgresql\data\base -Recurse | `
        Select-String -pattern $PiNodeEntry["NodeName"] | `
        Select-Object -Last 1 | `
        Out-File -Append -Encoding utf8 -FilePath $LogFile
}

Write-Host "Done! Double check log at $LogFile ..."
dir $Logfile
if (Test-Path -Path $Ftmp -PathType Leaf)
{
    #Remove-Item -Path .\tmp*.tmp -Force
    Remove-Item -Path $Ftmp -Force
}
Write-Host ""
Write-Host "Success!"
exit 0
