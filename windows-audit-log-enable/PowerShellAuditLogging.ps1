#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Configures Windows log auditing in one script: advanced audit policy, process command-line
    logging and PowerShell logging.

.DESCRIPTION
    Replaces ScriptEventLog.ps1 and Invoke-CYNPowerShellAuditLogging.ps1.

    Run with no parameters (for example through PowerShellAuditLogging.bat) to apply everything:
      1. Advanced audit policy (auditpol, Success and Failure) for the event IDs in the guide
         WindowsLogAuditingConfiguration_v2.0A: 4720, 4624, 4625, 4648, 4776, 4656, 4663, 4698,
         4688, 4768, 4769 and 4770.
      2. Command line in process creation events (4688).
      3. PowerShell Script Block Logging (4104), Module Logging and Transcription for Windows
         PowerShell, and Script Block Logging for PowerShell 7.
      4. The transcript folder (default C:\logs), restricted to Administrators and SYSTEM.
      5. A self-check that a new PowerShell session produces a 4104 event.

    These are LOCAL settings. A domain GPO that defines the same settings overwrites them at the
    next policy refresh, so use this script on standalone or test hosts and the GPO (see the
    guide) for domain systems.

    To use only the function, dot-source the file. Nothing runs when it is dot-sourced:
        . .\PowerShellAuditLogging.ps1
        Invoke-PowerShellAuditLogging -Method DisableAllLogging

.PARAMETER Method
    ApplyAll                  Audit policy plus all PowerShell logging (default).
    AuditPolicy               Audit policy only.
    ScriptBlockLogging        Windows PowerShell Script Block Logging.
    ModuleLogging             Windows PowerShell Module Logging.
    TranscriptLogging         Windows PowerShell Transcription.
    EnableAllLogging          All PowerShell logging, process command line, and the self-check.
    DisableAllLogging         Remove the PowerShell logging settings. The log folder is kept.
    ProcessCreateWithCmdline  Process creation auditing with the command line.
    Pwsh7ScriptBlockLogging, Pwsh7ModuleLogging, Pwsh7TranscriptLogging
                              The same features for PowerShell 7.
    InstallPwSh7              Download and install PowerShell 7 (runs Microsoft's install script).

.PARAMETER TranscriptLogPath
    Folder for PowerShell transcripts. Default: C:\logs

.PARAMETER SkipTranscriptAcl
    Do not change the permissions of the transcript folder. Use this when the folder is shared
    with other logs, because the default permissions allow only Administrators and SYSTEM.

.EXAMPLE
    .\PowerShellAuditLogging.ps1

    Apply the audit policy and all PowerShell logging.

.EXAMPLE
    .\PowerShellAuditLogging.ps1 -Method EnableAllLogging -TranscriptLogPath D:\logs

    Enable the PowerShell logging only, with transcripts in D:\logs.

.NOTES
    Run as Administrator. Script Block, Module and Transcription settings apply to PowerShell
    sessions started after the script runs.

    Originated from Tim Ip's powershell_logging.ps1 (https://github.com/timip/splunk).
#>
[CmdletBinding()]
param(
    [ValidateSet('ApplyAll', 'AuditPolicy', 'ScriptBlockLogging', 'ModuleLogging', 'TranscriptLogging',
                 'EnableAllLogging', 'DisableAllLogging', 'ProcessCreateWithCmdline',
                 'Pwsh7ScriptBlockLogging', 'Pwsh7ModuleLogging', 'Pwsh7TranscriptLogging', 'InstallPwSh7')]
    [string]$Method = 'ApplyAll',

    [string]$TranscriptLogPath = 'C:\logs',

    [switch]$SkipTranscriptAcl
)

$script:Failures = 0

# Windows PowerShell policy keys. 64-bit PowerShell reads the native key; 32-bit PowerShell
# reads the Wow6432Node key. Both are written so either one is logged.
$script:WinPsPolicyRoots = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell',
    'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell'
)
$script:Ps7PolicyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore'
$script:CmdLineAuditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'

# Modules to log. The guide lists 'Microsoft.PowerShell.*' and 'Microsoft.WSMan.Management';
# '*' logs every module (more events). Change this list to match the guide if needed.
$script:ModuleLoggingNames = @('*')

# Advanced audit policy subcategories and the event IDs they produce (as grouped in the guide)
$script:AuditSubcategories = @(
    @{ Name = 'User Account Management';            Events = '4720' }
    @{ Name = 'Logon';                              Events = '4624, 4625, 4648' }
    @{ Name = 'Credential Validation';              Events = '4776' }
    @{ Name = 'File System';                        Events = '4656' }
    @{ Name = 'Registry';                           Events = '4656' }
    @{ Name = 'SAM';                                Events = '4656' }
    @{ Name = 'Handle Manipulation';                Events = '4656' }
    @{ Name = 'Removable Storage';                  Events = '4656' }
    @{ Name = 'Kernel Object';                      Events = '4663' }
    @{ Name = 'Other Object Access Events';         Events = '4698' }
    @{ Name = 'Process Creation';                   Events = '4688' }
    @{ Name = 'Kerberos Authentication Service';    Events = '4768' }
    @{ Name = 'Kerberos Service Ticket Operations'; Events = '4769, 4770' }
)

#region Helpers

function Write-Status {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info', 'Ok', 'Fail', 'Warn')][string]$Level = 'Info'
    )
    switch ($Level) {
        'Ok'    { Write-Host "[+] $Message" -ForegroundColor Green }
        'Fail'  { Write-Host "[-] $Message" -ForegroundColor Red; $script:Failures++ }
        'Warn'  { Write-Host "[!] $Message" -ForegroundColor Yellow }
        default { Write-Host "[*] $Message" -ForegroundColor Cyan }
    }
}

function Set-PolicyValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord', 'String')][string]$Type = 'DWord'
    )
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

function Remove-PolicyValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    if (Test-Path -Path $Path) {
        Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
    }
}

function New-TranscriptFolder {
    # Creates the transcript folder and, unless -SkipAcl is given, limits it to
    # Administrators and SYSTEM (inheritance removed).
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$SkipAcl
    )
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    if ($SkipAcl) {
        Write-Status "Transcript folder $Path ready (permissions left unchanged)"
        return
    }
    $acl = Get-Acl -Path $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM') {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.SetAccessRule($rule)
    }
    Set-Acl -Path $Path -AclObject $acl
    Write-Status "Transcript folder $Path ready (Administrators and SYSTEM only)"
}

function Set-ScriptBlockPolicy {
    param([Parameter(Mandatory)][string[]]$Roots)
    foreach ($root in $Roots) {
        Set-PolicyValue -Path "$root\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -Value 1
        Set-PolicyValue -Path "$root\ScriptBlockLogging" -Name 'EnableScriptBlockInvocationLogging' -Value 1
    }
}

function Set-ModuleLoggingPolicy {
    param([Parameter(Mandatory)][string[]]$Roots)
    foreach ($root in $Roots) {
        Set-PolicyValue -Path "$root\ModuleLogging" -Name 'EnableModuleLogging' -Value 1
        foreach ($module in $script:ModuleLoggingNames) {
            Set-PolicyValue -Path "$root\ModuleLogging\ModuleNames" -Name $module -Value $module -Type String
        }
    }
}

function Set-TranscriptionPolicy {
    param(
        [Parameter(Mandatory)][string[]]$Roots,
        [Parameter(Mandatory)][string]$Directory
    )
    foreach ($root in $Roots) {
        Set-PolicyValue -Path "$root\Transcription" -Name 'EnableInvocationHeader' -Value 1
        Set-PolicyValue -Path "$root\Transcription" -Name 'EnableTranscripting' -Value 1
        Set-PolicyValue -Path "$root\Transcription" -Name 'OutputDirectory' -Value $Directory -Type String
    }
}

#endregion

#region Audit policy

function Set-AuditPolicy {
    Write-Status 'Applying advanced audit policy (Success and Failure)'
    foreach ($item in $script:AuditSubcategories) {
        $output = auditpol /set /subcategory:"$($item.Name)" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Status "$($item.Name) (events $($item.Events))" 'Ok'
        }
        else {
            Write-Status "$($item.Name): auditpol failed. $output" 'Fail'
        }
    }
}

function Invoke-PSAuditProcessCreationCmdLine {
    Write-Status 'Enabling process creation auditing with the command line (event 4688)'
    $null = auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Status 'auditpol failed for Process Creation' 'Fail'
    }
    Set-PolicyValue -Path $script:CmdLineAuditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1
}

#endregion

#region Windows PowerShell logging

function Invoke-PSAuditScriptBlockLogging {
    Write-Status 'Enabling PowerShell Script Block Logging'
    Set-ScriptBlockPolicy -Roots $script:WinPsPolicyRoots
}

function Invoke-PSAuditModuleLogging {
    Write-Status 'Enabling PowerShell Module Logging'
    Set-ModuleLoggingPolicy -Roots $script:WinPsPolicyRoots
}

function Invoke-PSAuditTranscriptLogging {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$SkipAcl
    )
    Write-Status "Enabling PowerShell Transcription (output: $Path)"
    New-TranscriptFolder -Path $Path -SkipAcl:$SkipAcl
    Set-TranscriptionPolicy -Roots $script:WinPsPolicyRoots -Directory $Path
}

#endregion

#region PowerShell 7 logging

function Invoke-PSAuditPS7ScriptBlockLogging {
    Write-Status 'Enabling PowerShell 7 Script Block Logging'
    Set-ScriptBlockPolicy -Roots @($script:Ps7PolicyRoot)
}

function Invoke-PSAuditPS7ModuleLogging {
    Write-Status 'Enabling PowerShell 7 Module Logging'
    Set-ModuleLoggingPolicy -Roots @($script:Ps7PolicyRoot)
}

function Invoke-PSAuditPS7TranscriptLogging {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$SkipAcl
    )
    Write-Status "Enabling PowerShell 7 Transcription (output: $Path)"
    New-TranscriptFolder -Path $Path -SkipAcl:$SkipAcl
    Set-TranscriptionPolicy -Roots @($script:Ps7PolicyRoot) -Directory $Path
}

function Install-PwSh7 {
    # Runs Microsoft's documented install script with administrator rights.
    Write-Status 'Installing PowerShell 7 (a prompt will appear)'
    Invoke-Expression "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI"
    & 'C:\Program Files\PowerShell\7\RegisterManifest.ps1'
    & 'C:\Program Files\PowerShell\7\InstallPSCorePolicyDefinitions.ps1'
}

#endregion

#region Check, enable all, disable all

function Invoke-PSAuditCheck {
    # Starts a NEW Windows PowerShell process (the policy applies to new sessions) and looks for
    # its script block in the Operational log (event 4104).
    Write-Status 'Checking that Script Block Logging produces event 4104 in a new session'

    $marker = 'PSAuditCheck-' + [guid]::NewGuid().ToString('N')
    $start = Get-Date
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    & $powershell -NoProfile -Command "Write-Output '$marker'" | Out-Null
    Start-Sleep -Seconds 2

    $found = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-PowerShell/Operational'
        Id        = 4104
        StartTime = $start
    } -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*$marker*" }

    if ($found) {
        Write-Status 'Script Block Logging works: event 4104 found for the test session' 'Ok'
    }
    else {
        Write-Status ('No 4104 event found for the test session. Check the keys under ' +
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging and that the ' +
            'Microsoft-Windows-PowerShell/Operational log is enabled.') 'Fail'
    }
}

function Invoke-PSAuditAllLogging {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$SkipAcl
    )
    Write-Status 'Applying all PowerShell logging methods'
    Invoke-PSAuditScriptBlockLogging
    Invoke-PSAuditModuleLogging
    Invoke-PSAuditTranscriptLogging -Path $Path -SkipAcl:$SkipAcl
    Invoke-PSAuditProcessCreationCmdLine
    Invoke-PSAuditPS7ScriptBlockLogging
    Invoke-PSAuditCheck
}

function Invoke-PSAuditDisableAllLogging {
    # Removes the policy values. The transcript folder is NOT deleted, because it can hold
    # existing transcripts and may share a location with other logs.
    Write-Status 'Disabling PowerShell logging (the log folder and existing transcripts are kept)'
    foreach ($root in (@($script:WinPsPolicyRoots) + $script:Ps7PolicyRoot)) {
        Remove-PolicyValue -Path "$root\ScriptBlockLogging" -Name 'EnableScriptBlockLogging'
        Remove-PolicyValue -Path "$root\ScriptBlockLogging" -Name 'EnableScriptBlockInvocationLogging'
        Remove-PolicyValue -Path "$root\ModuleLogging" -Name 'EnableModuleLogging'
        if (Test-Path -Path "$root\ModuleLogging\ModuleNames") {
            Remove-Item -Path "$root\ModuleLogging\ModuleNames" -Recurse -Force
        }
        Remove-PolicyValue -Path "$root\Transcription" -Name 'EnableInvocationHeader'
        Remove-PolicyValue -Path "$root\Transcription" -Name 'EnableTranscripting'
        Remove-PolicyValue -Path "$root\Transcription" -Name 'OutputDirectory'
    }
    Remove-PolicyValue -Path $script:CmdLineAuditKey -Name 'ProcessCreationIncludeCmdLine_Enabled'
}

#endregion

function Invoke-PowerShellAuditLogging {
    <#
    .SYNOPSIS
        Enables, disables or checks PowerShell logging. See the script help for the methods.
    .EXAMPLE
        Invoke-PowerShellAuditLogging -Method EnableAllLogging -TranscriptLogPath C:\logs
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ScriptBlockLogging', 'ModuleLogging', 'TranscriptLogging', 'EnableAllLogging',
                     'DisableAllLogging', 'ProcessCreateWithCmdline', 'Pwsh7ScriptBlockLogging',
                     'Pwsh7ModuleLogging', 'Pwsh7TranscriptLogging', 'InstallPwSh7')]
        [string]$Method,

        [string]$TranscriptLogPath = 'C:\logs',

        [switch]$SkipTranscriptAcl
    )

    switch ($Method) {
        'ScriptBlockLogging'       { Invoke-PSAuditScriptBlockLogging }
        'ModuleLogging'            { Invoke-PSAuditModuleLogging }
        'TranscriptLogging'        { Invoke-PSAuditTranscriptLogging -Path $TranscriptLogPath -SkipAcl:$SkipTranscriptAcl }
        'EnableAllLogging'         { Invoke-PSAuditAllLogging -Path $TranscriptLogPath -SkipAcl:$SkipTranscriptAcl }
        'DisableAllLogging'        { Invoke-PSAuditDisableAllLogging }
        'ProcessCreateWithCmdline' { Invoke-PSAuditProcessCreationCmdLine }
        'Pwsh7ScriptBlockLogging'  { Invoke-PSAuditPS7ScriptBlockLogging }
        'Pwsh7ModuleLogging'       { Invoke-PSAuditPS7ModuleLogging }
        'Pwsh7TranscriptLogging'   { Invoke-PSAuditPS7TranscriptLogging -Path $TranscriptLogPath -SkipAcl:$SkipTranscriptAcl }
        'InstallPwSh7'             { Install-PwSh7 }
    }
}

# Main. Skipped when the file is dot-sourced so the functions can be loaded on their own.
if ($MyInvocation.InvocationName -ne '.') {
    switch ($Method) {
        'ApplyAll' {
            Set-AuditPolicy
            Invoke-PowerShellAuditLogging -Method EnableAllLogging -TranscriptLogPath $TranscriptLogPath -SkipTranscriptAcl:$SkipTranscriptAcl
        }
        'AuditPolicy' {
            Set-AuditPolicy
        }
        default {
            Invoke-PowerShellAuditLogging -Method $Method -TranscriptLogPath $TranscriptLogPath -SkipTranscriptAcl:$SkipTranscriptAcl
        }
    }

    if ($script:Failures -gt 0) {
        Write-Status "$($script:Failures) step(s) failed. Review the messages above." 'Warn'
        exit 1
    }
    Write-Status 'Done. New PowerShell sessions are now logged.' 'Ok'
    exit 0
}
