#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$IrPath,
    [Parameter(Mandatory = $true)][string]$WorkParent
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This launcher requires Windows. Use the Go harness directly on other platforms.' }
$binary = Get-Item -LiteralPath $IrPath
$parent = Get-Item -LiteralPath $WorkParent
if ($binary.PSIsContainer -or ($binary.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'IrPath must be an existing regular executable, not a reparse point.'
}
if (-not $parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'WorkParent must be an existing trusted private directory, not a reparse point.'
}
$go = Get-Command go -CommandType Application -ErrorAction Stop
$harness = Join-Path $PSScriptRoot 'package-acceptance.go'
$private = Join-Path $parent.FullName ('ir-package-acceptance-private-' + [Guid]::NewGuid().ToString('N'))
# Never modify the caller's parent ACL. No cleanup, recursive deletion or lock recovery.
$null = New-Item -ItemType Directory -Path $private -ErrorAction Stop
try {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $sid, [Security.AccessControl.FileSystemRights]::FullControl,
        ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $private -AclObject $acl
    $actual = Get-Acl -LiteralPath $private
    if (-not $actual.AreAccessRulesProtected) { throw 'The new work directory did not acquire a protected DACL.' }
    $rules = @($actual.Access)
    if ($rules.Count -ne 1 -or $rules[0].IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or
        $rules[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $rules[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
        throw 'The new work directory DACL does not match the current-user-only rule.'
    }
    $environment = [ordered]@{
        windows_version = [Environment]::OSVersion.VersionString
        os_architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        process_architecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        powershell_version = $PSVersionTable.PSVersion.ToString()
        user_sid = $sid.Value
        private_directory = $private
        dacl_sddl = $actual.Sddl
        ir_executable = $binary.FullName
    }
    $environment | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $private 'windows-environment.json') -Encoding utf8NoBOM
    # The harness records every expected rejection's native exit code itself.
    $PSNativeCommandUseErrorActionPreference = $false
    & $go.Source run $harness -ir $binary.FullName -work-parent $private
    if ($LASTEXITCODE -ne 0) { throw "Acceptance failed with exit $LASTEXITCODE; inspect retained artifacts." }
} finally {
    Write-Host "Windows acceptance directory retained: $private"
}
