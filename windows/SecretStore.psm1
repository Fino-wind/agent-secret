Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-SecretPath([string] $Name) {
    if ($Name -cnotmatch '\A[a-zA-Z0-9_.-]{1,128}\z') { throw 'Invalid secret name.' }
    # Prefix avoids Windows reserved device names and trailing-dot ambiguity.
    Join-Path (Join-Path $env:LOCALAPPDATA 'agent-secret') ("secret.$Name.dpapi")
}

function Save-AgentSecret([string] $Name, [Security.SecureString] $Value) {
    $path = Get-SecretPath $Name
    if ($null -eq $Value -or $Value.Length -eq 0) { throw 'Empty value; nothing stored.' }
    $directory = [IO.Path]::GetDirectoryName($path)
    [void][IO.Directory]::CreateDirectory($directory)
    if ((Get-Item -LiteralPath $directory).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Secret directory must not be a link.'
    }
    $acl = Get-Acl -LiteralPath $directory
    $acl.SetAccessRuleProtection($true, $false)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($existing in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($existing) }
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    $directoryInfo = [IO.DirectoryInfo]::new($directory)
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        [IO.FileSystemAclExtensions]::SetAccessControl($directoryInfo, $acl)
    } else { $directoryInfo.SetAccessControl($acl) }
    $temporary = Join-Path $directory ([Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        # On Windows, no -Key means DPAPI CurrentUser, not portable encryption.
        $encrypted = ConvertFrom-SecureString -SecureString $Value
        [IO.File]::WriteAllText($temporary, $encrypted)
        if ([IO.File]::Exists($path)) {
            $backup = $temporary + '.bak'
            try { [IO.File]::Replace($temporary, $path, $backup) }
            finally { if ([IO.File]::Exists($backup)) { [IO.File]::Delete($backup) } }
        }
        else { [IO.File]::Move($temporary, $path) }
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Read-AgentSecret([string] $Name) {
    $path = Get-SecretPath $Name
    if (-not [IO.File]::Exists($path)) { throw 'Secret not found.' }
    ConvertTo-SecureString -String ([IO.File]::ReadAllText($path))
}

function Get-AgentSecretNames {
    $directory = Join-Path $env:LOCALAPPDATA 'agent-secret'
    if (Test-Path -LiteralPath $directory) {
        Get-ChildItem -LiteralPath $directory -Filter 'secret.*.dpapi' -File |
            ForEach-Object { $_.Name.Substring(7, $_.Name.Length - 13) } | Sort-Object
    }
}

function Remove-AgentSecret([string] $Name) {
    [IO.File]::Delete((Get-SecretPath $Name))
}

Export-ModuleMember -Function Save-AgentSecret, Read-AgentSecret, Get-AgentSecretNames, Remove-AgentSecret
