$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SecretStore.psm1') -Force
$originalData = $env:LOCALAPPDATA
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('agent-secret-test-' + [Guid]::NewGuid().ToString('N'))
$env:LOCALAPPDATA = $testRoot
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
try {
    $dummy = 'dummy-only-' + [char]0x4e2d + ' $ ` " spaces'
    $value = ConvertTo-SecureString $dummy -AsPlainText -Force
    Save-AgentSecret 'test.key' $value
    $value.Dispose()
    $encrypted = [IO.File]::ReadAllText((Join-Path $testRoot 'agent-secret\secret.test.key.dpapi'))
    Assert (-not $encrypted.Contains($dummy)) 'Plaintext on disk'
    $loaded = Read-AgentSecret 'test.key'
    Assert (([Net.NetworkCredential]::new('', $loaded)).Password -ceq $dummy) 'Round trip failed'
    $loaded.Dispose()
    Assert (@(Get-AgentSecretNames).Count -eq 1) 'Listing failed'
    $replacement = ConvertTo-SecureString 'replacement-dummy' -AsPlainText -Force
    Save-AgentSecret 'test.key' $replacement
    $replacement.Dispose()
    $loaded = Read-AgentSecret 'test.key'
    Assert (([Net.NetworkCredential]::new('', $loaded)).Password -eq 'replacement-dummy') 'Overwrite failed'
    $loaded.Dispose()
    foreach ($invalid in @('../escape', '', 'a/b', 'x:y')) {
        $rejected = $false
        try { Read-AgentSecret $invalid | Out-Null } catch { $rejected = $true }
        Assert $rejected 'Invalid name accepted'
    }
    $empty = New-Object Security.SecureString
    $rejected = $false
    try { Save-AgentSecret 'test.key' $empty } catch { $rejected = $true }
    $empty.Dispose()
    Assert $rejected 'Empty value accepted'
    [IO.File]::WriteAllText((Join-Path $testRoot 'agent-secret\secret.broken.dpapi'), 'corrupt')
    $rejected = $false
    try { Read-AgentSecret 'broken' | Out-Null } catch { $rejected = $true }
    Assert $rejected 'Corruption accepted'
    Remove-AgentSecret 'broken'
    Remove-AgentSecret 'test.key'
    Remove-AgentSecret 'test.key'
    Assert (@(Get-AgentSecretNames).Count -eq 0) 'Delete failed'
    Write-Output 'PASS: encrypted storage, Unicode round trip, overwrite, names, invalid input, empty value, corruption and deletion.'
} finally {
    $env:LOCALAPPDATA = $originalData
    # Delete only the uniquely created test directory, never the real store.
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
