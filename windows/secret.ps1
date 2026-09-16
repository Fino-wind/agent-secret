# Windows PowerShell 5.1 or PowerShell 7 on Windows. No execution-policy changes.
param(
    [Parameter(Position=0)][string] $Command = 'help',
    [Parameter(Position=1)][string] $Name
)
$ErrorActionPreference = 'Stop'
try {
    if ($env:OS -ne 'Windows_NT') { throw 'This entry point requires Windows.' }
    Import-Module (Join-Path $PSScriptRoot 'SecretStore.psm1') -Force
    if ($Command -in @('set', 'get', 'rm') -and $Name -cnotmatch '\A[a-zA-Z0-9_.-]{1,128}\z') {
        throw 'Name must contain 1-128 letters, digits, underscores, dots or hyphens.'
    }
    switch ($Command) {
        'set' {
            Add-Type -AssemblyName System.Windows.Forms
            $form = New-Object Windows.Forms.Form
            try {
                $form.Text = 'Agent Secret Manager'
                $form.ClientSize = New-Object Drawing.Size(420, 145)
                $form.StartPosition = 'CenterScreen'
                $form.FormBorderStyle = 'FixedDialog'
                $form.MaximizeBox = $false
                $form.MinimizeBox = $false
                $label = New-Object Windows.Forms.Label
                $label.Text = "Enter secret: $Name"
                $label.SetBounds(16, 16, 388, 24)
                $inputBox = New-Object Windows.Forms.TextBox
                $inputBox.UseSystemPasswordChar = $true
                $inputBox.SetBounds(16, 46, 388, 24)
                $save = New-Object Windows.Forms.Button
                $save.Text = 'Save'
                $save.DialogResult = [Windows.Forms.DialogResult]::OK
                $save.SetBounds(224, 94, 85, 30)
                $cancel = New-Object Windows.Forms.Button
                $cancel.Text = 'Cancel'
                $cancel.DialogResult = [Windows.Forms.DialogResult]::Cancel
                $cancel.SetBounds(319, 94, 85, 30)
                $form.Controls.AddRange(@($label, $inputBox, $save, $cancel))
                $form.AcceptButton = $save
                $form.CancelButton = $cancel
                if ($form.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { throw 'Cancelled; nothing stored.' }
                $value = New-Object Security.SecureString
                try {
                    foreach ($character in $inputBox.Text.ToCharArray()) { $value.AppendChar($character) }
                    $inputBox.Clear()
                    Save-AgentSecret $Name $value
                } finally { $value.Dispose() }
                Write-Output "Stored '$Name' with Windows DPAPI (value not shown)."
            } finally { $form.Dispose() }
        }
        'get' {
            $value = Read-AgentSecret $Name
            $pointer = [IntPtr]::Zero
            try {
                $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($value)
                Write-Output ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer))
            } finally {
                if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
                $value.Dispose()
            }
        }
        'list' { Get-AgentSecretNames }
        'rm' { Remove-AgentSecret $Name; Write-Output "Removed '$Name'." }
        { $_ -in @('help', '-h', '--help') } { Write-Output 'secret.ps1 set|get|rm <name> | list' }
        default { throw 'Unknown command. Use set, get, list or rm.' }
    }
} catch {
    # Do not print exceptions that might include input or decrypted material.
    [Console]::Error.WriteLine('Secret operation failed. Check the command, name, local permissions and Windows user profile; an empty or cancelled dialog stores nothing.')
    exit 1
}
