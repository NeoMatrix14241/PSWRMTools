# =====================================================================================================
# CREDENTIAL ENCRYPTION HELPER
# Creates encrypted credential files that only YOU on THIS computer can decrypt
# =====================================================================================================

# Set script directory
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
Set-Location -LiteralPath "$scriptDir"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CREDENTIAL ENCRYPTION UTILITY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Working Directory: $scriptDir" -ForegroundColor Gray
Write-Host ""

$credentialsFile = Join-Path $scriptDir "credentials.enc"
$usernameFile = Join-Path $scriptDir "username.txt"

# Check if files already exist
if (Test-Path -Path $credentialsFile) {
    Write-Host "WARNING: Encrypted credentials already exist!" -ForegroundColor Yellow
    $overwrite = Read-Host "Do you want to overwrite? (yes/no)"
    if ($overwrite -ne "yes") {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit
    }
}

Write-Host "Please enter your domain admin credentials:" -ForegroundColor Yellow
Write-Host "(e.g., domain\administrator)" -ForegroundColor Gray
Write-Host ""

# Prompt for credentials
$credential = Get-Credential -Message "Enter domain admin credentials"

if (-not $credential) {
    Write-Host "ERROR: No credentials provided!" -ForegroundColor Red
    exit
}

try {
    # Save encrypted password
    $credential.Password | ConvertFrom-SecureString | Set-Content $credentialsFile
    
    # Save username
    $credential.UserName | Set-Content $usernameFile
    
    Write-Host ""
    Write-Host "SUCCESS!" -ForegroundColor Green
    Write-Host "Encrypted credentials saved to: $credentialsFile" -ForegroundColor Cyan
    Write-Host "Username saved to: $usernameFile" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "IMPORTANT SECURITY NOTES:" -ForegroundColor Yellow
    Write-Host "- These files can ONLY be decrypted by: $env:USERNAME" -ForegroundColor White
    Write-Host "- On this computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "- Keep these files in the same folder as your script" -ForegroundColor White
    Write-Host ""
    Write-Host "You can now run the time sync script!" -ForegroundColor Green
    Write-Host ""
    
} catch {
    Write-Host "ERROR: Failed to save credentials: $_" -ForegroundColor Red
    exit
}