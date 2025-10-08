# =====================================================================================================
# CONFIGURATION
# =====================================================================================================
$domainController = "sample.domain.com"
$timeZone = "Asia/Manila"
$psExecTimeout = 30

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
Set-Location -LiteralPath "$scriptDir"

$pcListFile = Join-Path $scriptDir "hostnames.txt"
$outputFile = Join-Path $scriptDir "TIME_SYNC_RESULTS.csv"
$psExecPath = Join-Path $scriptDir "PsExec64.exe"
$credentialsFile = Join-Path $scriptDir "credentials.enc"
$usernameFile = Join-Path $scriptDir "username.txt"
# =====================================================================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PSEXEC TIME SYNC (RUN AS SYSTEM)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Script Directory: $scriptDir" -ForegroundColor Gray
Write-Host ""

# Delete old CSV
Write-Host "Preparing output file..." -ForegroundColor Cyan
if (Test-Path -Path $outputFile) {
    Write-Host "  -> Deleting old CSV file" -ForegroundColor Yellow
    try {
        Remove-Item -Path $outputFile -Force -ErrorAction Stop
        Write-Host "  -> Old CSV deleted successfully" -ForegroundColor Green
    } catch {
        Write-Host "  -> ERROR: Could not delete old CSV: $_" -ForegroundColor Red
        Write-Host "  -> Please close the file if it's open in Excel" -ForegroundColor Yellow
        Write-Host ""
        exit
    }
} else {
    Write-Host "  -> No old CSV found (fresh start)" -ForegroundColor Gray
}
Write-Host "  -> New CSV will be created: $outputFile" -ForegroundColor Green
Write-Host ""

# Load credentials
Write-Host "Loading encrypted credentials..." -ForegroundColor Cyan

if (-not (Test-Path -Path $credentialsFile)) {
    Write-Host "ERROR: Encrypted credentials file not found!" -ForegroundColor Red
    Write-Host "Expected location: $credentialsFile" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please run 'create_encrypted_credentials.ps1' first." -ForegroundColor Yellow
    Write-Host ""
    exit
}

if (-not (Test-Path -Path $usernameFile)) {
    Write-Host "ERROR: Username file not found!" -ForegroundColor Red
    Write-Host "Expected location: $usernameFile" -ForegroundColor Yellow
    exit
}

try {
    $username = Get-Content -Path $usernameFile
    $encryptedPassword = Get-Content -Path $credentialsFile | ConvertTo-SecureString
    $credential = New-Object System.Management.Automation.PSCredential($username, $encryptedPassword)
    
    Write-Host "Credentials loaded successfully for: $username" -ForegroundColor Green
    Write-Host ""
    
} catch {
    Write-Host "ERROR: Failed to load credentials: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "The credentials may have been created by a different user or on a different computer." -ForegroundColor Yellow
    Write-Host "Please run 'create_encrypted_credentials.ps1' again." -ForegroundColor Yellow
    Write-Host ""
    exit
}

# Check files
if (-not (Test-Path -Path $pcListFile)) {
    Write-Host "ERROR: PC list file not found!" -ForegroundColor Red
    Write-Host "Expected location: $pcListFile" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please create 'hostnames.txt' with one PC name/IP per line." -ForegroundColor Yellow
    Write-Host ""
    exit
}

if (-not (Test-Path -Path $psExecPath)) {
    Write-Host "ERROR: PsExec64.exe not found!" -ForegroundColor Red
    Write-Host "Expected location: $psExecPath" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please download from: https://live.sysinternals.com/PsExec64.exe" -ForegroundColor Cyan
    Write-Host ""
    exit
}

$pcList = Get-Content -Path $pcListFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

$csvColumns = @("Computer Name", "IP Address", "Status", "Command Executed", "Time Source", "Output", "Error")

# =====================================================================================================
# HELPER FUNCTION: Run PsExec with Timeout
# =====================================================================================================
function Invoke-PsExecWithTimeout {
    param(
        [string]$Computer,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$Command,
        [int]$TimeoutSeconds = 30
    )
    
    $username = $Credential.UserName
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    
    # Build PsExec arguments
    $psExecArgs = "\\$Computer -u `"$username`" -p `"$password`" -accepteula -nobanner $Command"
    
    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = $psExecPath
    $processInfo.Arguments = $psExecArgs
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processInfo
    
    try {
        $process.Start() | Out-Null
        
        $finished = $process.WaitForExit($TimeoutSeconds * 150000)
        
        if (-not $finished) {
            $process.Kill()
            throw "Operation timed out after $TimeoutSeconds seconds"
        }
        
        $output = $process.StandardOutput.ReadToEnd()
        $errorOutput = $process.StandardError.ReadToEnd()
        $exitCode = $process.ExitCode
        
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        
        return [PSCustomObject]@{
            Output = $output.Trim()
            Error = $errorOutput.Trim()
            ExitCode = $exitCode
            Success = ($exitCode -eq 0)
        }
        
    } catch {
        if ($process -and -not $process.HasExited) {
            $process.Kill()
        }
        throw $_
    } finally {
        if ($process) {
            $process.Dispose()
        }
    }
}

# =====================================================================================================
# VERIFY DOMAIN CONTROLLER
# =====================================================================================================
Write-Host "Verifying Domain Controller access..." -ForegroundColor Yellow
Write-Host "Domain Controller: $domainController" -ForegroundColor Yellow
Write-Host ""

try {
    Write-Host "  -> Testing: net time \\$domainController" -ForegroundColor Gray
    $netTimeOutput = net time "\\$domainController" 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  -> SUCCESS!" -ForegroundColor Green
        $timeString = $netTimeOutput | Where-Object { $_ -match "Current time at" }
        Write-Host "  -> $timeString" -ForegroundColor Gray
        Write-Host ""
    } else {
        throw "Cannot connect to domain controller"
    }
} catch {
    Write-Host "  -> ERROR: Cannot connect to Domain Controller!" -ForegroundColor Red
    Write-Host "  -> $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host ""
    exit
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "READY TO SYNC" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Domain Controller: $domainController" -ForegroundColor White
Write-Host "Timezone: $timeZone" -ForegroundColor White
Write-Host "Total PCs: $($pcList.Count)" -ForegroundColor Yellow
Write-Host "Command: NET TIME \\$domainController /SET /Y" -ForegroundColor Green
Write-Host "Execution Mode: SYSTEM (bypasses user rights)" -ForegroundColor Green
Write-Host "Authentication: $username" -ForegroundColor Cyan
Write-Host "Timeout: $psExecTimeout seconds per PC" -ForegroundColor Cyan
Write-Host ""

# =====================================================================================================
# PROCESS EACH PC
# =====================================================================================================
$counter = 0
foreach ($pc in $pcList) {
    $counter++
    Write-Host "[$counter/$($pcList.Count)] Processing: $pc" -ForegroundColor Cyan
    
    $ipAddress = "N/A"
    $outputMsg = ""
    $commandExecuted = "NET TIME \\$domainController /SET /Y (as SYSTEM)"
    
    try {
        # Test connectivity
        Write-Host "  -> Testing connectivity..." -ForegroundColor Gray
        if (-not (Test-Connection -ComputerName $pc -Count 1 -Quiet)) {
            throw "PC is not reachable (ping failed)"
        }
        
        # Get IP
        try {
            $ipAddress = (Resolve-DnsName -Name $pc -Type A -ErrorAction Stop).IPAddress | Select-Object -First 1
        } catch {
            $ipAddress = "N/A"
        }
        
        # EXECUTE NET TIME AS SYSTEM (-s flag)
        Write-Host "  -> Executing as SYSTEM: NET TIME \\$domainController /SET /Y" -ForegroundColor Cyan
        
        # CRITICAL: -s flag runs command as SYSTEM (no user rights issues)
        $syncCommand = "-s cmd /c `"NET TIME \\$domainController /SET /Y`""
        
        $result = Invoke-PsExecWithTimeout -Computer $pc -Credential $credential `
                                           -Command $syncCommand -TimeoutSeconds $psExecTimeout
        
        # Check result
        if ($result.ExitCode -eq 0) {
            $status = "Success"
            $statusColor = "Green"
            $errorMsg = ""
            $outputMsg = $result.Output
            
            Write-Host "  -> SUCCESS! Time synchronized with domain" -ForegroundColor Green
        } else {
            $status = "Failed"
            $statusColor = "Red"
            $errorMsg = "Exit Code: $($result.ExitCode)"
            
            if ($result.Error) {
                $errorMsg += " - $($result.Error)"
            }
            if ($result.Output) {
                $errorMsg += " - $($result.Output)"
            }
            
            Write-Host "  -> FAILED! Exit code: $($result.ExitCode)" -ForegroundColor Red
            
            if ($result.Error) {
                Write-Host "  -> Error: $($result.Error)" -ForegroundColor Red
            }
        }
        
        $resultObj = [PSCustomObject]@{
            'Computer Name' = $pc
            'IP Address'    = $ipAddress
            'Status'        = $status
            'Command Executed' = $commandExecuted
            'Time Source'   = $domainController
            'Output'        = $outputMsg
            'Error'         = $errorMsg
        }
        
        Write-Host "  [OK] $status" -ForegroundColor $statusColor
        
    } catch {
        $errorMsg = $_.Exception.Message
        
        $resultObj = [PSCustomObject]@{
            'Computer Name' = $pc
            'IP Address'    = $ipAddress
            'Status'        = "Failed"
            'Command Executed' = $commandExecuted
            'Time Source'   = $domainController
            'Output'        = ""
            'Error'         = $errorMsg
        }
        
        Write-Host "  [ERROR] Failed: $errorMsg" -ForegroundColor Red
    }
    
    $resultObj | Select-Object $csvColumns | Export-Csv -Path $outputFile -NoTypeInformation -Append
    
    Write-Host ""
}

# =====================================================================================================
# SUMMARY
# =====================================================================================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SCRIPT COMPLETED" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Results saved to: $outputFile" -ForegroundColor Green
Write-Host ""

if (Test-Path -Path $outputFile) {
    try {
        # FIXED: Force array conversion to handle single-item results
        $results = @(Import-Csv -Path $outputFile -ErrorAction Stop)
        $successCount = @($results | Where-Object { $_.Status -eq "Success" }).Count
        $failedCount = @($results | Where-Object { $_.Status -eq "Failed" }).Count
        
        Write-Host "SUMMARY:" -ForegroundColor Yellow
        Write-Host "  Total PCs: $($results.Count)" -ForegroundColor White
        Write-Host "  Success: $successCount" -ForegroundColor Green
        Write-Host "  Failed: $failedCount" -ForegroundColor Red
        Write-Host ""
        
        Write-Host "TIME SOURCE:" -ForegroundColor Cyan
        Write-Host "  Domain Controller: $domainController" -ForegroundColor White
        Write-Host "  Command: NET TIME \\$domainController /SET /Y" -ForegroundColor White
        Write-Host "  Execution: As SYSTEM (bypasses user rights)" -ForegroundColor White
        Write-Host "  Timezone: $timeZone" -ForegroundColor White
        Write-Host ""
        
        Write-Host "AUTHENTICATION:" -ForegroundColor Cyan
        Write-Host "  Protocol: NTLM (via PsExec)" -ForegroundColor White
        Write-Host "  User: $username" -ForegroundColor White
        Write-Host ""
        
        if ($failedCount -gt 0) {
            Write-Host "FAILED PCs:" -ForegroundColor Red
            $results | Where-Object { $_.Status -eq "Failed" } | ForEach-Object {
                Write-Host "  - $($_.'Computer Name'): $($_.'Error')" -ForegroundColor Red
            }
            Write-Host ""
        }
        
        if ($successCount -gt 0) {
            Write-Host "SUCCESSFUL PCs:" -ForegroundColor Green
            $results | Where-Object { $_.Status -eq "Success" } | ForEach-Object {
                Write-Host "  - $($_.'Computer Name') [$($_.'IP Address')]" -ForegroundColor Green
            }
            Write-Host ""
        }
        
    } catch {
        Write-Host "ERROR: Could not read CSV for summary: $_" -ForegroundColor Red
    }
} else {
    Write-Host "ERROR: Output file not found!" -ForegroundColor Red
}

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")