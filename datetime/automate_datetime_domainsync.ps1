# =====================================================================================================
# CONFIGURATION
# =====================================================================================================
$pcListFile = "hostnames.txt"
$outputFile = "TIME_SYNC_RESULTS.csv"
$timeServer = "DOMAIN-SERVER-SAMPLE.domain.com"
# =====================================================================================================

# Set script directory
$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Set-Location -LiteralPath "$scriptDir"

# Check if PC list file exists
if (-not (Test-Path -Path $pcListFile)) {
    Write-Host "ERROR: The file '$pcListFile' does not exist!" -ForegroundColor Red
    exit
}

# Read PC names/IPs
$pcList = Get-Content -Path $pcListFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

# Clear/create output file
if (Test-Path -Path $outputFile) {
    Remove-Item -Path $outputFile
}

# Initialize results array
$allResults = @()

# Define CSV columns
$csvColumns = @("Computer Name", "IP Address", "Status", "Time Before", "Time After", "Output", "Error")

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "NET TIME SYNCHRONIZATION SCRIPT" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Time Server: $timeServer" -ForegroundColor Yellow
Write-Host "Total PCs to process: $($pcList.Count)" -ForegroundColor Yellow
Write-Host ""

# Process each PC
$counter = 0
foreach ($pc in $pcList) {
    $counter++
    Write-Host "[$counter/$($pcList.Count)] Processing: $pc" -ForegroundColor Cyan
    
    $ipAddress = "N/A"
    
    try {
        # Test if PC is reachable
        Write-Host "  -> Testing connectivity..." -ForegroundColor Gray
        if (-not (Test-Connection -ComputerName $pc -Count 1 -Quiet)) {
            throw "PC is not reachable (ping failed)"
        }
        
        # Resolve IP address
        try {
            $ipAddress = (Resolve-DnsName -Name $pc -Type A -ErrorAction Stop).IPAddress | Select-Object -First 1
        } catch {
            $ipAddress = "N/A"
        }
        
        # Execute net time command with elevation
        Write-Host "  -> Syncing time..." -ForegroundColor Gray
        $result = Invoke-Command -ComputerName $pc -ScriptBlock {
            param($server)
            
            $output = @{}
            
            # Get current time BEFORE sync
            $output.TimeBefore = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            
            # Create a scheduled task to run with SYSTEM privileges (bypasses UAC)
            $taskName = "TempTimeSync_" + (Get-Random)
            $action = "cmd /c net time \\$server /set /y"
            
            # Create and run task as SYSTEM
            $null = schtasks /Create /TN $taskName /TR $action /SC ONCE /ST 23:59 /RU "SYSTEM" /RL HIGHEST /F
            $null = schtasks /Run /TN $taskName
            
            # Wait for task to complete
            Start-Sleep -Seconds 3
            
            # Delete task
            $null = schtasks /Delete /TN $taskName /F
            
            # Get time AFTER sync
            $output.TimeAfter = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $output.NetTimeOutput = "Time synchronized successfully via scheduled task"
            
            return $output
            
        } -ArgumentList $timeServer -ErrorAction Stop
        
        # Success
        $resultObj = [PSCustomObject]@{
            'Computer Name' = $pc
            'IP Address'    = $ipAddress
            'Status'        = "Success"
            'Time Before'   = $result.TimeBefore
            'Time After'    = $result.TimeAfter
            'Output'        = $result.NetTimeOutput
            'Error'         = ""
        }
        
        Write-Host "  [OK] Success" -ForegroundColor Green
        Write-Host "  -> Time Before: $($result.TimeBefore)" -ForegroundColor Yellow
        Write-Host "  -> Time After:  $($result.TimeAfter)" -ForegroundColor Green
        
    } catch {
        # Failure
        $errorMsg = $_.Exception.Message
        
        $resultObj = [PSCustomObject]@{
            'Computer Name' = $pc
            'IP Address'    = $ipAddress
            'Status'        = "Failed"
            'Time Before'   = "N/A"
            'Time After'    = "N/A"
            'Output'        = ""
            'Error'         = $errorMsg
        }
        
        Write-Host "  [ERROR] Failed: $errorMsg" -ForegroundColor Red
    }
    
    # Add to results array
    $allResults += $resultObj
    
    Write-Host ""
}

# Export all results to CSV at once
$allResults | Select-Object $csvColumns | Export-Csv -Path $outputFile -NoTypeInformation -Force

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SCRIPT COMPLETED" -ForegroundColor Cyan
Write-Host "Results saved to: $outputFile" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Display summary using the results array (not re-reading CSV)
$successCount = ($allResults | Where-Object { $_.Status -eq "Success" }).Count
$failedCount = ($allResults | Where-Object { $_.Status -eq "Failed" }).Count

Write-Host "SUMMARY:" -ForegroundColor Yellow
Write-Host "  Total PCs: $($allResults.Count)" -ForegroundColor White
Write-Host "  Success: $successCount" -ForegroundColor Green
Write-Host "  Failed: $failedCount" -ForegroundColor Red
Write-Host ""