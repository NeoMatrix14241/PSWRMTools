# =====================================================================================================
# CONFIGURATION
# =====================================================================================================
$pcListFile = "hostnames.txt"          # File with PC names/IPs (one per line)
$outputFile = "TIME_SYNC_RESULTS.csv"  # Results log
$timeServer = "DOMAIN-SERVER" # Time server to sync with
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

# Define CSV columns
$csvColumns = @("Computer Name", "Status", "Output", "Error")

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TIME SYNCHRONIZATION SCRIPT" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
Write-Host "Time Server: $timeServer" -ForegroundColor Yellow
Write-Host "Total PCs to process: $($pcList.Count)`n" -ForegroundColor Yellow

# Process each PC
$counter = 0
foreach ($pc in $pcList) {
    $counter++
    Write-Host "[$counter/$($pcList.Count)] Processing: $pc" -ForegroundColor Cyan
    
    try {
        # Test if PC is reachable
        if (-not (Test-Connection -ComputerName $pc -Count 1 -Quiet)) {
            throw "PC is not reachable (ping failed)"
        }
        
        # Execute time sync command
        $result = Invoke-Command -ComputerName $pc -ScriptBlock {
            param($server)
            $output = net time "\\$server" /set /y 2>&1
            return $output
        } -ArgumentList $timeServer -ErrorAction Stop
        
        # Success
        $resultObj = [PSCustomObject]@{
            'Computer Name' = $pc
            'Status'        = "Success"
            'Output'        = ($result | Out-String).Trim()
            'Error'         = ""
        }
        
        Write-Host "  ✓ Success" -ForegroundColor Green
        
    } catch {
        # Failure
        $errorMsg = $_.Exception.Message
        
        $resultObj = [PSCustomObject]@{
            'Computer Name' = $pc
            'Status'        = "Failed"
            'Output'        = ""
            'Error'         = $errorMsg
        }
        
        Write-Host "  ✗ Failed: $errorMsg" -ForegroundColor Red
    }
    
    # Export to CSV
    $resultObj | Select-Object $csvColumns | Export-Csv -Path $outputFile -NoTypeInformation -Append
    
    Write-Host ""
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SCRIPT COMPLETED" -ForegroundColor Cyan
Write-Host "Results saved to: $outputFile" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan