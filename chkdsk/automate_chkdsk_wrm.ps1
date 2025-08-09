# Multithreaded CHKDSK Script for Debugging - FIXED VERSION WITH FULL LOGGING
$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Set-Location -LiteralPath "$scriptDir"

# Configuration
$macAddressFile = "mac_address.txt"
$outputFile = Join-Path $scriptDir "CHKDSK_RESULTS_WRM.csv"  # Full path
$logFolderName = "CHKDSK_RESULTS_WRM_LOGS"  # Log folder name based on CSV
$logFolder = Join-Path $scriptDir $logFolderName
$dhcpServer = "192.168.126.134"
$scopeId = "192.168.160.0"
$checkPrimaryOnly = $true # Set to $true to check only primary drive (C:)
$maxConcurrentJobs = 5  # Adjust based on your network and system capacity

Write-Host "=== MULTITHREADED CHKDSK DEBUG SCRIPT (FIXED) ===" -ForegroundColor Cyan
Write-Host "Max concurrent jobs: $maxConcurrentJobs" -ForegroundColor Yellow
Write-Host "Output file: $outputFile" -ForegroundColor Yellow
Write-Host "Log folder: $logFolder" -ForegroundColor Yellow

# Create log folder if it doesn't exist
if (-not (Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    Write-Host "Created log folder: $logFolder" -ForegroundColor Green
} else {
    Write-Host "Using existing log folder: $logFolder" -ForegroundColor Yellow
}

# Read MAC addresses
$macAddresses = @()
if (Test-Path $macAddressFile) {
    $rawMacAddresses = Get-Content -Path $macAddressFile
    foreach ($mac in $rawMacAddresses) {
        $cleanMac = $mac.Trim()
        if ($cleanMac -ne "") {
            $macAddresses += $cleanMac
        }
    }
} else {
    Write-Host "MAC address file not found: $macAddressFile" -ForegroundColor Red
    exit 1
}

Write-Host "MAC addresses to process: $($macAddresses.Count)"
foreach ($mac in $macAddresses) {
    Write-Host "  - $mac" -ForegroundColor Green
}

# Initialize CSV with header (delete existing file first)
if (Test-Path $outputFile) {
    Remove-Item $outputFile -Force
    Write-Host "Removed existing output file" -ForegroundColor Yellow
}

$csvHeader = "MAC Address,IP Address,Computer Name,Drive Letter,CHKDSK Status,CHKDSK Result,Summary,Execution Time,Job ID,Thread ID,Log File"
$csvHeader | Out-File -FilePath $outputFile -Encoding UTF8
Write-Host "Created CSV header in: $outputFile" -ForegroundColor Green

# Get DHCP leases once
Write-Host "`nQuerying DHCP..." -ForegroundColor Cyan
try {
    Import-Module DhcpServer -ErrorAction Stop
    $leases = Get-DhcpServerv4Lease -ComputerName $dhcpServer -ScopeId $scopeId -ErrorAction Stop
    Write-Host "Found $($leases.Count) DHCP leases" -ForegroundColor Green
} catch {
    Write-Host "Failed to get DHCP leases: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Define the script block for each job - FIXED VERSION WITH FULL LOGGING
$chkdskScriptBlock = {
    param(
        $macAddress,
        $dhcpLeases,
        $outputFilePath,  # Full path passed as parameter
        $logFolderPath,   # Log folder path
        $jobId,
        $checkPrimaryOnly
    )
    
    $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
    
    # Create log file name based on MAC address (clean for filename)
    $cleanMacForFile = ($macAddress -replace "[:-]", "") -replace "[^a-zA-Z0-9]", "_"
    $logFileName = "CHKDSK_$cleanMacForFile" + "_Job$jobId.log"
    $logFilePath = Join-Path $logFolderPath $logFileName
    
    # Function to write to log file
    function Write-LogFile {
        param($message, $logPath)
        try {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            "[$timestamp] $message" | Out-File -FilePath $logPath -Append -Encoding UTF8
        } catch {
            Write-Host "Failed to write to log: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Initialize log file
    Write-LogFile "=== CHKDSK LOG FOR MAC: $macAddress (Job $jobId, Thread $threadId) ===" $logFilePath
    
    # Thread-safe CSV writing function with better error handling
    function Write-CsvResult {
        param($csvLine, $filePath)
        $maxRetries = 10
        $retryCount = 0
        $success = $false
        
        do {
            try {
                # Use Add-Content with Mutex-like behavior
                $mutex = New-Object System.Threading.Mutex($false, "CSVWriteMutex")
                $mutex.WaitOne() | Out-Null
                
                $csvLine | Out-File -FilePath $filePath -Append -Encoding UTF8 -ErrorAction Stop
                $success = $true
                
                $mutex.ReleaseMutex()
                break
            } catch {
                if ($mutex) { $mutex.ReleaseMutex() }
                $retryCount++
                Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 1000)
            }
        } while ($retryCount -lt $maxRetries -and -not $success)
        
        return $success
    }
    
    # Create result object function
    function New-ResultObject {
        param(
            $MAC, $IP = "N/A", $HostName = "N/A", $Drive = "N/A", 
            $Status, $Result, $Summary, $Duration = 0, $JobId, $ThreadId, $LogFile = "N/A"
        )
        
        return [PSCustomObject]@{
            MAC = $MAC
            IP = $IP
            HostName = $HostName
            Drive = $Drive
            Status = $Status
            Result = $Result
            Summary = $Summary
            Duration = $Duration
            JobId = $JobId
            ThreadId = $ThreadId
            LogFile = $LogFile
        }
    }
    
    # Helper function to build CSV line safely
    function Build-CsvLine {
        param($resultObject)
        
        $safeSummary = ($resultObject.Summary -replace '"', '""')
        $line = """$($resultObject.MAC)"",""$($resultObject.IP)"",""$($resultObject.HostName)"",""$($resultObject.Drive)"",""$($resultObject.Status)"",""$($resultObject.Result)"",""$safeSummary"",""$($resultObject.Duration)"",""$($resultObject.JobId)"",""$($resultObject.ThreadId)"",""$($resultObject.LogFile)"""
        return $line
    }
    
    try {
        Write-Host "Job $($jobId) (Thread $threadId): Processing $macAddress" -ForegroundColor Cyan
        Write-LogFile "Starting processing for MAC: $macAddress" $logFilePath
        
        # Find DHCP lease
        $cleanMac = ($macAddress -replace "[-:]", "").ToLower()
        
        $matchingLease = $dhcpLeases | Where-Object { 
            ($_.ClientId -replace "[-:]", "").ToLower() -eq $cleanMac
        }
        
        if (-not $matchingLease) {
            Write-Host "Job $($jobId): No DHCP lease found for $macAddress" -ForegroundColor Yellow
            Write-LogFile "ERROR: No DHCP lease found for MAC address" $logFilePath
            $resultObj = New-ResultObject -MAC $macAddress -Status "Failed" -Result "No DHCP Lease" -Summary "No lease found for MAC address" -JobId $jobId -ThreadId $threadId -LogFile $logFileName
            $csvLine = Build-CsvLine -resultObject $resultObj
            $writeSuccess = Write-CsvResult -csvLine $csvLine -filePath $outputFilePath
            Write-Host "Job $($jobId): CSV write result for 'No DHCP Lease': $writeSuccess" -ForegroundColor Magenta
            return $resultObj
        }
        
        $ipAddress = $matchingLease.IPAddress.ToString()
        $hostName = $matchingLease.HostName
        $targetName = if ($hostName -and $hostName.Trim() -ne "") { $hostName.Trim() } else { $ipAddress }
        
        Write-Host "Job $($jobId): Found lease - IP: $ipAddress, Host: $targetName" -ForegroundColor Green
        Write-LogFile "Found DHCP lease - IP: $ipAddress, Host: $targetName" $logFilePath
        
        # Test WinRM connectivity first
        try {
            Write-Host "Job $($jobId): Testing WinRM connectivity to $targetName" -ForegroundColor Yellow
            Write-LogFile "Testing WinRM connectivity to $targetName" $logFilePath
            Test-WSMan -ComputerName $targetName -ErrorAction Stop | Out-Null
            Write-Host "Job $($jobId): WinRM test successful" -ForegroundColor Green
            Write-LogFile "WinRM test successful" $logFilePath
        } catch {
            Write-Host "Job $($jobId): WinRM test failed - $($_.Exception.Message)" -ForegroundColor Red
            Write-LogFile "ERROR: WinRM test failed - $($_.Exception.Message)" $logFilePath
            $resultObj = New-ResultObject -MAC $macAddress -IP $ipAddress -HostName $targetName -Status "Failed" -Result "WinRM Connection Failed" -Summary $_.Exception.Message -JobId $jobId -ThreadId $threadId -LogFile $logFileName
            $csvLine = Build-CsvLine -resultObject $resultObj
            $writeSuccess = Write-CsvResult -csvLine $csvLine -filePath $outputFilePath
            Write-Host "Job $($jobId): CSV write result for 'WinRM Failed': $writeSuccess" -ForegroundColor Magenta
            return $resultObj
        }
        
        # Run CHKDSK via Invoke-Command
        try {
            Write-Host "Job $($jobId): Starting CHKDSK on $targetName" -ForegroundColor Yellow
            Write-LogFile "Starting CHKDSK on $targetName" $logFilePath
            $startTime = Get-Date
            
            $chkdskResult = Invoke-Command -ComputerName $targetName -ScriptBlock {
                param($checkPrimaryOnly)
                
                try {
                    # Determine which drives to check
                    if ($checkPrimaryOnly) {
                        $drivesToCheck = @("C:")
                    } else {
                        # Get all NTFS fixed drives
                        try {
                            $drivesToCheck = Get-Volume | 
                                Where-Object { 
                                    $_.DriveType -eq 'Fixed' -and 
                                    $_.FileSystem -eq 'NTFS' -and 
                                    $_.DriveLetter -ne $null -and
                                    $_.Size -gt 100MB
                                } | 
                                ForEach-Object { "$($_.DriveLetter):" }
                        } catch {
                            # Fallback to just C: if Get-Volume fails
                            $drivesToCheck = @("C:")
                        }
                    }
                    
                    if ($drivesToCheck.Count -eq 0) {
                        $drivesToCheck = @("C:")  # Ensure we always have at least C:
                    }
                    
                    $allResults = @()
                    foreach ($drive in $drivesToCheck) {
                        try {
                            Write-Output "Checking drive $drive..."
                            
                            # Run CHKDSK with full output capture
                            $chkdskOutput = & cmd /c "chkdsk $drive 2>&1"
                            
                            $fullOutput = if ($chkdskOutput -is [array]) {
                                ($chkdskOutput -join "`n").Trim()
                            } else {
                                $chkdskOutput.ToString().Trim()
                            }
                            
                            # Extract clean summary for CSV
                            $outputLines = $fullOutput -split "`n"
                            $summaryLines = @()
                            
                            # Look for key summary information
                            foreach ($line in $outputLines) {
                                $trimmedLine = $line.Trim()
                                
                                # Skip progress and formatting lines
                                if ($trimmedLine -eq "" -or 
                                    $trimmedLine -match "^Progress:" -or 
                                    $trimmedLine -match "^Stage:" -or 
                                    $trimmedLine -match "^Total:" -or 
                                    $trimmedLine -match "^ETA:" -or
                                    $trimmedLine -match "^\.\.\." -or
                                    $trimmedLine -match "^\.+" -or
                                    $trimmedLine -match "\d+% complete" -or
                                    $trimmedLine -match "percent complete") {
                                    continue
                                }
                                
                                # Capture important lines
                                if ($trimmedLine -match "(Windows has checked|file system|found no problems|errors found|KB total disk space|KB available|bad sectors|corrupt)" -or
                                    $trimmedLine -match "(completed successfully|scan completed|access denied|in use|invalid drive)" -or
                                    $trimmedLine -match "(bytes total disk space|bytes available)" -or
                                    ($trimmedLine.Length -lt 100 -and $trimmedLine.Length -gt 5)) {
                                    $summaryLines += $trimmedLine
                                }
                            }
                            
                            # Create clean summary
                            $cleanSummary = if ($summaryLines.Count -gt 0) {
                                ($summaryLines | Select-Object -First 5) -join " | "
                            } else {
                                "CHKDSK completed - check detailed log"
                            }
                            
                            # Status detection based on full output
                            if ($fullOutput -match "Windows has checked the file system and found no problems") {
                                $status = "Success"
                                $result = "No Problems Found"
                            } elseif ($fullOutput -match "errors found|corrupt|bad sectors") {
                                $status = "Problems Found"
                                $result = "Errors Detected"
                            } elseif ($fullOutput -match "completed successfully|scan completed") {
                                $status = "Success" 
                                $result = "Check Completed Successfully"
                            } elseif ($fullOutput -match "access denied|Access is denied") {
                                $status = "Failed"
                                $result = "Access Denied"
                            } elseif ($fullOutput -match "in use|being used by another process") {
                                $status = "Failed"
                                $result = "Drive In Use"
                            } elseif ($fullOutput -match "invalid drive|not found") {
                                $status = "Failed"
                                $result = "Invalid Drive"
                            } elseif ($fullOutput.Length -gt 100) {
                                $status = "Success"
                                $result = "Check Completed - Review Log"
                            } else {
                                $status = "Failed"
                                $result = "No Valid Output"
                            }
                            
                            $driveResultObj = [PSCustomObject]@{
                                Drive = $drive
                                Status = $status
                                Result = $result
                                Summary = $cleanSummary
                                FullOutput = $fullOutput  # Keep full output for logging
                            }
                            $allResults += $driveResultObj
                            
                        } catch {
                            # Handle individual drive check errors
                            $driveResultObj = [PSCustomObject]@{
                                Drive = $drive
                                Status = "Failed"
                                Result = "Drive Check Error"
                                Summary = "Error checking drive $drive" + ": " + $_.Exception.Message
                                FullOutput = "Error checking drive $drive" + ": " + $_.Exception.Message
                            }
                            $allResults += $driveResultObj
                        }
                    }
                    
                    # Combine results for all drives
                    $combinedSummaryParts = @()
                    $combinedFullOutputParts = @()
                    $overallResultParts = @()
                    $hasProblems = $false
                    $hasFailed = $false
                    $hasSuccess = $false
                    
                    foreach ($driveResult in $allResults) {
                        $driveInfo = $driveResult.Drive
                        $driveSummary = $driveResult.Summary
                        $driveFullOutput = $driveResult.FullOutput
                        $driveResultText = $driveResult.Result
                        
                        $combinedSummaryParts += "$driveInfo" + ": " + "$driveSummary"
                        $combinedFullOutputParts += "=== DRIVE $driveInfo ===" + "`n" + "$driveFullOutput" + "`n"
                        $overallResultParts += "$driveInfo" + ":" + "$driveResultText"
                        
                        if ($driveResult.Status -eq "Problems Found") { $hasProblems = $true }
                        elseif ($driveResult.Status -eq "Failed") { $hasFailed = $true }
                        elseif ($driveResult.Status -eq "Success") { $hasSuccess = $true }
                    }
                    
                    $combinedSummary = ($combinedSummaryParts -join " || ").Substring(0, [Math]::Min(500, ($combinedSummaryParts -join " || ").Length))  # Limit summary length
                    $combinedFullOutput = $combinedFullOutputParts -join "`n"
                    $overallResult = $overallResultParts -join "; "
                    
                    # Determine overall status
                    $overallStatus = if ($hasProblems) { "Problems Found" }
                                    elseif ($hasFailed -and -not $hasSuccess) { "Failed" }
                                    elseif ($hasSuccess) { "Success" }
                                    else { "Failed" }
                    
                    return [PSCustomObject]@{
                        Status = $overallStatus
                        Result = $overallResult
                        Summary = $combinedSummary
                        FullOutput = $combinedFullOutput
                        DriveCount = $allResults.Count
                        Success = $true
                        ProcessedDrives = ($allResults | ForEach-Object { $_.Drive }) -join ","
                    }
                    
                } catch {
                    return [PSCustomObject]@{
                        Status = "Failed"
                        Result = "Remote Execution Error" 
                        Summary = "Error in remote script block: $($_.Exception.Message)"
                        FullOutput = "Error in remote script block: $($_.Exception.Message)"
                        DriveCount = 0
                        Success = $false
                        ProcessedDrives = "None"
                    }
                }
            } -ArgumentList $checkPrimaryOnly -ErrorAction Stop
            
            $endTime = Get-Date
            $duration = [math]::Round(($endTime - $startTime).TotalSeconds, 2)

            # FIXED: Write CHKDSK results to log file
            Write-LogFile "CHKDSK execution completed in $duration seconds" $logFilePath
            Write-LogFile "=== CHKDSK RESULTS ===" $logFilePath
            Write-LogFile "Status: $($chkdskResult.Status)" $logFilePath
            Write-LogFile "Result: $($chkdskResult.Result)" $logFilePath
            Write-LogFile "Summary: $($chkdskResult.Summary)" $logFilePath

            if ($chkdskResult.FullOutput) {
                Write-LogFile "=== FULL CHKDSK OUTPUT ===" $logFilePath
                Write-LogFile "$($chkdskResult.FullOutput)" $logFilePath
            } else {
                Write-LogFile "No full output captured" $logFilePath
            }

            Write-LogFile "Processed drives: $($chkdskResult.ProcessedDrives)" $logFilePath
            Write-LogFile "Drive count: $($chkdskResult.DriveCount)" $logFilePath
            Write-LogFile "=== END CHKDSK RESULTS ===" $logFilePath
            
            Write-Host "Job $($jobId): CHKDSK completed in $duration seconds" -ForegroundColor Green
            Write-Host "Job $($jobId): CHKDSK Result - Status: $($chkdskResult.Status), Result: $($chkdskResult.Result)" -ForegroundColor Green
            
            # Write result to CSV - THIS IS THE CRITICAL PART
            $driveList = if ($chkdskResult.DriveCount -gt 1) { "Multiple ($($chkdskResult.DriveCount))" } else { "C:" }
            $resultObj = New-ResultObject -MAC $macAddress -IP $ipAddress -HostName $targetName -Drive $driveList -Status $chkdskResult.Status -Result $chkdskResult.Result -Summary $chkdskResult.Summary -Duration $duration -JobId $jobId -ThreadId $threadId -LogFile $logFileName
            
            $csvLine = Build-CsvLine -resultObject $resultObj
            
            Write-Host "Job $($jobId): About to write to CSV - Status: $($resultObj.Status)" -ForegroundColor Magenta
            $writeSuccess = Write-CsvResult -csvLine $csvLine -filePath $outputFilePath
            
            if ($writeSuccess) {
                Write-Host "Job $($jobId): Successfully wrote CHKDSK result to CSV" -ForegroundColor Green
            } else {
                Write-Host "Job $($jobId): FAILED to write CHKDSK result to CSV after retries" -ForegroundColor Red
            }
            
            Write-LogFile "CSV write completed - Success: $writeSuccess" $logFilePath
            return $resultObj
            
        } catch {
            $errorMsg = $_.Exception.Message
            Write-Host "Job $($jobId): Remote execution failed - $errorMsg" -ForegroundColor Red
            Write-LogFile "ERROR: Remote execution failed - $errorMsg" $logFilePath
            
            $resultObj = New-ResultObject -MAC $macAddress -IP $ipAddress -HostName $targetName -Status "Failed" -Result "Remote Execution Error" -Summary $errorMsg -JobId $jobId -ThreadId $threadId -LogFile $logFileName
            $csvLine = Build-CsvLine -resultObject $resultObj
            $writeSuccess = Write-CsvResult -csvLine $csvLine -filePath $outputFilePath
            Write-Host "Job $($jobId): CSV write result for 'Remote Execution Error': $writeSuccess" -ForegroundColor Magenta
            return $resultObj
        }
        
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Host "Job $($jobId): Processing error - $errorMsg" -ForegroundColor Red
        Write-LogFile "ERROR: Processing error - $errorMsg" $logFilePath
        
        $resultObj = New-ResultObject -MAC $macAddress -Status "Failed" -Result "Processing Error" -Summary $errorMsg -JobId $jobId -ThreadId $threadId -LogFile $logFileName
        $csvLine = Build-CsvLine -resultObject $resultObj
        $writeSuccess = Write-CsvResult -csvLine $csvLine -filePath $outputFilePath
        Write-Host "Job $($jobId): CSV write result for 'Processing Error': $writeSuccess" -ForegroundColor Magenta
        return $resultObj
    } finally {
        Write-LogFile "=== JOB COMPLETED ===" $logFilePath
    }
}

# Initialize job tracking
$jobs = @()
$completedJobs = @()
$jobCounter = 1
$startTime = Get-Date

Write-Host "`n=== STARTING PARALLEL PROCESSING ===" -ForegroundColor Cyan

# Process MAC addresses with job throttling
for ($i = 0; $i -lt $macAddresses.Count; $i++) {
    $macAddress = $macAddresses[$i]
    
    # Wait if we've reached the maximum concurrent jobs
    while ((Get-Job -State Running).Count -ge $maxConcurrentJobs) {
        Start-Sleep -Seconds 2
        
        # Check for completed jobs
        $finishedJobs = Get-Job -State Completed
        foreach ($job in $finishedJobs) {
            try {
                $result = Receive-Job -Job $job -ErrorAction Stop
                $completedJobs += $result
                Remove-Job -Job $job -ErrorAction SilentlyContinue
                
                # Progress update
                $completedCount = $completedJobs.Count
                $totalCount = $macAddresses.Count
                $percentComplete = [math]::Round(($completedCount / $totalCount) * 100, 1)
                
                if ($result) {
                    $statusColor = switch ($result.Status) {
                        'Success' { 'Green' }
                        'Problems Found' { 'Yellow' }
                        'Failed' { 'Red' }
                        default { 'White' }
                    }
                    Write-Host "[$percentComplete%] Completed: $($result.MAC) -> $($result.Status) ($($result.Result)) [Job:$($result.JobId) Thread:$($result.ThreadId)]" -ForegroundColor $statusColor
                }
            } catch {
                Write-Host "Error receiving job result: $($_.Exception.Message)" -ForegroundColor Red
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # Start new job - Pass log folder path as additional parameter
    $job = Start-Job -ScriptBlock $chkdskScriptBlock -ArgumentList $macAddress, $leases, $outputFile, $logFolder, $jobCounter, $checkPrimaryOnly
    $jobs += $job
    
    Write-Host "Started job $jobCounter for MAC: $macAddress [PowerShell JobId: $($job.Id)]" -ForegroundColor Cyan
    $jobCounter++
    Start-Sleep -Milliseconds 500  # Small delay to prevent overwhelming
}

Write-Host "`nAll jobs started. Waiting for completion..." -ForegroundColor Yellow

# Wait for all remaining jobs to complete - NO TIMEOUT
while ((Get-Job -State Running).Count -gt 0) {
    Start-Sleep -Seconds 5
    
    # Show running job count
    $runningCount = (Get-Job -State Running).Count
    $currentTime = Get-Date
    $elapsedMinutes = [math]::Round(($currentTime - $startTime).TotalMinutes, 1)
    Write-Host "Still running: $runningCount jobs... (Elapsed: $elapsedMinutes minutes)" -ForegroundColor Yellow
    
    # Check for completed jobs
    $finishedJobs = Get-Job -State Completed
    foreach ($job in $finishedJobs) {
        try {
            $result = Receive-Job -Job $job -ErrorAction Stop
            $completedJobs += $result
            Remove-Job -Job $job -ErrorAction SilentlyContinue
            
            # Progress update
            $completedCount = $completedJobs.Count
            $totalCount = $macAddresses.Count
            $percentComplete = [math]::Round(($completedCount / $totalCount) * 100, 1)
            
            if ($result) {
                $statusColor = switch ($result.Status) {
                    'Success' { 'Green' }
                    'Problems Found' { 'Yellow' }
                    'Failed' { 'Red' }
                    default { 'White' }
                }
                Write-Host "[$percentComplete%] Completed: $($result.MAC) -> $($result.Status) ($($result.Result)) [Job:$($result.JobId) Thread:$($result.ThreadId)]" -ForegroundColor $statusColor
            }
        } catch {
            Write-Host "Error receiving job result: $($_.Exception.Message)" -ForegroundColor Red
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}

# Clean up any remaining jobs
Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue

$endTime = Get-Date
$totalDuration = ($endTime - $startTime).TotalMinutes

# Show final results
Write-Host "`n=== FINAL RESULTS ===" -ForegroundColor Cyan
Write-Host "Total execution time: $([math]::Round($totalDuration, 2)) minutes"
Write-Host "Jobs completed: $($completedJobs.Count) / $($macAddresses.Count)"

# Verify CSV file exists and show results
if (Test-Path $outputFile) {
    try {
        $results = Import-Csv $outputFile
        Write-Host "CSV results: $($results.Count) records" -ForegroundColor Green
        
        # Summary statistics
        $successCount = 0
        $problemsCount = 0
        $failedCount = 0
        
        foreach ($result in $results) {
            $chkdskStatusValue = $result.'CHKDSK Status'
            switch ($chkdskStatusValue) {
                'Success' { $successCount++ }
                'Problems Found' { $problemsCount++ }
                'Failed' { $failedCount++ }
            }
        }
        
        Write-Host "`nSummary:" -ForegroundColor Yellow
        Write-Host "  Success: $successCount" -ForegroundColor Green
        Write-Host "  Problems Found: $problemsCount" -ForegroundColor Yellow
        Write-Host "  Failed: $failedCount" -ForegroundColor Red
        
        Write-Host "`nDetailed Results:" -ForegroundColor Yellow
        foreach ($result in $results) {
            $statusValue = $result.'CHKDSK Status'
            $color = switch ($statusValue) {
                'Success' { 'Green' }
                'Problems Found' { 'Yellow' }
                'Failed' { 'Red' }
                default { 'White' }
            }
            $executionTime = $result.'Execution Time'
            $duration = if ($executionTime -ne '0') { " (" + $executionTime + "s)" } else { "" }
            $macAddress = $result.'MAC Address'
            $ipAddress = $result.'IP Address'
            $chkdskStatus = $result.'CHKDSK Status'
            $chkdskResult = $result.'CHKDSK Result'
            $jobId = $result.'Job ID'
            
            Write-Host "MAC: $macAddress | IP: $ipAddress | Status: $chkdskStatus | Result: $chkdskResult$duration [Job:$jobId]" -ForegroundColor $color
        }
    } catch {
        Write-Host "Error reading CSV file: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "No results file found at: $outputFile" -ForegroundColor Red
}

Write-Host "`nScript completed. Results saved to: $outputFile" -ForegroundColor Green