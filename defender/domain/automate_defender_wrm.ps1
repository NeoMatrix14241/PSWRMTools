# Ensure the script runs in its own directory (robust for elevation and special characters)
$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Set-Location -LiteralPath "$scriptDir"

# =====================================================================================================
# MODIFY THIS SECTION TO SET YOUR FILE PATHS AND DHCP SERVER
# =====================================================================================================
# File Paths
$macFile = "mac_address.txt"
$outputFile = Join-Path $scriptDir "DEFENDER_RESULTS_WRM.csv"

# Set your DHCP server's IP address
$dhcpServer = "192.168.160.100"
$scopeId = "192.168.160.0"
# =====================================================================================================

Write-Host "Current working directory: $(Get-Location)"

# Check if MAC address file exists
try {
    if (-not (Test-Path -Path $macFile)) {
        throw "The MAC address file '$macFile' does not exist. Please check the path."
    }
} catch {
    $errorMessage = "Error: $_"
    $errorMessage | Out-File -Append -LiteralPath $outputFile
    Write-Host $errorMessage
    exit
}

# Read MAC addresses from the file, trim any surrounding spaces
try {
    $macAddresses = Get-Content -Path $macFile | ForEach-Object { $_.Trim() }
} catch {
    $errorMessage = "Error reading the MAC address file '$macFile': $_"
    $errorMessage | Out-File -Append -LiteralPath $outputFile
    Write-Host $errorMessage
    exit
}



# Always delete the previous CSV file before creating a new one at the start of the script
try {
    # Remove the file only if it exists
    if (Test-Path -LiteralPath $outputFile) {
        Remove-Item -LiteralPath $outputFile -Force
        Write-Host "Deleted previous CSV: $outputFile"
    }
    # Write CSV header for new file
    $csvColumns = @(
        "MAC Address", "IP Address", "Computer Name", "Domain User", "Threat Name", "Action Success", 
        "Initial Detection Time", "Last Threat Status Change Time", "Process Name", "Remediation Time", 
        "Threat ID", "Threat Status Error Code", "Threat Status ID", "Status"
    )
    $headerLine = $csvColumns -join ','
    $parentDir = Split-Path -Parent $outputFile
    if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }
    try {
        Set-Content -Path $outputFile -Value $headerLine -ErrorAction Stop
    } catch {
        Write-Host "Output file $outputFile already deleted, no further actions needed :)"
        # Do not exit, continue script
    }
    Write-Host "Created new CSV: $outputFile"
} catch {
    $errorMessage = "Error clearing or preparing the output file '$outputFile': $_"
    Write-Host $errorMessage
    exit
}

Write-Host "Output file path: $outputFile"

# Query the DHCP server for the leases once
try {
    $leases = Get-DhcpServerv4Lease -ComputerName $dhcpServer -ScopeId $scopeId
} catch {
    $errorMessage = "Error querying the DHCP server '$dhcpServer' with ScopeId '$scopeId': $_"
    $errorMessage | Out-File -Append -LiteralPath $outputFile
    Write-Host $errorMessage
    exit
}

Write-Host "Found the following leases:"
$leases | Format-Table ClientId, IPAddress, HostName


# Define CSV column order (full set)
$csvColumns = @(
    "MAC Address", "IP Address", "Computer Name", "Domain User", "Threat Name", "Action Success",
    "Initial Detection Time", "Last Threat Status Change Time", "Process Name", "Remediation Time",
    "Threat ID", "Threat Status Error Code", "Threat Status ID", "Status"
)

# Loop through each MAC address
foreach ($macAddress in $macAddresses) {
    Write-Host ""
    try {
        $macAddressFormatted = $macAddress -replace "[-:]", ""
        $macAddressFormatted = $macAddressFormatted.ToLower()
        Write-Host "Searching for MAC Address: $macAddressFormatted"
        try {
            $leasesMatching = $leases | Where-Object {
                ($_.ClientId -replace "[-:]", "").ToLower() -eq $macAddressFormatted
            }
        } catch {
            $errorMessage = "Error processing MAC Address '$macAddressFormatted': $_"
            $errorMessage | Out-File -Append -LiteralPath $outputFile
            Write-Host $errorMessage
            continue
        }
        if ($leasesMatching) {
            $ipAddress = $leasesMatching.IPAddress.IPAddressToString
            $hostName = $leasesMatching.HostName
            $targetName = if ($hostName) { $hostName } else { $ipAddress }
            Write-Host "Found: $hostName ($ipAddress)"
            try {
                $defenderResults = Invoke-Command -ComputerName $targetName -ScriptBlock {
                    try {
                        $detections = Get-MpThreatDetection
                        if ($detections) {
                            return $detections | ForEach-Object {
                                [PSCustomObject]@{
                                    ThreatName = if ($_.Resources) { ($_.Resources -join ", ") } elseif ($_.ThreatID) { $_.ThreatID.ToString() } else { "" }
                                    ActionSuccess = if ($_.ActionSuccess) { $_.ActionSuccess.ToString() } else { "" }
                                    InitialDetectionTime = if ($_.InitialDetectionTime) { $_.InitialDetectionTime.ToString() } else { "" }
                                    LastThreatStatusChangeTime = if ($_.LastThreatStatusChangeTime) { $_.LastThreatStatusChangeTime.ToString() } else { "" }
                                    ProcessName = if ($_.ProcessName) { $_.ProcessName.ToString() } else { "" }
                                    RemediationTime = if ($_.RemediationTime) { $_.RemediationTime.ToString() } else { "" }
                                    ThreatID = if ($_.ThreatID) { $_.ThreatID.ToString() } else { "" }
                                    ThreatStatusErrorCode = if ($_.ThreatStatusErrorCode -ne $null) { $_.ThreatStatusErrorCode.ToString() } elseif ($_.PSObject.Properties.Match('ThreatStatusErrorCode')) { $_.PSObject.Properties['ThreatStatusErrorCode'].Value } else { "" }
                                    ThreatStatusID = if ($_.ThreatStatusID) { $_.ThreatStatusID.ToString() } else { "" }
                                    DomainUser = if ($_.DomainUser) { $_.DomainUser } else { "" }
                                }
                            }
                        } else {
                            return "No threats detected."
                        }
                    } catch {
                        return "Windows Defender not accessible."
                    }
                } -ErrorAction Stop
                if ($defenderResults -is [System.Array]) {
                    foreach ($det in $defenderResults) {
                        $resultObj = [PSCustomObject]@{
                            'MAC Address'    = $macAddress
                            'IP Address'     = $ipAddress
                            'Computer Name'  = $hostName
                            'Domain User'    = if ($det.PSObject.Properties.Match('DomainUser')) { $det.DomainUser } elseif ($_.DomainUser) { $_.DomainUser } else { '' }
                            'Threat Name'    = if ($det.PSObject.Properties.Match('ThreatName')) { $det.ThreatName } else { '' }
                            'Action Success' = if ($det.PSObject.Properties.Match('ActionSuccess')) { $det.ActionSuccess } else { '' }
                            'Initial Detection Time' = if ($det.PSObject.Properties.Match('InitialDetectionTime')) { $det.InitialDetectionTime } else { '' }
                            'Last Threat Status Change Time' = if ($det.PSObject.Properties.Match('LastThreatStatusChangeTime')) { $det.LastThreatStatusChangeTime } else { '' }
                            'Process Name' = if ($det.PSObject.Properties.Match('ProcessName')) { $det.ProcessName } else { '' }
                            'Remediation Time' = if ($det.PSObject.Properties.Match('RemediationTime')) { $det.RemediationTime } else { '' }
                            'Threat ID' = if ($det.PSObject.Properties.Match('ThreatID')) { $det.ThreatID } else { '' }
                            'Threat Status Error Code' = if ($det.PSObject.Properties.Match('ThreatStatusErrorCode')) { $det.ThreatStatusErrorCode } else { '' }
                            'Threat Status ID' = if ($det.PSObject.Properties.Match('ThreatStatusID')) { $det.ThreatStatusID } else { '' }
                            'Status'         = 'Detected'
                        }
                        try {
                            $resultObj | Select-Object $csvColumns | Export-Csv -LiteralPath $outputFile -NoTypeInformation -Force -Append
                            Write-Host "Defender detection for MAC $macAddress added to CSV."
                        } catch {
                            Write-Host "Error appending to CSV: $_"
                        }
                    }
                } elseif ($defenderResults -is [PSCustomObject]) {
                    $resultObj = [PSCustomObject]@{
                        'MAC Address'    = $macAddress
                        'IP Address'     = $ipAddress
                        'Computer Name'  = $hostName
                        'Domain User'    = if ($defenderResults.PSObject.Properties.Match('DomainUser')) { $defenderResults.DomainUser } elseif ($defenderResults.DomainUser) { $defenderResults.DomainUser } else { '' }
                        'Threat Name'    = if ($defenderResults.PSObject.Properties.Match('ThreatName')) { $defenderResults.ThreatName } else { '' }
                        'Action Success' = if ($defenderResults.PSObject.Properties.Match('ActionSuccess')) { $defenderResults.ActionSuccess } else { '' }
                        'Initial Detection Time' = if ($defenderResults.PSObject.Properties.Match('InitialDetectionTime')) { $defenderResults.InitialDetectionTime } else { '' }
                        'Last Threat Status Change Time' = if ($defenderResults.PSObject.Properties.Match('LastThreatStatusChangeTime')) { $defenderResults.LastThreatStatusChangeTime } else { '' }
                        'Process Name' = if ($defenderResults.PSObject.Properties.Match('ProcessName')) { $defenderResults.ProcessName } else { '' }
                        'Remediation Time' = if ($defenderResults.PSObject.Properties.Match('RemediationTime')) { $defenderResults.RemediationTime } else { '' }
                        'Threat ID' = if ($defenderResults.PSObject.Properties.Match('ThreatID')) { $defenderResults.ThreatID } else { '' }
                        'Threat Status Error Code' = if ($defenderResults.PSObject.Properties.Match('ThreatStatusErrorCode')) { $defenderResults.ThreatStatusErrorCode } else { '' }
                        'Threat Status ID' = if ($defenderResults.PSObject.Properties.Match('ThreatStatusID')) { $defenderResults.ThreatStatusID } else { '' }
                        'Status'         = 'Detected'
                    }
                    try {
                        $resultObj | Select-Object $csvColumns | Export-Csv -LiteralPath $outputFile -NoTypeInformation -Force -Append
                        Write-Host "Defender detection for MAC $macAddress added to CSV."
                    } catch {
                        Write-Host "Error appending to CSV: $_"
                    }
                } elseif ($defenderResults -eq "No threats detected.") {
                    $resultObj = [PSCustomObject]@{
                        'MAC Address'    = $macAddress
                        'IP Address'     = $ipAddress
                        'Computer Name'  = $hostName
                        'Domain User'    = ""
                        'Threat Name'    = ""
                        'Action Success' = ""
                        'Initial Detection Time' = ""
                        'Last Threat Status Change Time' = ""
                        'Process Name' = ""
                        'Remediation Time' = ""
                        'Threat ID' = ""
                        'Threat Status Error Code' = ""
                        'Threat Status ID' = ""
                        'Status'         = 'No threats detected'
                    }
                    try {
                        $resultObj | Select-Object $csvColumns | Export-Csv -LiteralPath $outputFile -NoTypeInformation -Force -Append
                        Write-Host "No threats for MAC $macAddress, added to CSV."
                    } catch {
                        Write-Host "Error appending to CSV: $_"
                    }
                } else {
                    $resultObj = [PSCustomObject]@{
                        'MAC Address'    = $macAddress
                        'IP Address'     = $ipAddress
                        'Computer Name'  = $hostName
                        'Domain User'    = ""
                        'Threat Name'    = ""
                        'Action Success' = ""
                        'Initial Detection Time' = ""
                        'Last Threat Status Change Time' = ""
                        'Process Name' = ""
                        'Remediation Time' = ""
                        'Threat ID' = ""
                        'Threat Status Error Code' = ""
                        'Threat Status ID' = ""
                        'Status'         = "Unknown result: $defenderResults"
                    }
                    try {
                        $resultObj | Select-Object $csvColumns | Export-Csv -LiteralPath $outputFile -NoTypeInformation -Force -Append
                        Write-Host "Unknown result for MAC $macAddress, added to CSV."
                    } catch {
                        Write-Host "Error appending to CSV: $_"
                    }
                }
            } catch {
                $errorMsg = $_.ToString()
                $resultObj = [PSCustomObject]@{
                    'MAC Address'    = $macAddress
                    'IP Address'     = $ipAddress
                    'Computer Name'  = $hostName
                    'Domain User'    = ""
                    'Threat Name'    = ""
                    'Action Success' = ""
                    'Initial Detection Time' = ""
                    'Last Threat Status Change Time' = ""
                    'Process Name' = ""
                    'Remediation Time' = ""
                    'Threat ID' = ""
                    'Threat Status Error Code' = ""
                    'Threat Status ID' = ""
                    'Status'         = "Connection failed: $errorMsg"
                }
                try {
                    $resultObj | Select-Object $csvColumns | Export-Csv -LiteralPath $outputFile -NoTypeInformation -Force -Append
                    Write-Host "Defender error for MAC $macAddress added to CSV."
                } catch {
                    Write-Host "Error appending to CSV: $_"
                }
            }
        } else {
            $resultObj = [PSCustomObject]@{
                'MAC Address'    = $macAddress
                'IP Address'     = "No IP address found"
                'Computer Name'  = "N/A"
                'Domain User'    = ""
                'Threat Name'    = "N/A"
                'Action Success' = "N/A"
                'Initial Detection Time' = "N/A"
                'Last Threat Status Change Time' = ""
                'Process Name' = ""
                'Remediation Time' = ""
                'Threat ID' = ""
                'Threat Status Error Code' = ""
                'Threat Status ID' = ""
                'Status'         = "No lease found for MAC"
            }
            try {
                $resultObj | Select-Object $csvColumns | Export-Csv -LiteralPath $outputFile -NoTypeInformation -Force -Append
                Write-Host "No lease found for MAC $macAddress, added to CSV."
            } catch {
                Write-Host "Error appending to CSV: $_"
            }
        }
    } catch {
        Write-Host "An error occurred processing MAC $macAddress. Skipping to next."
        continue
    }
}

Write-Host "Script finished processing."
