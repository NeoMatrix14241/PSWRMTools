# DEPRECATED: This script is no longer maintained. Please use the WRM version instead.

# Ensure the script runs in its own directory (robust for elevation and special characters)
$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Set-Location -LiteralPath "$scriptDir"

# =====================================================================================================
# MODIFY THIS SECTION TO SET YOUR FILE PATHS AND DHCP SERVER
# =====================================================================================================
# File Paths
$macAddressFile = "mac_address.txt"  # Path to your file with MAC addresses
$outputFile = "SMART_RESULTS_WMI-WRM.csv"   # Path to save the results in CSV format

# Set your DHCP server's IP address (e.g., EC2 instance in AWS)
$dhcpServer = "192.168.160.100"  # Replace with your DHCP server's IP address
$scopeId = "192.168.160.0"  # Replace with your ScopeId (usually the network ID of your DHCP scope)
# =====================================================================================================

# Debug: Output the current working directory
Write-Host "Current working directory: $(Get-Location)"

# Check if MAC address file exists
try {
    if (-not (Test-Path -Path $macAddressFile)) {
        throw "The MAC address file '$macAddressFile' does not exist. Please check the path."
    }
} catch {
    $errorMessage = "Error: $_"
    $errorMessage | Out-File -Append -FilePath $outputFile
    Write-Host $errorMessage
    exit
}

# Read MAC addresses from the file, trim any surrounding spaces
try {
    $macAddresses = Get-Content -Path $macAddressFile | ForEach-Object { $_.Trim() }
} catch {
    $errorMessage = "Error reading the MAC address file '$macAddressFile': $_"
    $errorMessage | Out-File -Append -FilePath $outputFile
    Write-Host $errorMessage
    exit
}

# Initialize or clear output CSV before writing
try {
    # If the CSV already exists, clear it
    if (Test-Path -Path $outputFile) {
        Remove-Item -Path $outputFile
    }
    # Create an empty array to store the results
} catch {
    $errorMessage = "Error clearing or preparing the output file '$outputFile': $_"
    $errorMessage | Out-File -Append -FilePath $outputFile
    Write-Host $errorMessage
    exit
}

# Debug: Output the file path for the CSV
Write-Host "Output file path: $outputFile"

# Query the DHCP server for the leases once
try {
    $leases = Get-DhcpServerv4Lease -ComputerName $dhcpServer -ScopeId $scopeId
} catch {
    $errorMessage = "Error querying the DHCP server '$dhcpServer' with ScopeId '$scopeId': $_"
    $errorMessage | Out-File -Append -FilePath $outputFile
    Write-Host $errorMessage
    exit
}

# Debug: Output the leases for verification
Write-Host "Found the following leases:"
$leases | Format-Table ClientId, IPAddress, HostName

# Loop through each MAC address
foreach ($macAddress in $macAddresses) {
    # Clean up the MAC address to match the DHCP server's format (ensure no dashes or colons)
    $macAddressFormatted = $macAddress -replace "[-:]", ""  # Ensure MAC is clean of any dashes or colons

    # Ensure the MAC address is in lowercase (match case sensitivity in DHCP leases)
    $macAddressFormatted = $macAddressFormatted.ToLower()

    # Debug: Check the formatted MAC address
    Write-Host ""
    Write-Host "Searching for MAC Address: $macAddressFormatted"

    # Adjust ClientId to match the MAC address format (strip prefix if present)
    try {
        $leasesMatching = $leases | Where-Object { 
            ($_.ClientId -replace "[-:]", "").ToLower() -eq $macAddressFormatted
        }
    } catch {
        $errorMessage = "Error processing MAC Address '$macAddressFormatted': $_"
        $errorMessage | Out-File -Append -FilePath $outputFile
        Write-Host $errorMessage
        continue
    }

    if ($leasesMatching) {
        # Get the IP address and hostname for the MAC address
        $ipAddress = $leasesMatching.IPAddress
        $hostName = $leasesMatching.HostName

        # Run Get-WmiObject for the resolved IP address and collect the result
        try {
            # Get all drives connected to the remote machine via WMI
            $wmiResults = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ComputerName $ipAddress -ErrorAction Stop
            
            # Loop through each drive result
            foreach ($wmiResult in $wmiResults) {
                $failureStatus = $wmiResult.PredictFailure
                $instanceName = $wmiResult.InstanceName
                $reason = $wmiResult.Reason
                $psComputerName = $wmiResult.PSComputerName

                # Create a custom object to hold the result
                $resultObj = [PSCustomObject]@{
                    MACAddress      = $macAddress
                    IPAddress       = $ipAddress
                    InstanceName    = $instanceName
                    PredictFailure  = $failureStatus
                    Reason          = $reason
                    PSComputerName  = $psComputerName
                }

                # Append the result to the CSV file incrementally
                try {
                    $resultObj | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
                    Write-Host "Result for MAC $macAddress added to CSV."
                } catch {
                    Write-Host "Error appending to CSV: $_"
                }
            }

            # Only log "No SMART data" if the WMI call succeeded but returned no results
            if ($null -ne $wmiResults -and -not $wmiResults) {
                $resultObj = [PSCustomObject]@{
                    MACAddress      = $macAddress
                    IPAddress       = $ipAddress
                    InstanceName    = "N/A"
                    PredictFailure  = "No SMART data returned"
                    Reason          = "No WMI results"
                    PSComputerName  = $ipAddress
                }
                try {
                    $resultObj | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
                    Write-Host "No SMART data for MAC $macAddress, added to CSV."
                } catch {
                    Write-Host "Error appending to CSV: $_"
                }
            }
        } catch {
            $errorMsg = $_.ToString()
            if ($errorMsg -match "Not supported") {
                # Fallback for NVMe: Use PowerShell Remoting to run MSFT_PhysicalDisk on remote computer using HostName
                try {
                    $targetName = if ($hostName) { $hostName } else { $ipAddress }
                    $nvmeDisks = Invoke-Command -ComputerName $targetName -ScriptBlock {
                        Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus
                    }
                    if ($nvmeDisks) {
                        $foundNvme = $false
                        foreach ($disk in $nvmeDisks) {
                            # Improved: treat as NVMe if MediaType is SSD or FriendlyName contains NVMe (case-insensitive)
                            if ($disk.MediaType -eq 'SSD' -or $disk.FriendlyName -match '(?i)NVMe') {
                                $foundNvme = $true
                                $resultObj = [PSCustomObject]@{
                                    MACAddress      = $macAddress
                                    IPAddress       = $ipAddress
                                    InstanceName    = $disk.FriendlyName
                                    MediaType       = $disk.MediaType
                                    PredictFailure  = $disk.HealthStatus
                                    Reason          = "NVMe/SSD fallback"
                                    PSComputerName  = $targetName
                                }
                                try {
                                    $resultObj | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
                                    Write-Host "NVMe/SSD SMART/Health for MAC $macAddress added to CSV."
                                } catch {
                                    Write-Host "Error appending NVMe/SSD result to CSV: $_"
                                }
                            }
                        }
                        # If no NVMe/SSD disks found, log that as well
                        if (-not $foundNvme) {
                            $resultObj = [PSCustomObject]@{
                                MACAddress      = $macAddress
                                IPAddress       = $ipAddress
                                InstanceName    = "N/A"
                                MediaType       = "N/A"
                                PredictFailure  = "No NVMe/SSD disk found"
                                Reason          = "NVMe/SSD fallback"
                                PSComputerName  = $targetName
                            }
                            try {
                                $resultObj | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
                                Write-Host "No NVMe/SSD disk for MAC $macAddress, added to CSV."
                            } catch {
                                Write-Host "Error appending to CSV: $_"
                            }
                        }
                    } else {
                        $resultObj = [PSCustomObject]@{
                            MACAddress      = $macAddress
                            IPAddress       = $ipAddress
                            InstanceName    = "N/A"
                            MediaType       = "N/A"
                            PredictFailure  = "No disks found"
                            Reason          = "NVMe/SSD fallback"
                            PSComputerName  = $targetName
                        }
                        try {
                            $resultObj | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
                            Write-Host "No disks for MAC $macAddress, added to CSV."
                        } catch {
                            Write-Host "Error appending to CSV: $_"
                        }
                    }
                } catch {
                    $fallbackError = $_.ToString()
                    $resultObj = [PSCustomObject]@{
                        MACAddress      = $macAddress
                        IPAddress       = $ipAddress
                        InstanceName    = "N/A"
                        PredictFailure  = "NVMe fallback failed: $fallbackError"
                        Reason          = "NVMe fallback error"
                        PSComputerName  = $hostName
                    }
                    try {
                        $resultObj | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
                        Write-Host "NVMe fallback error for MAC $macAddress added to CSV."
                    } catch {
                        Write-Host "Error appending to CSV: $_"
                    }
                }
                continue
            } elseif ($errorMsg -match "The RPC server is unavailable") {
                $failureStatus = "RPC server unavailable for IP: $ipAddress"
                $reason = "RPC error"
            } else {
                $failureStatus = "Error connecting to $($ipAddress): $errorMsg"
                $reason = "WMI error"
            }

            $resultObj = [PSCustomObject]@{
                MACAddress      = $macAddress
                IPAddress       = $ipAddress
                InstanceName    = "N/A"
                PredictFailure  = $failureStatus
                Reason          = $reason
                PSComputerName  = $ipAddress
            }

            # Append the error result to the CSV file
            try {
                $resultObj | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
                Write-Host "WMI error for MAC $macAddress added to CSV."
            } catch {
                Write-Host "Error appending to CSV: $_"
            }
        }
    } else {
        # If no lease is found for the MAC address, log that as well
        $resultObj = [PSCustomObject]@{
            MACAddress      = $macAddress
            IPAddress       = "No IP address found"
            InstanceName    = "N/A"
            PredictFailure  = "N/A"
            Reason          = "No lease found"
            PSComputerName  = "N/A"
        }
        
        # Append the result to the CSV file
        try {
            $resultObj | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
            Write-Host "No lease found for MAC $macAddress, added to CSV."
        } catch {
            Write-Host "Error appending to CSV: $_"
        }
    }
}

Write-Host "Script finished processing."
