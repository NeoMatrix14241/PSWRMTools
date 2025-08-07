# Ensure the script runs in its own directory (robust for elevation and special characters)
$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Set-Location -LiteralPath "$scriptDir"

# =====================================================================================================
# MODIFY THIS SECTION TO SET YOUR FILE PATHS AND DHCP SERVER
# =====================================================================================================
# File Paths
$macAddressFile = "mac_address.txt"  # Path to your file with MAC addresses
$outputFile = "SMART_RESULTS_WRM.csv"   # Path to save the results in CSV format

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
    $csvResults = @()
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

# Define CSV column order (updated to include Size)
$csvColumns = @("MAC Address", "IP Address", "Computer Name", "Drive Name", "Drive Status", "Disk Type", "Size (GB)")

# Loop through each MAC address
foreach ($macAddress in $macAddresses) {
    # Add a blank line for readability
    Write-Host ""
    try {
        # Clean up the MAC address to match the DHCP server's format (ensure no dashes or colons)
        $macAddressFormatted = $macAddress -replace "[-:]", ""  # Ensure MAC is clean of any dashes or colons
        # Ensure the MAC address is in lowercase (match case sensitivity in DHCP leases)
        $macAddressFormatted = $macAddressFormatted.ToLower()
        # Debug: Check the formatted MAC address
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
            # Always use Get-PhysicalDisk via Invoke-Command for disk health (updated to include Size)
            try {
                $targetName = if ($hostName) { $hostName } else { $ipAddress }
                $diskResults = Invoke-Command -ComputerName $targetName -ScriptBlock {
                    Get-PhysicalDisk | Select FriendlyName, MediaType, HealthStatus, Size
                }
                if ($diskResults) {
                    foreach ($disk in $diskResults) {
                        # Convert size from bytes to GB (rounded to 2 decimal places)
                        $sizeGB = if ($disk.Size) { [math]::Round($disk.Size / 1GB, 2) } else { "N/A" }
                        $resultObj = [PSCustomObject]@{
                            'MAC Address'    = $macAddress
                            'IP Address'     = $ipAddress
                            'Computer Name'  = $targetName
                            'Drive Name'     = $disk.FriendlyName
                            'Drive Status'   = $disk.HealthStatus
                            'Disk Type'      = $disk.MediaType
                            'Size (GB)'      = $sizeGB
                        }
                        try {
                            $resultObj | Select-Object $csvColumns | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
                            Write-Host "PhysicalDisk health for MAC $macAddress added to CSV."
                        } catch {
                            Write-Host "Error appending to CSV: $_"
                        }
                    }
                } else {
                    $resultObj = [PSCustomObject]@{
                        'MAC Address'    = $macAddress
                        'IP Address'     = $ipAddress
                        'Computer Name'  = $targetName
                        'Drive Name'     = "N/A"
                        'Drive Status'   = "No PhysicalDisk data returned"
                        'Disk Type'      = "N/A"
                        'Size (GB)'      = "N/A"
                    }
                    try {
                        $resultObj | Select-Object $csvColumns | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
                        Write-Host "No PhysicalDisk data for MAC $macAddress, added to CSV."
                    } catch {
                        Write-Host "Error appending to CSV: $_"
                    }
                }
            } catch {
                $errorMsg = $_.ToString()
                if ($errorMsg -match "The RPC server is unavailable") {
                    $failureStatus = "RPC server unavailable for IP: $ipAddress"
                    $diskType = "N/A"
                } else {
                    $failureStatus = "Error connecting to $($ipAddress): $errorMsg"
                    $diskType = "N/A"
                }
                $resultObj = [PSCustomObject]@{
                    'MAC Address'    = $macAddress
                    'IP Address'     = $ipAddress
                    'Computer Name'  = $ipAddress
                    'Drive Name'     = "N/A"
                    'Drive Status'   = $failureStatus
                    'Disk Type'      = $diskType
                    'Size (GB)'      = "N/A"
                }
                # Append the error result to the CSV file
                try {
                    $resultObj | Select-Object $csvColumns | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
                    Write-Host "PhysicalDisk error for MAC $macAddress added to CSV."
                } catch {
                    Write-Host "Error appending to CSV: $_"
                }
            }
        } else {
            # If no lease is found for the MAC address, log that as well
            $resultObj = [PSCustomObject]@{
                'MAC Address'    = $macAddress
                'IP Address'     = "No IP address found"
                'Computer Name'  = "N/A"
                'Drive Name'     = "N/A"
                'Drive Status'   = "N/A"
                'Disk Type'      = "N/A"
                'Size (GB)'      = "N/A"
            }
            # Append the result to the CSV file
            try {
                $resultObj | Select-Object $csvColumns | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
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
