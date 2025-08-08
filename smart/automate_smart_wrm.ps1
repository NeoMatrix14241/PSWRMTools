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
$dhcpServer = "192.168.126.134"  # Replace with your DHCP server's IP address
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

# Define CSV column order (updated to include Volume information)
$csvColumns = @("MAC Address", "IP Address", "Computer Name", "Drive Name", "Drive Status", "Disk Type", "Size (GB)", "Volume Letter", "Volume Label", "File System", "Used Space (GB)", "Free Space (GB)", "Total Volume Size (GB)")

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
            # Get both PhysicalDisk and Volume information via Invoke-Command
            try {
                $targetName = if ($hostName) { $hostName } else { $ipAddress }
                $combinedResults = Invoke-Command -ComputerName $targetName -ScriptBlock {
                    # Get PhysicalDisk information
                    $physicalDisks = Get-PhysicalDisk | Select FriendlyName, MediaType, HealthStatus, Size, DeviceId
                    
                    # Get Volume information
                    $volumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } | 
                               Select DriveLetter, FileSystemLabel, FileSystem, Size, SizeRemaining
                    
                    # Get disk-to-volume mapping
                    $diskToVolume = @{}
                    $partitions = Get-Partition | Where-Object { $_.DriveLetter }
                    foreach ($partition in $partitions) {
                        $diskNumber = $partition.DiskNumber
                        $driveLetter = $partition.DriveLetter
                        if (-not $diskToVolume.ContainsKey($diskNumber)) {
                            $diskToVolume[$diskNumber] = @()
                        }
                        $diskToVolume[$diskNumber] += $driveLetter
                    }
                    
                    # Combine the data
                    $combinedData = @()
                    foreach ($disk in $physicalDisks) {
                        $diskNumber = $disk.DeviceId
                        $relatedVolumes = $diskToVolume[$diskNumber]
                        
                        if ($relatedVolumes) {
                            foreach ($driveLetter in $relatedVolumes) {
                                $volume = $volumes | Where-Object { $_.DriveLetter -eq $driveLetter }
                                if ($volume) {
                                    $combinedData += [PSCustomObject]@{
                                        PhysicalDisk = $disk
                                        Volume = $volume
                                        DriveLetter = $driveLetter
                                    }
                                }
                            }
                        } else {
                            # Physical disk without associated volumes
                            $combinedData += [PSCustomObject]@{
                                PhysicalDisk = $disk
                                Volume = $null
                                DriveLetter = $null
                            }
                        }
                    }
                    
                    # Also add volumes that might not have been matched to physical disks
                    foreach ($volume in $volumes) {
                        $found = $false
                        foreach ($data in $combinedData) {
                            if ($data.DriveLetter -eq $volume.DriveLetter) {
                                $found = $true
                                break
                            }
                        }
                        if (-not $found) {
                            $combinedData += [PSCustomObject]@{
                                PhysicalDisk = $null
                                Volume = $volume
                                DriveLetter = $volume.DriveLetter
                            }
                        }
                    }
                    
                    return $combinedData
                }
                
                if ($combinedResults) {
                    foreach ($result in $combinedResults) {
                        # Physical Disk information
                        $diskName = if ($result.PhysicalDisk) { $result.PhysicalDisk.FriendlyName } else { "N/A" }
                        $diskStatus = if ($result.PhysicalDisk) { $result.PhysicalDisk.HealthStatus } else { "N/A" }
                        $diskType = if ($result.PhysicalDisk) { $result.PhysicalDisk.MediaType } else { "N/A" }
                        $diskSizeGB = if ($result.PhysicalDisk -and $result.PhysicalDisk.Size) { [math]::Round($result.PhysicalDisk.Size / 1GB, 2) } else { "N/A" }
                        
                        # Volume information
                        $volumeLetter = if ($result.Volume) { $result.Volume.DriveLetter + ":" } else { "N/A" }
                        $volumeLabel = if ($result.Volume) { $result.Volume.FileSystemLabel } else { "N/A" }
                        $fileSystem = if ($result.Volume) { $result.Volume.FileSystem } else { "N/A" }
                        $totalVolumeSize = if ($result.Volume -and $result.Volume.Size) { [math]::Round($result.Volume.Size / 1GB, 2) } else { "N/A" }
                        $freeSpace = if ($result.Volume -and $result.Volume.SizeRemaining) { [math]::Round($result.Volume.SizeRemaining / 1GB, 2) } else { "N/A" }
                        $usedSpace = if ($result.Volume -and $result.Volume.Size -and $result.Volume.SizeRemaining) { 
                            [math]::Round(($result.Volume.Size - $result.Volume.SizeRemaining) / 1GB, 2) 
                        } else { "N/A" }
                        
                        $resultObj = [PSCustomObject]@{
                            'MAC Address'           = $macAddress
                            'IP Address'           = $ipAddress
                            'Computer Name'        = $targetName
                            'Drive Name'           = $diskName
                            'Drive Status'         = $diskStatus
                            'Disk Type'            = $diskType
                            'Size (GB)'            = $diskSizeGB
                            'Volume Letter'        = $volumeLetter
                            'Volume Label'         = $volumeLabel
                            'File System'          = $fileSystem
                            'Used Space (GB)'      = $usedSpace
                            'Free Space (GB)'      = $freeSpace
                            'Total Volume Size (GB)' = $totalVolumeSize
                        }
                        try {
                            $resultObj | Select-Object $csvColumns | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
                            Write-Host "Disk and Volume info for MAC $macAddress (Drive: $volumeLetter) added to CSV."
                        } catch {
                            Write-Host "Error appending to CSV: $_"
                        }
                    }
                } else {
                    $resultObj = [PSCustomObject]@{
                        'MAC Address'           = $macAddress
                        'IP Address'           = $ipAddress
                        'Computer Name'        = $targetName
                        'Drive Name'           = "N/A"
                        'Drive Status'         = "No disk/volume data returned"
                        'Disk Type'            = "N/A"
                        'Size (GB)'            = "N/A"
                        'Volume Letter'        = "N/A"
                        'Volume Label'         = "N/A"
                        'File System'          = "N/A"
                        'Used Space (GB)'      = "N/A"
                        'Free Space (GB)'      = "N/A"
                        'Total Volume Size (GB)' = "N/A"
                    }
                    try {
                        $resultObj | Select-Object $csvColumns | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
                        Write-Host "No disk/volume data for MAC $macAddress, added to CSV."
                    } catch {
                        Write-Host "Error appending to CSV: $_"
                    }
                }
            } catch {
                $errorMsg = $_.ToString()
                if ($errorMsg -match "The RPC server is unavailable") {
                    $failureStatus = "RPC server unavailable for IP: $ipAddress"
                } else {
                    $failureStatus = "Error connecting to $($ipAddress): $errorMsg"
                }
                $resultObj = [PSCustomObject]@{
                    'MAC Address'           = $macAddress
                    'IP Address'           = $ipAddress
                    'Computer Name'        = $ipAddress
                    'Drive Name'           = "N/A"
                    'Drive Status'         = $failureStatus
                    'Disk Type'            = "N/A"
                    'Size (GB)'            = "N/A"
                    'Volume Letter'        = "N/A"
                    'Volume Label'         = "N/A"
                    'File System'          = "N/A"
                    'Used Space (GB)'      = "N/A"
                    'Free Space (GB)'      = "N/A"
                    'Total Volume Size (GB)' = "N/A"
                }
                # Append the error result to the CSV file
                try {
                    $resultObj | Select-Object $csvColumns | Export-Csv -Path $outputFile -NoTypeInformation -Force -Append
                    Write-Host "Disk/Volume error for MAC $macAddress added to CSV."
                } catch {
                    Write-Host "Error appending to CSV: $_"
                }
            }
        } else {
            # If no lease is found for the MAC address, log that as well
            $resultObj = [PSCustomObject]@{
                'MAC Address'           = $macAddress
                'IP Address'           = "No IP address found"
                'Computer Name'        = "N/A"
                'Drive Name'           = "N/A"
                'Drive Status'         = "N/A"
                'Disk Type'            = "N/A"
                'Size (GB)'            = "N/A"
                'Volume Letter'        = "N/A"
                'Volume Label'         = "N/A"
                'File System'          = "N/A"
                'Used Space (GB)'      = "N/A"
                'Free Space (GB)'      = "N/A"
                'Total Volume Size (GB)' = "N/A"
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