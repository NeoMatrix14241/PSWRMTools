# Helper function to get IPv4 and MAC address for a remote host, with fallback for workgroup hosts
function Get-HostNetworkInfo {
    param(
        [string]$ComputerName,
        [bool]$IsWorkgroup = $false,
        [string]$Username = $null,
        [string]$Password = $null
    )
    try {
        if (-not $IsWorkgroup) {
            $networkInfo = Get-CimInstance -ComputerName $ComputerName -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        } else {
            $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential ($Username, $securePassword)
            $cimSession = New-CimSession -ComputerName $ComputerName -Credential $cred -Authentication Default
            $networkInfo = Get-CimInstance -CimSession $cimSession -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        }
        $ipv4 = $null
        $mac = $null
        if ($networkInfo) {
            foreach ($adapter in $networkInfo) {
                if ($adapter.IPAddress) {
                    $ipv4List = $adapter.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -notlike '127.*' -and $_ -notlike '169.254.*' }
                    if ($ipv4List -and $ipv4List[0] -is [string] -and $ipv4List[0] -match '^\d{1,3}(\.\d{1,3}){3}$') {
                        $ipv4 = $ipv4List[0]
                        $mac = $adapter.MACAddress
                        break
                    } elseif ($ipv4List) {
                        $ipv4 = ($ipv4List | Out-String).Trim()
                        $mac = $adapter.MACAddress
                        break
                    }
                }
            }
        }
        if ($IsWorkgroup -and $cimSession) { Remove-CimSession $cimSession }
        return @{ IPv4 = $ipv4; MAC = $mac }
    } catch {
        if ($IsWorkgroup -and $cimSession) { Remove-CimSession $cimSession }
        return @{ IPv4 = $null; MAC = $null }
    }
}

# Ensure the script runs in its own directory
$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Set-Location -LiteralPath "$scriptDir"

# =====================================================================================================
# MODIFY THIS SECTION TO SET YOUR FILE PATHS
# =====================================================================================================
# File Paths
$domainHostFile = "hostname_domain.txt"
$workgroupHostFile = "hostname_workgroup.txt"
$outputFile = "SMART_RESULTS_WRM.csv"
# =====================================================================================================

# Debug: Output the current working directory
Write-Host "Current working directory: $(Get-Location)"

# Check if hostname files exist
try {
    if (-not (Test-Path -Path $domainHostFile)) {
        throw "The hostname file '$domainHostFile' does not exist. Please check the path."
    }
    if (-not (Test-Path -Path $workgroupHostFile)) {
        Write-Host "Warning: The workgroup hostname file '$workgroupHostFile' does not exist. Only domain hosts will be processed."
    }
} catch {
    $errorMessage = "Error: $_"
    $errorMessage | Out-File -Append -FilePath $outputFile
    Write-Host $errorMessage
    exit
}

# Read and validate hostnames
try {
    $rawDomainHostNames = Get-Content -Path $domainHostFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
    $domainHostNames = @()
    foreach ($entry in $rawDomainHostNames) {
        if ($entry -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
            $domainHostNames += $entry
        } else {
            Write-Host "Warning: Skipping IP address '$entry' in domain host file. Use hostnames only."
        }
    }
    
    if (Test-Path -Path $workgroupHostFile) {
        $rawWorkgroupHostLines = Get-Content -Path $workgroupHostFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" -and -not ($_.StartsWith('#')) }
        $workgroupHosts = @()
        foreach ($entry in $rawWorkgroupHostLines) {
            $parts = $entry -split ','
            if ($parts.Count -ge 3) {
                $ip = $parts[0].Trim()
                $uname = $parts[1].Trim()
                $pass = $parts[2].Trim()
                if ($ip -match '^(\d{1,3}\.){3}\d{1,3}$') {
                    $workgroupHosts += [PSCustomObject]@{ IP = $ip; Username = $uname; Password = $pass }
                } else {
                    Write-Host "Warning: Skipping non-IP entry '$ip' in workgroup host file."
                }
            } elseif ($parts.Count -eq 1 -and $parts[0] -match '^(\d{1,3}\.){3}\d{1,3}$') {
                $workgroupHosts += [PSCustomObject]@{ IP = $parts[0].Trim(); Username = $null; Password = $null }
            } else {
                Write-Host "Warning: Skipping invalid line in workgroup host file: '$entry'"
            }
        }
    } else {
        $workgroupHosts = @()
    }
} catch {
    $errorMessage = "Error reading the hostname files: $_"
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
} catch {
    $errorMessage = "Error clearing or preparing the output file '$outputFile': $_"
    $errorMessage | Out-File -Append -FilePath $outputFile
    Write-Host $errorMessage
    exit
}

# Debug: Output the file path for the CSV
Write-Host "Output file path: $outputFile"

# Define CSV column order (matching SMART script exactly)
$csvColumns = @("MAC Address", "IP Address", "Computer Name", "Drive Name", "Drive Status", "Disk Type", "Size (GB)", "Volume Letter", "Volume Label", "File System", "Used Space (GB)", "Free Space (GB)", "Total Volume Size (GB)")

# Optionally, set default credentials for workgroup hosts
$defaultWorkgroupUsername = $null  # e.g. "administrator"
$defaultWorkgroupPassword = $null  # e.g. "password"

# Loop through each domain hostname
foreach ($hostName in $domainHostNames) {
    # Add a blank line for readability
    Write-Host ""
    try {
        Write-Host "Processing Domain Hostname: $hostName"
        
        $netInfo = Get-HostNetworkInfo -ComputerName $hostName -IsWorkgroup:$false
        $ipAddress = if ($netInfo.IPv4) { $netInfo.IPv4 } else { "N/A" }
        $macAddress = if ($netInfo.MAC) { $netInfo.MAC } else { "N/A" }
        
        try {
            $combinedResults = Invoke-Command -ComputerName $hostName -ScriptBlock {
                # Get all disk information
                $physicalDisks = Get-PhysicalDisk | Select DeviceId, FriendlyName, MediaType, HealthStatus, Size
                $disks = Get-Disk | Select Number, FriendlyName
                
                # Get Volume information
                $volumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } | 
                           Select DriveLetter, FileSystemLabel, FileSystem, Size, SizeRemaining
                
                # Step 1: Map PhysicalDisk DeviceId to Disk Number via FriendlyName
                $physicalDiskToDiskNumber = @{}
                foreach ($physicalDisk in $physicalDisks) {
                    $matchingDisk = $disks | Where-Object { $_.FriendlyName -eq $physicalDisk.FriendlyName }
                    if ($matchingDisk) {
                        $physicalDiskToDiskNumber[$physicalDisk.DeviceId] = $matchingDisk.Number
                    }
                }
                
                # Step 2: Map Disk Number to Drive Letters via Partitions
                $diskToVolumes = @{}
                $partitions = Get-Partition | Where-Object { $_.DriveLetter }
                foreach ($partition in $partitions) {
                    $diskNumber = $partition.DiskNumber
                    $driveLetter = $partition.DriveLetter
                    if (-not $diskToVolumes.ContainsKey($diskNumber)) {
                        $diskToVolumes[$diskNumber] = @()
                    }
                    $diskToVolumes[$diskNumber] += $driveLetter
                }
                
                # Step 3: Combine PhysicalDisk with Volumes
                $combinedData = @()
                foreach ($physicalDisk in $physicalDisks) {
                    $diskNumber = $physicalDiskToDiskNumber[$physicalDisk.DeviceId]
                    $relatedDriveLetters = $diskToVolumes[$diskNumber]
                    
                    if ($relatedDriveLetters) {
                        foreach ($driveLetter in $relatedDriveLetters) {
                            $volume = $volumes | Where-Object { $_.DriveLetter -eq $driveLetter }
                            if ($volume) {
                                $combinedData += [PSCustomObject]@{
                                    PhysicalDisk = $physicalDisk
                                    Volume = $volume
                                    DriveLetter = $driveLetter
                                }
                            }
                        }
                    } else {
                        # Physical disk without associated volumes
                        $combinedData += [PSCustomObject]@{
                            PhysicalDisk = $physicalDisk
                            Volume = $null
                            DriveLetter = $null
                        }
                    }
                }
                
                # Step 4: Add orphaned volumes (volumes not matched to physical disks)
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
                        'Computer Name'        = $hostName
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
                        Write-Host "Disk and Volume info for $hostName (Drive: $volumeLetter) added to CSV."
                    } catch {
                        Write-Host "Error appending to CSV: $_"
                    }
                }
            } else {
                $resultObj = [PSCustomObject]@{
                    'MAC Address'           = $macAddress
                    'IP Address'           = $ipAddress
                    'Computer Name'        = $hostName
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
                    Write-Host "No disk/volume data for $hostName, added to CSV."
                } catch {
                    Write-Host "Error appending to CSV: $_"
                }
            }
        } catch {
            $errorMsg = $_.ToString()
            if ($errorMsg -match "The RPC server is unavailable") {
                $failureStatus = "RPC server unavailable for $hostName"
            } else {
                $failureStatus = "Error connecting to $hostName`: $errorMsg"
            }
            $resultObj = [PSCustomObject]@{
                'MAC Address'           = $macAddress
                'IP Address'           = $ipAddress
                'Computer Name'        = $hostName
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
                Write-Host "Disk/Volume error for $hostName added to CSV."
            } catch {
                Write-Host "Error appending to CSV: $_"
            }
        }
    } catch {
        Write-Host "An error occurred processing hostname $hostName. Skipping to next."
        continue
    }
}

# Loop through each workgroup host (with per-host credentials)
foreach ($workgroupHost in $workgroupHosts) {
    $hostName = $workgroupHost.IP
    $workgroupUsername = if ($workgroupHost.Username) { $workgroupHost.Username } else { $defaultWorkgroupUsername }
    $workgroupPassword = if ($workgroupHost.Password) { $workgroupHost.Password } else { $defaultWorkgroupPassword }
    
    # Add a blank line for readability
    Write-Host ""
    try {
        Write-Host "Processing Workgroup Host: $hostName"
        
        $netInfo = Get-HostNetworkInfo -ComputerName $hostName -IsWorkgroup:$true -Username $workgroupUsername -Password $workgroupPassword
        $ipAddress = if ($netInfo.IPv4) { $netInfo.IPv4 } else { "N/A" }
        $macAddress = if ($netInfo.MAC) { $netInfo.MAC } else { "N/A" }

        # Try to get the actual hostname from the remote machine
        $actualHostName = $null
        try {
            $securePassword = ConvertTo-SecureString $workgroupPassword -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential ($workgroupUsername, $securePassword)
            $actualHostName = Invoke-Command -ComputerName $hostName -Credential $cred -ScriptBlock {
                try {
                    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
                    if ($cs -and $cs.Name) { return $cs.Name }
                    else { return $env:COMPUTERNAME }
                } catch {
                    return $env:COMPUTERNAME
                }
            } -ErrorAction Stop
        } catch {
            $actualHostName = $hostName
        }
        if (-not $actualHostName) { $actualHostName = $hostName }

        # Get both PhysicalDisk and Volume information via Invoke-Command
        try {
            $securePassword = ConvertTo-SecureString $workgroupPassword -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential ($workgroupUsername, $securePassword)
            $combinedResults = Invoke-Command -ComputerName $hostName -Credential $cred -ScriptBlock {
                # Get all disk information
                $physicalDisks = Get-PhysicalDisk | Select DeviceId, FriendlyName, MediaType, HealthStatus, Size
                $disks = Get-Disk | Select Number, FriendlyName
                
                # Get Volume information
                $volumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } | 
                           Select DriveLetter, FileSystemLabel, FileSystem, Size, SizeRemaining
                
                # Step 1: Map PhysicalDisk DeviceId to Disk Number via FriendlyName
                $physicalDiskToDiskNumber = @{}
                foreach ($physicalDisk in $physicalDisks) {
                    $matchingDisk = $disks | Where-Object { $_.FriendlyName -eq $physicalDisk.FriendlyName }
                    if ($matchingDisk) {
                        $physicalDiskToDiskNumber[$physicalDisk.DeviceId] = $matchingDisk.Number
                    }
                }
                
                # Step 2: Map Disk Number to Drive Letters via Partitions
                $diskToVolumes = @{}
                $partitions = Get-Partition | Where-Object { $_.DriveLetter }
                foreach ($partition in $partitions) {
                    $diskNumber = $partition.DiskNumber
                    $driveLetter = $partition.DriveLetter
                    if (-not $diskToVolumes.ContainsKey($diskNumber)) {
                        $diskToVolumes[$diskNumber] = @()
                    }
                    $diskToVolumes[$diskNumber] += $driveLetter
                }
                
                # Step 3: Combine PhysicalDisk with Volumes
                $combinedData = @()
                foreach ($physicalDisk in $physicalDisks) {
                    $diskNumber = $physicalDiskToDiskNumber[$physicalDisk.DeviceId]
                    $relatedDriveLetters = $diskToVolumes[$diskNumber]
                    
                    if ($relatedDriveLetters) {
                        foreach ($driveLetter in $relatedDriveLetters) {
                            $volume = $volumes | Where-Object { $_.DriveLetter -eq $driveLetter }
                            if ($volume) {
                                $combinedData += [PSCustomObject]@{
                                    PhysicalDisk = $physicalDisk
                                    Volume = $volume
                                    DriveLetter = $driveLetter
                                }
                            }
                        }
                    } else {
                        # Physical disk without associated volumes
                        $combinedData += [PSCustomObject]@{
                            PhysicalDisk = $physicalDisk
                            Volume = $null
                            DriveLetter = $null
                        }
                    }
                }
                
                # Step 4: Add orphaned volumes (volumes not matched to physical disks)
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
                        'Computer Name'        = $actualHostName
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
                        Write-Host "Disk and Volume info for $actualHostName ($hostName) (Drive: $volumeLetter) added to CSV."
                    } catch {
                        Write-Host "Error appending to CSV: $_"
                    }
                }
            } else {
                $resultObj = [PSCustomObject]@{
                    'MAC Address'           = $macAddress
                    'IP Address'           = $ipAddress
                    'Computer Name'        = $actualHostName
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
                    Write-Host "No disk/volume data for $actualHostName ($hostName), added to CSV."
                } catch {
                    Write-Host "Error appending to CSV: $_"
                }
            }
        } catch {
            $errorMsg = $_.ToString()
            if ($errorMsg -match "The RPC server is unavailable") {
                $failureStatus = "RPC server unavailable for $hostName"
            } else {
                $failureStatus = "Error connecting to $hostName`: $errorMsg"
            }
            $resultObj = [PSCustomObject]@{
                'MAC Address'           = $macAddress
                'IP Address'           = $ipAddress
                'Computer Name'        = $actualHostName
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
                Write-Host "Disk/Volume error for $actualHostName ($hostName) added to CSV."
            } catch {
                Write-Host "Error appending to CSV: $_"
            }
        }
    } catch {
        Write-Host "An error occurred processing workgroup host $hostName. Skipping to next."
        continue
    }
}

Write-Host "Script finished processing."