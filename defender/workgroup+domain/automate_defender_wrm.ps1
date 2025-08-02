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
            # Try domain method first
            $networkInfo = Get-CimInstance -ComputerName $ComputerName -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        } else {
            # Use explicit credentials for workgroup hosts
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
# Ensure the script runs in its own directory (robust for elevation and special characters)
$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Set-Location -LiteralPath "$scriptDir"



# File Paths
$domainHostFile = "hostname_domain.txt"
$workgroupHostFile = "hostname_workgroup.txt"
$outputFile = Join-Path $scriptDir "DEFENDER_RESULTS_WRM.csv"

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
    $errorMessage | Out-File -Append -LiteralPath $outputFile
    Write-Host $errorMessage
    exit
}



# Read and validate domain hostnames (should be hostnames, not IPs)
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
    # Read and validate workgroup hosts (supporting comments and per-host credentials)
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
                    Write-Host "Warning: Skipping non-IP entry '$ip' in workgroup host file. Use IPv4 addresses only."
                }
            } elseif ($parts.Count -eq 1 -and $parts[0] -match '^(\d{1,3}\.){3}\d{1,3}$') {
                # Allow IP-only lines for backward compatibility (use default creds if set)
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



Write-Host "Found the following domain hostnames:"
$domainHostNames | ForEach-Object { Write-Host $_ }
Write-Host "Found the following workgroup hosts (IP, Username, Password):"
if ($workgroupHosts) {
    foreach ($workgroupHost in $workgroupHosts) {
        $pwDisplay = ''
        if ($workgroupHost.Password) {
            $pwDisplay = '***'
        }
        Write-Host ("IP: {0}, Username: {1}, Password: {2}" -f $workgroupHost.IP, $workgroupHost.Username, $pwDisplay)
    }
} else {
    Write-Host "(none)"
}


# Define CSV column order (full set)
$csvColumns = @(
    "MAC Address", "IP Address", "Computer Name", "Domain User", "Threat Name", "Action Success",
    "Initial Detection Time", "Last Threat Status Change Time", "Process Name", "Remediation Time",
    "Threat ID", "Threat Status Error Code", "Threat Status ID", "Status"
)




# Optionally, set default credentials for workgroup hosts that do not specify them in the file
$defaultWorkgroupUsername = $null  # e.g. "administrator"
$defaultWorkgroupPassword = $null  # e.g. "password"


# Loop through each domain hostname
foreach ($hostName in $domainHostNames) {
    Write-Host ""
    Write-Host "Processing Domain Hostname: $hostName"
    $netInfo = Get-HostNetworkInfo -ComputerName $hostName -IsWorkgroup:$false
    $ipv4 = if ($netInfo.IPv4) { [string]$netInfo.IPv4 } else { "N/A" }
    $mac = if ($netInfo.MAC) { $netInfo.MAC } else { "N/A" }
    try {
        $defenderResults = Invoke-Command -ComputerName $hostName -ScriptBlock {
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
                    'MAC Address'    = $mac
                    'IP Address'     = $ipv4
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
                    Write-Host "Defender detection for $hostName added to CSV."
                } catch {
                    Write-Host "Error appending to CSV: $_"
                }
            }
        } elseif ($defenderResults -is [PSCustomObject]) {
            $resultObj = [PSCustomObject]@{
                'MAC Address'    = $mac
                'IP Address'     = $ipv4
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
                Write-Host "Defender detection for $hostName added to CSV."
            } catch {
                Write-Host "Error appending to CSV: $_"
            }
        } elseif ($defenderResults -eq "No threats detected.") {
            $resultObj = [PSCustomObject]@{
                'MAC Address'    = $mac
                'IP Address'     = $ipv4
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
                Write-Host "No threats for $hostName, added to CSV."
            } catch {
                Write-Host "Error appending to CSV: $_"
            }
        } else {
            $resultObj = [PSCustomObject]@{
                'MAC Address'    = $mac
                'IP Address'     = $ipv4
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
                Write-Host "Unknown result for $hostName, added to CSV."
            } catch {
                Write-Host "Error appending to CSV: $_"
            }
        }
    } catch {
        $errorMsg = $_.ToString()
        $resultObj = [PSCustomObject]@{
            'MAC Address'    = $mac
            'IP Address'     = $ipv4
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
            Write-Host "Defender error for $hostName added to CSV."
        } catch {
            Write-Host "Error appending to CSV: $_"
        }
    }
}

# Loop through each workgroup host (with per-host credentials)
foreach ($workgroupHost in $workgroupHosts) {
    $hostName = $workgroupHost.IP
    $workgroupUsername = if ($workgroupHost.Username) { $workgroupHost.Username } else { $defaultWorkgroupUsername }
    $workgroupPassword = if ($workgroupHost.Password) { $workgroupHost.Password } else { $defaultWorkgroupPassword }
    Write-Host ""
    Write-Host "Processing Workgroup Hostname: $hostName"
    $netInfo = Get-HostNetworkInfo -ComputerName $hostName -IsWorkgroup:$true -Username $workgroupUsername -Password $workgroupPassword
    $ipv4 = if ($netInfo.IPv4) { [string]$netInfo.IPv4 } else { "N/A" }
    $mac = if ($netInfo.MAC) { $netInfo.MAC } else { "N/A" }

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

    try {
        $securePassword = ConvertTo-SecureString $workgroupPassword -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($workgroupUsername, $securePassword)
        $defenderResults = Invoke-Command -ComputerName $hostName -ScriptBlock {
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
        } -Credential $cred -ErrorAction Stop
        if ($defenderResults -is [System.Array]) {
            foreach ($det in $defenderResults) {
                $resultObj = [PSCustomObject]@{
                    'MAC Address'    = $mac
                    'IP Address'     = $ipv4
                    'Computer Name'  = $actualHostName
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
                    Write-Host "Defender detection for $actualHostName ($hostName) added to CSV."
                } catch {
                    Write-Host "Error appending to CSV: $_"
                }
            }
        } elseif ($defenderResults -is [PSCustomObject]) {
            $resultObj = [PSCustomObject]@{
                'MAC Address'    = $mac
                'IP Address'     = $ipv4
                'Computer Name'  = $actualHostName
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
                Write-Host "Defender detection for $actualHostName ($hostName) added to CSV."
            } catch {
                Write-Host "Error appending to CSV: $_"
            }
        } elseif ($defenderResults -eq "No threats detected.") {
            $resultObj = [PSCustomObject]@{
                'MAC Address'    = $mac
                'IP Address'     = $ipv4
                'Computer Name'  = $actualHostName
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
                Write-Host "No threats for $actualHostName ($hostName), added to CSV."
            } catch {
                Write-Host "Error appending to CSV: $_"
            }
        } else {
            $resultObj = [PSCustomObject]@{
                'MAC Address'    = $mac
                'IP Address'     = $ipv4
                'Computer Name'  = $actualHostName
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
                Write-Host "Unknown result for $actualHostName ($hostName), added to CSV."
            } catch {
                Write-Host "Error appending to CSV: $_"
            }
        }
    } catch {
        $errorMsg = $_.ToString()
        $resultObj = [PSCustomObject]@{
            'MAC Address'    = $mac
            'IP Address'     = $ipv4
            'Computer Name'  = $actualHostName
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
            Write-Host "Defender error for $actualHostName ($hostName) added to CSV."
        } catch {
            Write-Host "Error appending to CSV: $_"
        }
    }
}

Write-Host "Script finished processing."
