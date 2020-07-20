$Logfile = 'FileScannerClient.log'
$uri = 'http://localhost:5000/scan'
$tempDir = 'temp'

Function LogWrite {
    Param ([string]$logstring)

    Add-content $Logfile -value $logstring
}

Write-Output 'File scanner client'
while (1) {
    $mode = Read-Host -Prompt 'To send the exe from specific path -> Press 1
To send the exe of the process that consumes the highest CPU -> Press 2
'
    if ($mode -eq 1) {
        $filePath = Read-Host -Prompt 'Please enter the file path'
    } 
    else {
        if ($mode -eq 2) {
            $highestCPU = Get-Process | Where-Object { $_.ProcessName -ne 'System' } | Sort-Object CPU -descending | Select-Object -First 1
            $procName = $highestCPU.ProcessName
            $filePath = (Get-Process $procName).path | Select-Object -First 1
        }
        else { break }        
    }
    <# Copying file to temp directory to ensure OS does not hold it #>
    if (-not(Test-Path $tempDir)) {
        mkdir $tempDir | Out-Null
    }
    Copy-Item -Path $filePath -Destination $tempDir
    $newPath = $tempDir + "\" + (Split-Path $filePath -leaf)
    $form = @{ file = Get-Item -Path $newPath }
    $result = Invoke-RestMethod -Uri $uri -Method Post -Form $form
    $dateStr = (Get-Date -Format "dd/MM/yyyy HH:mm:ss").ToString()
    $log = $dateStr + " - File " + $newPath + " sent to " + $uri + " for scanning "
    LogWrite $log
    Write-Output ($result | ConvertTo-Json)
}