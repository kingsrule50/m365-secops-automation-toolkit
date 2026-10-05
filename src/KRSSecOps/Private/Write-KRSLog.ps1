function Write-KRSLog {
    <#
    .SYNOPSIS
        Writes one structured JSON-lines audit record for the toolkit's own activity.
    .DESCRIPTION
        Every connect, read, throttle and change is logged with operator, host, correlation ID and result,
        so the automation leaves the same audit trail an enterprise change process expects.
        Logging never stops the calling function: a failed write becomes a warning.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Action,

        [Parameter()]
        [string]$Target = '',

        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Change')]
        [string]$Level = 'Info',

        [Parameter()]
        [ValidateSet('Success', 'Failure', 'Skipped', 'WhatIf')]
        [string]$Result = 'Success',

        [Parameter()]
        [string]$Message = ''
    )

    $logRoot = Get-KRSValue -InputObject $script:KRSConfig -Name 'LogPath'
    if (-not $logRoot) {
        $logRoot = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'KRSSecOps/logs'
    }

    $caller = (Get-PSCallStack | Select-Object -Skip 1 -First 1).FunctionName
    $entry = [ordered]@{
        timestamp     = [datetime]::UtcNow.ToString('o')
        correlationId = $script:KRSCorrelationId
        operator      = [Environment]::UserName
        host          = [Environment]::MachineName
        function      = $caller
        level         = $Level
        action        = $Action
        target        = $Target
        result        = $Result
        message       = $Message
    }

    try {
        if (-not (Test-Path -LiteralPath $logRoot)) {
            $null = New-Item -ItemType Directory -Path $logRoot -Force -WhatIf:$false -Confirm:$false
        }
        $file = Join-Path $logRoot ('KRSSecOps-{0}.jsonl' -f [datetime]::UtcNow.ToString('yyyyMMdd'))
        Add-Content -LiteralPath $file -Value ($entry | ConvertTo-Json -Compress) -Encoding utf8 -WhatIf:$false -Confirm:$false
    }
    catch {
        Write-Warning "KRSSecOps could not write to its log at '$logRoot': $($_.Exception.Message)"
    }

    Write-Verbose ("[{0}] {1} {2} {3}" -f $Level, $Action, $Target, $Message)
}
