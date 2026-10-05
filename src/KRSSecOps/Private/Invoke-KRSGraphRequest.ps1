function Invoke-KRSGraphRequest {
    <#
    .SYNOPSIS
        Single entry point for every Microsoft Graph call the module makes.
    .DESCRIPTION
        Adds what raw Invoke-MgGraphRequest calls leave to the caller:
        - relative URIs (defaults to the v1.0 endpoint)
        - paging through @odata.nextLink with -All
        - retry with Retry-After or exponential backoff on 429, 503 and 504
        - objects streamed to the pipeline one at a time, so large tenants do not build huge arrays
        Keeping all Graph traffic here also gives the tests one seam to mock.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [hashtable]$Headers = @{},

        [Parameter()]
        [switch]$All,

        [Parameter()]
        [ValidateRange(0, 10)]
        [int]$MaxRetries = 5
    )

    $next = if ($Uri -match '^https://') { $Uri } else { 'https://graph.microsoft.com/v1.0/' + $Uri.TrimStart('/') }

    do {
        $attempt = 0
        $response = $null
        while ($true) {
            $request = @{
                Uri         = $next
                Method      = $Method
                Headers     = $Headers
                OutputType  = 'PSObject'
                ErrorAction = 'Stop'
            }
            if ($PSBoundParameters.ContainsKey('Body')) {
                $request.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 -Compress }
                $request.ContentType = 'application/json'
            }

            try {
                $script:KRSGraphRequestCount++
                $response = Invoke-MgGraphRequest @request
                break
            }
            catch {
                $status = Get-KRSHttpStatus -ErrorRecord $_
                if ($status -in 429, 503, 504 -and $attempt -lt $MaxRetries) {
                    $attempt++
                    $delay = Get-KRSRetryDelay -ErrorRecord $_ -Attempt $attempt
                    Write-KRSLog -Level Warning -Action 'GraphRetry' -Target $next -Result Skipped -Message "HTTP $status, attempt $attempt of $MaxRetries, waiting $delay s"
                    Start-Sleep -Seconds $delay
                    continue
                }
                throw
            }
        }

        $value = Get-KRSValue -InputObject $response -Name 'value'
        if ($null -ne $response -and $response.PSObject.Properties['value']) {
            foreach ($item in @($value)) { $item }
            $next = if ($All) { Get-KRSValue -InputObject $response -Name '@odata.nextLink' } else { $null }
        }
        else {
            if ($null -ne $response) { $response }
            $next = $null
        }
    } while ($next)
}

function Get-KRSHttpStatus {
    # Best-effort HTTP status from an Invoke-MgGraphRequest error; $null when none can be found.
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $exception = $ErrorRecord.Exception
    $response = Get-KRSValue -InputObject $exception -Name 'Response'
    $code = Get-KRSValue -InputObject $response -Name 'StatusCode'
    if ($null -ne $code) { return [int]$code }

    switch -Regex ($exception.Message) {
        'TooManyRequests|\b429\b' { return 429 }
        'ServiceUnavailable|\b503\b' { return 503 }
        'GatewayTimeout|\b504\b' { return 504 }
        'NotFound|\b404\b' { return 404 }
        'Forbidden|Authorization_RequestDenied|\b403\b' { return 403 }
        'BadRequest|\b400\b' { return 400 }
    }
    $null
}

function Get-KRSRetryDelay {
    # Honours Retry-After when Graph sends it, otherwise 2, 4, 8 ... seconds capped at 60.
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory)]
        [int]$Attempt
    )

    $headers = Get-KRSValue -InputObject (Get-KRSValue -InputObject $ErrorRecord.Exception -Name 'Response') -Name 'Headers'
    $retryAfter = Get-KRSValue -InputObject $headers -Name 'RetryAfter'
    $delta = Get-KRSValue -InputObject $retryAfter -Name 'Delta'
    if ($delta) { return [int][math]::Ceiling($delta.TotalSeconds) }
    [int][math]::Min(60, [math]::Pow(2, $Attempt))
}
