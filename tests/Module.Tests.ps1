BeforeDiscovery {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $ModuleManifest -Force
    $commands = @((Get-Module KRSSecOps).ExportedFunctions.Keys | ForEach-Object { @{ Name = $_ } })
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $ModuleManifest -Force
    $sourceRoot = Join-Path $PSScriptRoot '..' 'src' 'KRSSecOps'
    $publicFiles = Get-ChildItem -Path (Join-Path $sourceRoot 'Public') -Filter '*.ps1' -Recurse
    $allSource = Get-ChildItem -Path $sourceRoot -Filter '*.ps1' -Recurse
}

Describe 'Module structure' {
    It 'has a valid manifest' {
        { Test-ModuleManifest -Path $ModuleManifest -ErrorAction Stop } | Should -Not -Throw
    }

    It 'exports exactly the functions in Public/' {
        @((Get-Module KRSSecOps).ExportedFunctions.Keys | Sort-Object) | Should -Be @($publicFiles.BaseName | Sort-Object)
    }

    It 'lists every public function in FunctionsToExport' {
        $manifest = Import-PowerShellDataFile -Path $ModuleManifest
        @($manifest.FunctionsToExport | Sort-Object) | Should -Be @($publicFiles.BaseName | Sort-Object)
    }

    It 'uses the KRS noun prefix and approved verbs' {
        $approved = (Get-Verb).Verb
        foreach ($name in (Get-Module KRSSecOps).ExportedFunctions.Keys) {
            $verb, $noun = $name -split '-', 2
            $verb | Should -BeIn $approved -Because "$name must use an approved verb"
            $noun | Should -BeLike 'KRS*' -Because "$name must use the KRS prefix"
        }
    }
}

Describe 'Help for <Name>' -ForEach $commands {
    BeforeAll {
        $help = Get-Help -Name $Name -Full
        $common = [System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
        $parameters = (Get-Command -Name $Name).Parameters.Keys | Where-Object { $_ -notin $common }
    }

    It 'has a synopsis' {
        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Synopsis | Should -Not -BeLike "$Name*" -Because 'a synopsis that starts with the command name is the auto-generated syntax'
    }

    It 'has a description' {
        ($help.description.Text -join '') | Should -Not -BeNullOrEmpty
    }

    It 'has at least one example' {
        @($help.examples.example).Count | Should -BeGreaterThan 0
    }

    It 'documents every parameter' {
        foreach ($parameter in $parameters) {
            $entry = $help.parameters.parameter | Where-Object name -eq $parameter
            ($entry.description.Text -join '') | Should -Not -BeNullOrEmpty -Because "-$parameter needs a .PARAMETER entry"
        }
    }
}

Describe 'Code standards' {
    It 'every script parses without errors' {
        $repoRoot = Join-Path $PSScriptRoot '..'
        $scripts = Get-ChildItem -Path (Join-Path $repoRoot 'src'), (Join-Path $repoRoot 'setup'), (Join-Path $repoRoot 'build') -Recurse -Include '*.ps1', '*.psm1', '*.psd1' -File
        foreach ($script in $scripts) {
            $tokens = $null
            $parseErrors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$parseErrors)
            @($parseErrors).Count | Should -Be 0 -Because "$($script.Name) must parse: $(@($parseErrors).Message -join '; ')"
        }
    }

    It 'never uses Write-Host in module code' {
        $allSource | Select-String -Pattern '\bWrite-Host\b' | Should -BeNullOrEmpty
    }

    It 'routes every Graph call through Invoke-KRSGraphRequest' {
        $allSource | Where-Object Name -ne 'Invoke-KRSGraphRequest.ps1' |
            Select-String -Pattern '\bInvoke-MgGraphRequest\b' | Should -BeNullOrEmpty
    }

    It 'routes every Exchange and Purview command through Invoke-KRSExoCommand' {
        # Direct calls would skip -ErrorAction Stop, so a refused write could look like a success.
        $pattern = '(^\s*|[|;=({]\s*)(Get|Set|New|Remove)-(Mailbox|CASMailbox|InboxRule|Label|LabelPolicy|DlpCompliance\w+|RetentionCompliance\w+|TransportRule|TransportConfig|AcceptedDomain)\b'
        $allSource | Where-Object Name -ne 'Exchange.ps1' | Select-String -Pattern $pattern | Should -BeNullOrEmpty
    }

    It 'never references client secrets' {
        $allSource | Select-String -Pattern 'ClientSecret|client_secret' | Should -BeNullOrEmpty
    }

    It 'enables strict mode' {
        Get-Content (Join-Path $sourceRoot 'KRSSecOps.psm1') -Raw | Should -Match 'Set-StrictMode -Version Latest'
    }

    It 'keeps settings.json out of source control' {
        $repoRoot = Join-Path $PSScriptRoot '..'
        Get-Content (Join-Path $repoRoot '.gitignore') | Should -Contain 'src/KRSSecOps/Config/settings.json'
        if ((Get-Command git -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $repoRoot '.git'))) {
            git -C $repoRoot ls-files -- 'src/KRSSecOps/Config/settings.json' | Should -BeNullOrEmpty
        }
    }

    It 'ships an example settings file with placeholders only' {
        $example = Get-Content (Join-Path $sourceRoot 'Config' 'settings.example.json') -Raw | ConvertFrom-Json
        $example.TenantId | Should -BeLike '<*>'
        $example.ClientId | Should -BeLike '<*>'
        $example.CertificateThumbprint | Should -BeLike '<*>'
    }
}
