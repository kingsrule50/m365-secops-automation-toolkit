@{
    # PSGallery rule set plus formatting and compatibility rules.
    Severity     = @('ParseError', 'Error', 'Warning', 'Information')
    IncludeDefaultRules = $true
    ExcludeRules = @()

    Rules        = @{
        PSUseCompatibleSyntax      = @{
            Enable         = $true
            TargetVersions = @('7.4')
        }
        PSPlaceOpenBrace           = @{
            Enable             = $true
            OnSameLine         = $true
            NewLineAfter       = $true
            IgnoreOneLineBlock = $true
        }
        PSPlaceCloseBrace          = @{
            Enable             = $true
            NewLineAfter       = $true
            IgnoreOneLineBlock = $true
            NoEmptyLineBefore  = $false
        }
        PSUseConsistentIndentation = @{
            Enable              = $true
            IndentationSize     = 4
            Kind                = 'space'
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
        }
        PSAvoidUsingCmdletAliases  = @{ Enable = $true }
    }
}
