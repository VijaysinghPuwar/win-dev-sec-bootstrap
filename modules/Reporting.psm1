#Requires -Version 5.1
<#
    Console summaries for provisioning runs.
#>
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'Common.psm1')

function Write-ProvisioningSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Result)

    $order = @('Failed', 'Manual', 'Installed', 'Upgraded', 'Current', 'Planned', 'Skipped')
    $level = @{ Failed = 'Error'; Manual = 'Warn'; Installed = 'Ok'; Upgraded = 'Ok'; Current = 'Ok'; Planned = 'Plan'; Skipped = 'Warn' }
    Write-Status Info 'Provisioning summary'
    foreach ($status in $order) {
        $items = @($Result | Where-Object { $_.Status -eq $status })
        if ($items.Count -eq 0) { continue }
        Write-Status $level[$status] ('{0} ({1})' -f $status, $items.Count)
        foreach ($item in $items) {
            $label = if ($item.Id) { '{0,-7} {1} [{2}]' -f $item.Source, $item.Name, $item.Id } else { '{0,-7} {1}' -f $item.Source, $item.Name }
            if ($status -in @('Failed', 'Manual', 'Skipped')) { $label = "$label - $($item.Detail)" }
            Write-Status Detail $label
        }
    }
    if (@($Result | Where-Object { $_.RestartRequired }).Count -gt 0) {
        Write-Status Warn 'At least one change needs a restart to finish.'
    }
}

Export-ModuleMember -Function Write-ProvisioningSummary
