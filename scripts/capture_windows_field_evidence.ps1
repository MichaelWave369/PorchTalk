<#
.SYNOPSIS
PorchTalk: capture a read-only Windows observation into a new, local JSON file.
.DESCRIPTION
Wraps inspect_windows_readiness.ps1 and writes EXACTLY ONE create-only JSON
report to a pre-existing local directory. Does NOT create sockets, change
firewall rules, open private identity vaults, connect peers or authorize work.
The printed SHA-256 is an integrity checksum, NOT a signature or attestation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LocalIPv4,

    [Parameter(Mandatory = $true)]
    [string]$PeerIPv4,

    [Parameter(Mandatory = $true)]
    [ValidateRange(49152, 65535)]
    [int]$Port,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Deliberately do not create the output directory: user selects an existing
# protected, local destination. Do not alter or move any original files.
if (!(Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
    throw 'DENIED: output directory must already exist'
}
$folder = Get-Item -LiteralPath $OutputDirectory -ErrorAction Stop
$current = $folder
while ($null -ne $current) {
    if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'DENIED: symlinked or redirected evidence folder'
    }
    $current = $current.Parent
}

$inspector = Join-Path $PSScriptRoot 'inspect_windows_readiness.ps1'
if (!(Test-Path -LiteralPath $inspector -PathType Leaf)) {
    throw 'DENIED: read-only inspector is missing'
}

# Only one tool supplies the observation, maintaining the same schema used
# by the already-tested React Evidence Desk. Inputs may be fictional examples,
# but an output is NEVER proof that a physical interface was actually found.
$rawLines = & $inspector -LocalIPv4 $LocalIPv4 -PeerIPv4 $PeerIPv4 -Port $Port
$json = ($rawLines -join [Environment]::NewLine).Trim()
try {
    $report = ConvertFrom-Json -InputObject $json -ErrorAction Stop
}
catch {
    throw 'DENIED: inspector did not return valid JSON'
}
if ($report.schema -ne 'PORCHTALK_WINDOWS_READINESS_V1' -or
    $report.status -ne 'OBSERVATION_ONLY_NOT_AN_AUTHORIZATION' -or
    $report.static_rfc1918_pair_valid -ne $true -or
    $report.sockets_opened_by_this_script -ne $false -or
    $report.firewall_modified_by_this_script -ne $false -or
    $report.private_keys_read_by_this_script -ne $false -or
    $report.compute_authorized -ne $false) {
    throw 'DENIED: unsafe or inconsistent observation; no evidence file created'
}

$now = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$unique = ([Guid]::NewGuid().ToString('N')).Substring(0, 12)
$name = 'porchtalk-windows-' + $now + '-' + $unique + '.json'
$path = Join-Path $folder.FullName $name
$bytes = ([System.Text.UTF8Encoding]::new($false)).GetBytes($json + [Environment]::NewLine)
if ($bytes.Length -gt 8192) {
    throw 'DENIED: observation exceeds browser import size limit'
}

# Exclusive creation is the core copy-only invariant: no existing file may be
# replaced, renamed or altered. A write failure may leave a partial new file;
# it will fail evidence import and must be inspected manually.
$stream = $null
try {
    $stream = [System.IO.FileStream]::new(
        $path,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
}
finally {
    if ($null -ne $stream) {
        $stream.Dispose()
    }
}
$digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
[pscustomobject][ordered]@{
    schema = 'PORCHTALK_FIELD_CAPTURE_REPORT_V1'
    status = 'LOCAL_FILE_WRITTEN_OBSERVATION_ONLY'
    output_path = $path
    report_sha256 = $digest
    local_interface_claimed = [bool]$report.local_ipv4_observed_on_interface
    local_ipv4_entered = $report.local_ipv4_entered
    peer_ipv4_entered = $report.peer_ipv4_entered
    port = [int]$report.proposed_port
    operator_review_required = $true
    report_is_independently_attested = $false
    network_connection_attempted = $false
    compute_authorized = $false
} | ConvertTo-Json -Depth 4
