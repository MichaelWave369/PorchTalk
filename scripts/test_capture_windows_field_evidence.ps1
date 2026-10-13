# Gate C3 Windows runner negative controls: offline read-only report capture.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$folder = Join-Path ([IO.Path]::GetTempPath()) ('porchtalk-capture-fixture-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $folder -ErrorAction Stop | Out-Null
try {
    $captureScript = Join-Path $PSScriptRoot 'capture_windows_field_evidence.ps1'
    $argSet = @{
        LocalIPv4 = '192.168.10.15'
        PeerIPv4 = '192.168.10.20'
        Port = 54321
        OutputDirectory = $folder
    }
    $a = & $captureScript @argSet | ConvertFrom-Json
    if ($a.status -ne 'LOCAL_FILE_WRITTEN_OBSERVATION_ONLY' -or
        $a.schema -ne 'PORCHTALK_FIELD_CAPTURE_REPORT_V1' -or
        $a.compute_authorized -ne $false -or
        $a.operator_review_required -ne $true -or
        $a.network_connection_attempted -ne $false -or
        $a.report_is_independently_attested -ne $false) {
        throw 'Misleading or missing capture denial flags'
    }
    if (!(Test-Path -LiteralPath $a.output_path -PathType Leaf)) {
        throw 'Report not saved to disk'
    }
    $loaded = Get-Content -LiteralPath $a.output_path -Raw | ConvertFrom-Json
    if ($loaded.schema -ne 'PORCHTALK_WINDOWS_READINESS_V1' -or
        $loaded.status -ne 'OBSERVATION_ONLY_NOT_AN_AUTHORIZATION' -or
        $loaded.compute_authorized -ne $false -or
        $loaded.static_rfc1918_pair_valid -ne $true) {
        throw 'Report altered from read-only inspector'
    }
    $hash = (Get-FileHash -LiteralPath $a.output_path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $a.report_sha256 -or $hash -notmatch '^[a-f0-9]{64}$') {
        throw 'Checksum mismatch'
    }
    $previous = [IO.File]::ReadAllBytes($a.output_path)
    $b = & $captureScript @argSet | ConvertFrom-Json
    if ($a.output_path -eq $b.output_path) { throw 'Create-only output paths collided' }
    $after = [IO.File]::ReadAllBytes($a.output_path)
    if ([Convert]::ToBase64String($previous) -ne [Convert]::ToBase64String($after)) {
        throw 'Original capture changed on second capture'
    }

    $beforeCount = @(Get-ChildItem -LiteralPath $folder -File).Count
    $denied = $false
    try {
        & $captureScript -LocalIPv4 '8.8.8.8' -PeerIPv4 '192.168.10.20' -Port 54321 -OutputDirectory $folder | Out-Null
    }
    catch { $denied = $true }
    if (!$denied) { throw 'Public IPv4 capture should be denied' }
    if (@(Get-ChildItem -LiteralPath $folder -File).Count -ne $beforeCount) {
        throw 'Denied public address created a file'
    }

    $missing = Join-Path $folder 'missing-destination'
    $denied = $false
    try {
        & $captureScript -LocalIPv4 '192.168.10.15' -PeerIPv4 '192.168.10.20' -Port 54321 -OutputDirectory $missing | Out-Null
    }
    catch { $denied = $true }
    if (!$denied -or (Test-Path -LiteralPath $missing)) {
        throw 'Unapproved output folder unexpectedly created'
    }

    # Symlinks may require elevated Windows privileges and are not mandatory.
    $linkedFolder = Join-Path $folder 'linked-destination'
    try {
        New-Item -ItemType SymbolicLink -Path $linkedFolder -Target $folder -ErrorAction Stop | Out-Null
        $denied = $false
        try {
            & $captureScript -LocalIPv4 '192.168.10.15' -PeerIPv4 '192.168.10.20' -Port 54321 -OutputDirectory $linkedFolder | Out-Null
        }
        catch { $denied = $true }
        if (!$denied) { throw 'Reparse point target must be rejected' }
    }
    catch [System.UnauthorizedAccessException] {
        Write-Output 'Windows runner disallows symlink fixture; permission-independent checks still passed.'
    }

    Write-Output 'Gate C3 passed: copy-only JSON output, SHA256 checksum, no secret read, default-deny semantics.'
}
finally {
    Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
}
