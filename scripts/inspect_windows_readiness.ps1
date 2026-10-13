<#
.SYNOPSIS
PorchTalk Gate B4e. Read-only Windows LAN readiness observation.
.DESCRIPTION
Reads Windows network interfaces, firewall profile and current port-listener
status. DOES NOT open a socket, edit firewall rules, read private keys, perform
device pairing or authorize any PorchTalk connection. A returned report is
NEVER an approval to open a real LAN listener.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LocalIPv4,

    [Parameter(Mandatory = $true)]
    [string]$PeerIPv4,

    [Parameter(Mandatory = $true)]
    [ValidateRange(49152,65535)]
    [int]$Port
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-PrivateCanonicalIPv4 {
    param([string]$Value)
    if ($Value -notmatch '^[0-9]{1,3}(\.[0-9]{1,3}){3}$') {
        return $false
    }
    $octets = $Value.Split(".")
    foreach ($octet in $octets) {
        if ($octet.Length -gt 1 -and $octet.StartsWith("0")) {
            return $false
        }
        if ([int]$octet -gt 255) {
            return $false
        }
    }
    $a = [int]$octets[0]
    $b = [int]$octets[1]
    return (
        $a -eq 10 -or
        ($a -eq 172 -and $b -ge 16 -and $b -le 31) -or
        ($a -eq 192 -and $b -eq 168)
    )
}

$localPrivate = Test-PrivateCanonicalIPv4 -Value $LocalIPv4
$peerPrivate = Test-PrivateCanonicalIPv4 -Value $PeerIPv4
$same24 = $false
if ($localPrivate -and $peerPrivate -and $LocalIPv4 -ne $PeerIPv4) {
    $a = $LocalIPv4.Split(".")
    $b = $PeerIPv4.Split(".")
    $same24 = ($a[0] -eq $b[0] -and $a[1] -eq $b[1] -and $a[2] -eq $b[2])
    $lastA = [int]$a[3]
    $lastB = [int]$b[3]
    $same24 = $same24 -and ($lastA -ne 0) -and ($lastA -ne 255) -and ($lastB -ne 0) -and ($lastB -ne 255)
}

$report = [ordered]@{
    schema = "PORCHTALK_WINDOWS_READINESS_V1"
    status = "OBSERVATION_ONLY_NOT_AN_AUTHORIZATION"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    local_ipv4_entered = $LocalIPv4
    peer_ipv4_entered = $PeerIPv4
    proposed_port = $Port
    static_rfc1918_pair_valid = [bool]($localPrivate -and $peerPrivate -and $same24)
    local_ipv4_observed_on_interface = $false
    observed_interface_index = $null
    observed_prefix_length = $null
    observed_network_category = $null
    firewall_active_profile_enabled = $null
    proposed_port_already_listening = $null
    inspection_errors = @()
    unresolved_manual_checks = @(
        "VERIFY_PEER_PUBLIC_KEY_FINGERPRINT_OUT_OF_BAND"
        "INSPECT_VAULT_AND_TRUST_DATABASE_WINDOWS_ACLS"
        "VERIFY_ROUTER_HAS_NO_PORT_FORWARDING_OR_EXPOSURE"
        "LIMIT_TEMPORARY_INBOUND_FIREWALL_RULE_TO_INTENDED_PEER"
        "VERIFY_PEER_NETWORK_SEGMENT_AND_GUEST_WIFI_ISOLATION"
        "REVIEW_CUSTOM_PROTOCOL_SECURITY_BEFORE_ANY_REAL_USE"
    )
    sockets_opened_by_this_script = $false
    firewall_modified_by_this_script = $false
    private_keys_read_by_this_script = $false
    compute_authorized = $false
}

try {
    $records = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $LocalIPv4 -ErrorAction Stop)
    if ($records.Count -gt 0) {
        $item = $records[0]
        $report.local_ipv4_observed_on_interface = $true
        $report.observed_interface_index = [int]$item.InterfaceIndex
        $report.observed_prefix_length = [int]$item.PrefixLength
        try {
            $profile = Get-NetConnectionProfile -InterfaceIndex $item.InterfaceIndex -ErrorAction Stop
            $report.observed_network_category = [string]$profile.NetworkCategory
            $firewallName = if ($profile.NetworkCategory -eq "DomainAuthenticated") {"Domain"} else {[string]$profile.NetworkCategory}
            $firewall = Get-NetFirewallProfile -Name $firewallName -PolicyStore ActiveStore -ErrorAction Stop
            $report.firewall_active_profile_enabled = [bool]$firewall.Enabled
        }
        catch {
            $report.inspection_errors += "ACTIVE_FIREWALL_PROFILE_OR_NETWORK_CATEGORY_UNAVAILABLE"
        }
    }
}
catch {
    $report.inspection_errors += "LOCAL_INTERFACE_LOOKUP_UNAVAILABLE_OR_NOT_FOUND"
}

try {
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop)
    $report.proposed_port_already_listening = ($listeners.Count -gt 0)
}
catch {
    # No existing listener is a normal outcome; cannot distinguish from permissions
    # without a separate low-level inspection. Return unknown, not false.
    $report.proposed_port_already_listening = $null
    $report.inspection_errors += "PORT_LISTENER_STATUS_UNKNOWN"
}

$report | ConvertTo-Json -Depth 6
