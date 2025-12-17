# Plugin "Firewall Rules" OCSInventory
# Author: Léa DROGUET
# Contributor : Malika Mebrouk (changed description to comment and added protocol cleanup)

$ErrorActionPreference = 'SilentlyContinue'

# Protocol number to name mapping (adapted to what you care about)
$proto_map = @{
    0  = 'IP'
    1  = 'ICMP'
    2  = 'IGMP'
    6  = 'TCP'
    17 = 'UDP'
    41 = 'IPv6'
    58 = 'ICMPv6'
}


$rules = Get-NetFirewallRule |
    Select-Object -Property DisplayName, Description, Action, Direction, Enabled, InstanceID

$portsAndProtocols = Get-NetFirewallPortFilter |
    Select-Object -Property LocalPort, Protocol, InstanceID

$xml = ""

foreach ($rule in $rules) {


    $ruleDetails = $portsAndProtocols |
        Where-Object { $_.InstanceID -eq $rule.InstanceID } |
        Select-Object -First 1

    $source      = ""                # keep empty, as in your UI
    $sourcePort  = ""
    $destination = ""
    $destPort    = ""
    $rawProtocol = ""

    if ($ruleDetails) {
        $sourcePort  = $ruleDetails.LocalPort
        $rawProtocol = $ruleDetails.Protocol
    }

    # Normalize protocol
    $cleanProtocol = ""
    if ($rawProtocol -and $rawProtocol -ne 'Any') {
        if ($rawProtocol -match '^\d+$') {
            $num = [int]$rawProtocol
            if ($proto_map.ContainsKey($num)) {
                $cleanProtocol = $proto_map[$num]
            } else {
                $cleanProtocol = $rawProtocol
            }
        } else {
            $cleanProtocol = $rawProtocol
        }
    }

    $xml += "<FIREWALLRULES>`n"
    $xml += "<DISPLAYNAME>$($rule.DisplayName)</DISPLAYNAME>`n"
    $xml += "<SOURCE>$source</SOURCE>`n"
    $xml += "<SOURCE_PORT>$sourcePort</SOURCE_PORT>`n"
    $xml += "<DESTINATION>$destination</DESTINATION>`n"
    $xml += "<DESTINATION_PORT>$destPort</DESTINATION_PORT>`n"
    $xml += "<DIRECTION>$($rule.Direction)</DIRECTION>`n"
    $xml += "<ACTION>$($rule.Action)</ACTION>`n"
    $xml += "<PROTOCOL>$cleanProtocol</PROTOCOL>`n"
    $xml += "<COMMENT>$($rule.Description)</COMMENT>`n"
    $xml += "<OTHER></OTHER>`n"
    $xml += "</FIREWALLRULES>`n"
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::WriteLine($xml)

