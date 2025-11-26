# Plugin "Firewall Rules" OCSInventory
# Author: Lea DROGUET
# Contributor : Malika Mebrouk (rewrites parsing to be chain-aware (INPUT/OUTPUT/FORWARD), uses verbose iptables output per chain, properly parses and maps protocol numbers, extracts comments and src/dst ports (including ranges), tracks interfaces and other flags)

package Ocsinventory::Agent::Modules::Firewallrules;

sub new {
    my $name = "firewallrules";
    my (undef, $context) = @_;
    my $self = {};

    $self->{logger} = new Ocsinventory::Logger({
        config => $context->{config}
    });
    $self->{logger}->{header} = "[$name]";
    $self->{context} = $context;
    $self->{structure} = {
        name => $name,
        inventory_handler => $name . "_inventory_handler",
    };
    bless $self;
}

my %proto_map = (
    0 => 'IP',    1 => 'ICMP',   2 => 'IGMP',   3 => 'GGP',
    4 => 'IP-ENCAP', 5 => 'ST',  6 => 'TCP',    8 => 'EGP',
    9 => 'IGP',   12 => 'PUP',   17 => 'UDP'
); #add others if needed (see /etc/protocols)

sub firewallrules_inventory_handler {
    my $self = shift;
    my $logger = $self->{logger};
    my $common = $self->{context}->{common};
    my $current_chain = '';

    foreach my $line (_getFirewallRules()) {
        next if $line =~ /^pkts\s+bytes\s+target/i;
        next if $line =~ /^\s*$/;
        next if $line =~ /description/i;

        if ($line =~ /^Chain\s+(\S+)/) {
            $current_chain = $1;
            next;
        }

        my $displayName = "iptables";
        if ($current_chain eq 'INPUT') {
            $displayName = "INPUT";
        } elsif ($current_chain eq 'OUTPUT') {
            $displayName = "OUTPUT";
        } elsif ($current_chain eq 'FORWARD') {
            $displayName = "FORWARD";
        }

        if (
            $line =~ /^\s*
            (\S+)\s+         # pkts
            (\S+)\s+         # bytes
            (\S+)\s+         # action
            (\S+)\s+         # protocol_num
            (\S+)\s+         # opt
            (\S+)\s+         # in_if
            (\S+)\s+         # out_if
            (\S+)\s+         # source
            (\S+)\s+         # destination
            (.*)             # rest
            $/x
        ) {
            my ($pkts, $bytes, $action, $protocol_num, $opt, $in_if, $out_if, $source, $destination, $rest) =
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

            # Skip header lines by comparing lowercase strings
            if (
                lc($source) eq 'source' or
                lc($destination) eq 'destination' or
                lc($action) eq 'target' or
                lc($protocol_num) eq 'prot' or
                lc($in_if) eq 'in' or
                lc($out_if) eq 'out'
            ) {
                next;
            }

            my $protocol = exists $proto_map{$protocol_num} ? $proto_map{$protocol_num} : $protocol_num;

            # Extract comment enclosed in /* ... */
            my $comment = '';
            if ($rest =~ /\/\*\s*(.*?)\s*\*\//) {
                $comment = $1;
                $rest =~ s/\/\*\s*\Q$comment\E\s*\*\///g;
            }

            # Extract destination port(s) - support range/multi e.g. 67:68
            my $dst_port = '';
            if ($rest =~ /dpts?:([\d:]+)/) {
                $dst_port = $1;
                $rest =~ s/dpts?:[\d:]+//g;
            }

            # Extract source port(s) - support range/multi e.g. 1024:65535
            my $src_port = '';
            if ($rest =~ /spts?:([\d:]+)/) {
                $src_port = $1;
                $rest =~ s/spts?:[\d:]+//g;
            }

            # Trim leading/trailing whitespace in rest
            $rest =~ s/^\s+|\s+$//g;
            my $other = $rest;

            # Append input/output interfaces to other info if present
            if (defined $in_if && $in_if ne '*' && $in_if ne '') {
                $other = "in = $in_if" . ($other ? " $other" : '');
            }
            if (defined $out_if && $out_if ne '*' && $out_if ne '') {
                $other = $other ? "$other out = $out_if" : "out = $out_if";
            }

            $logger->debug("Parsed rule: action=$action, protocol=$protocol, source=$source, source_port=$src_port, destination=$destination, destination_port=$dst_port, comment=$comment, other=$other, chain=$current_chain");

            push @{$common->{xmltags}->{FIREWALLRULES}}, {
                DISPLAYNAME      => [$displayName],
                SOURCE           => [$source],
                SOURCE_PORT      => [$src_port],
                DESTINATION      => [$destination],
                DESTINATION_PORT => [$dst_port], 
                ACTION           => [$action],
                PROTOCOL         => [$protocol],
                COMMENT          => [$comment],
                OTHER            => [$other]
            };
        } else {
            $logger->debug("Warning: Could not parse firewall rule line: $line");
        }
    }
}

sub _getFirewallRules {
    my @all_rules;
    for my $chain ('INPUT', 'OUTPUT', 'FORWARD') {
        push @all_rules, "Chain $chain\n";
        push @all_rules, `iptables -L $chain -n -v`;
    }
    return @all_rules;
}

1;

