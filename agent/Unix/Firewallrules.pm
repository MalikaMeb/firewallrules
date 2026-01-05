# Plugin "Firewall Rules" OCSInventory
# Author: Léa DROGUET
# Contributor : Malika Mebrouk (rewrites parsing to be chain-aware (INPUT/OUTPUT/FORWARD) for Direction, uses verbose iptables output per chain, properly parses and maps protocol numbers, extracts comments and src/dst ports (including ranges), tracks interfaces and other flags, IPV6 support)

package Ocsinventory::Agent::Modules::Firewallrules;

sub new {
    my ($class, $context) = @_;
    my $self = {};
    bless $self, $class;

    $self->{logger} = Ocsinventory::Logger->new({
        config => $context->{config}
    });
    $self->{logger}->{header} = "[firewallrules]";
    $self->{context} = $context;
    $self->{structure} = {
        name => "firewallrules",
        inventory_handler => "firewallrules_inventory_handler",
    };

    # Static protocol map including IPv4 and IPv6 essential protocols
    $self->{proto_map} = {
        # IPv4 protocols
        0  => 'IP',
        1  => 'ICMP',
        2  => 'IGMP',
        3  => 'GGP',
        4  => 'IP-ENCAP',
        5  => 'ST',
        6  => 'TCP',
        7  => 'CBT',
        8  => 'EGP',
        9  => 'IGP',
        12 => 'PUP',
        17 => 'UDP',
        20 => 'HMP',
        22 => 'XNS-IDP',
        27 => 'RDP',
        29 => 'ISO-TP4',
        33 => 'DCCP',
        36 => 'XTP',
        37 => 'DDP',
        # IPv6 protocols
        41  => 'IPv6',
        43  => 'IPv6-Route',
        44  => 'IPv6-Frag',
        46  => 'RSVP',
        47  => 'GRE',
        50  => 'IPSEC-ESP',
        51  => 'IPSEC-AH',
        58  => 'IPv6-ICMP',
        59  => 'IPv6-NoNxt',
        60  => 'IPv6-Opts',
        88  => 'EIGRP',
        89  => 'OSPFIGP',
        103 => 'PIM',
        108 => 'IPCOMP',
        132 => 'SCTP',
    };

    return $self;
}

sub firewallrules_inventory_handler {
    my ($self) = @_;
    my $logger = $self->{logger};
    my $common = $self->{context}->{common};
    my $current_chain = '';
    my %proto_map = %{ $self->{proto_map} };

    foreach my $line (_getFirewallRules()) {
        next if $line =~ /^pkts\s+bytes\s+target/i;
        next if $line =~ /^\s*$/;
        next if $line =~ /description/i;

        if ($line =~ /^Chain\s+(\S+)/) {
            my $chain = $1;
            $chain =~ s/\(IPv[46]\)//;   # remove (IPv4) or (IPv6) suffix
            $current_chain = $chain;
            next;
        }

        my $direction = "iptables";
        if ($current_chain eq 'INPUT') {
            $direction = "INPUT";
        } elsif ($current_chain eq 'OUTPUT') {
            $direction = "OUTPUT";
        } elsif ($current_chain eq 'FORWARD') {
            $direction = "FORWARD";
        }

        # Trim the line first
        $line =~ s/^\s+|\s+$//g;
        
        # Skip empty lines after trimming
        next if $line eq '';
        
        # Split line on whitespace to handle variable spacing
        my @fields = split(/\s+/, $line);
        
        # Need at least 8 fields (pkts bytes target prot opt in out source destination)
        if (@fields >= 8) {
            my ($pkts, $bytes, $action, $protocol_num, $opt, $in_if, $out_if, $source, $destination);
            
            # Standard format: pkts bytes target prot opt in out source dest [rest]
            $pkts = $fields[0];
            $bytes = $fields[1];
            $action = $fields[2];
            $protocol_num = $fields[3];
            $opt = $fields[4];
            $in_if = $fields[5];
            $out_if = $fields[6];
            $source = $fields[7];
            $destination = $fields[8] // '';  # May not exist for 8-field lines
            
            # Rest of the fields (if any) - join remaining fields beyond position 8
            my $rest = (@fields > 9) ? join(' ', @fields[9..$#fields]) : '';

            # Skip header lines
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

            # Remove non-digit chars and map number to name
            $protocol_num =~ s/\D//g;
            my $protocol = exists $proto_map{$protocol_num} ? $proto_map{$protocol_num} : $protocol_num;

            # Extract comment enclosed in /* ... */
            my $comment = '';
            if ($rest =~ /\/\*\s*(.*?)\s*\*\//) {
                $comment = $1;
                $rest =~ s/\/\*\s*\Q$comment\E\s*\*\///g;
            }

            # Extract destination ports
            my $dst_port = '';
            if ($rest =~ /dpts?:([\d:]+)/) {
                $dst_port = $1;
                $rest =~ s/dpts?:[\d:]+//g;
            }

            # Extract source ports
            my $src_port = '';
            if ($rest =~ /spts?:([\d:]+)/) {
                $src_port = $1;
                $rest =~ s/spts?:[\d:]+//g;
            }

            $rest =~ s/^\s+|\s+$//g;
            my $other = $rest;

            if (defined $in_if && $in_if ne '*' && $in_if ne '') {
                $other = "in = $in_if" . ($other ? " $other" : '');
            }
            if (defined $out_if && $out_if ne '*' && $out_if ne '') {
                $other = $other ? "$other out = $out_if" : "out = $out_if";
            }

            $logger->debug("Parsed rule: action=$action, protocol=$protocol, source=$source, source_port=$src_port, destination=$destination, destination_port=$dst_port, comment=$comment, other=$other, chain=$current_chain");

            push @{$common->{xmltags}->{FIREWALLRULES}}, {
                DIRECTION        => [$direction],
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
            # Enhanced error message with field count
            my $field_count = scalar(@fields);
            $logger->debug("Warning: Could not parse firewall rule line (found $field_count fields, need 8+): $line");
        }
    }
}

sub _getFirewallRules {
    my @all_rules;
    for my $cmd (['iptables', 'IPv4'], ['ip6tables', 'IPv6']) {
        my ($bin, $ver) = @$cmd;
        for my $chain ('INPUT', 'OUTPUT', 'FORWARD') {
            push @all_rules, "Chain $chain ($ver)\n";
            my @rules = `$bin -L $chain -n -v 2>/dev/null`;
            push @all_rules, @rules;
        }
    }
    return @all_rules;
}

1;
