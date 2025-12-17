# Plugin "Firewall Rules" OCSInventory
# Author: Léa DROGUET
# Contributor : Malika Mebrouk (added fields: DIRECTION, SOURCE_PORT, DESTINATION_PORT, COMMENT, and OTHER)

package Apache::Ocsinventory::Plugins::Firewallrules::Map;

use strict;
use Apache::Ocsinventory::Map;

$DATA_MAP{firewallrules} = {
   mask => 0,
   multi => 1,
   auto => 1,
   delOnReplace => 1,
   sortBy => 'RULE_ID',
   writeDiff => 0,
   cache => 0,
   fields => {
       RULE_ID          => {},
       DIRECTION        => {},
       SOURCE           => {},
       SOURCE_PORT      => {},
       DESTINATION      => {},
       DESTINATION_PORT => {},
       ACTION           => {},
       PROTOCOL         => {},
       COMMENT          => {},
       OTHER            => {},
   }
};

1;
