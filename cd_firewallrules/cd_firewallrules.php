<?php
// Plugin "Firewall Rules" OCSInventory
// Author: Léa DROGUET
// Contributor : Malika Mebrouk (adding columns for direction, source/destination ports, comments, and other metadata)
/**
 * This file is used to build a table referring to the plugin and define its
 * default columns as well as SQL request.
 */

if (AJAX) {
    parse_str($protectedPost['ocs']['0'], $params);
    $protectedPost += $params;
    ob_start();
    $ajax = true;
} else {
    $ajax = false;
}

// print a title for the table
print_item_header($l->g(1234));

if (!isset($protectedPost['SHOW'])) {
    $protectedPost['SHOW'] = 'NOSHOW';
}

// form details and tab options
$form_name = "firewall";
$table_name = $form_name;
$tab_options = $protectedPost;
$tab_options['form_name'] = $form_name;
$tab_options['table_name'] = $table_name;

$item = info($protectedGet, $protectedPost['systemid'] ?? '');

echo open_form($form_name);

if (preg_match('/unix/', $item->USERAGENT)) {
    $list_fields = array(
        'Direction'        => 'DIRECTION',
        'Source'           => 'SOURCE',
        'Source Port'      => 'SOURCE_PORT',
        'Destination'      => 'DESTINATION',
        'Destination Port' => 'DESTINATION_PORT',
        'Action'           => 'ACTION',
        'Protocol'         => 'PROTOCOL',
        'Comment'          => 'COMMENT',
        'Other'            => 'OTHER',
    );
} else {
    $list_fields = array(
        'Direction'        => 'DIRECTION',
        'Enabled'          => 'ENABLED',
        'Source'           => 'SOURCE',
        'Source Port'      => 'SOURCE_PORT',
        'Destination'      => 'DESTINATION',
        'Destination Port' => 'DESTINATION_PORT',
        'Action'           => 'ACTION',
        'Protocol'         => 'PROTOCOL',
        'Comment'          => 'COMMENT',
        'Other'            => 'OTHER',
    );
}

// Columns to include at any time and default columns
$list_col_cant_del = $list_fields;
$default_fields = $list_fields;

// Select columns for table display
$sql = prepare_sql_tab($list_fields);
$sql['SQL']  .= " FROM firewallrules WHERE (hardware_id = $systemid)";

array_push($sql['ARG'], $systemid);
$tab_options['ARG_SQL'] = $sql['ARG'];
$tab_options['ARG_SQL_COUNT'] = $systemid;

ajaxtab_entete_fixe($list_fields, $default_fields, $tab_options, $list_col_cant_del);

echo close_form();

if ($ajax) {
    ob_end_clean();
    tab_req($list_fields, $default_fields, $list_col_cant_del, $sql['SQL'], $tab_options);
    ob_start();
}
?>
