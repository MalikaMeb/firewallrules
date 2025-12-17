<?php
/**
 * This function is called on installation and is used to
 * create database schema for the plugin
 */
function extension_install_firewallrules() {
    $commonObject = new ExtensionCommon;
    $commonObject->sqlQuery("DROP TABLE IF EXISTS `firewallrules`");
    $commonObject->sqlQuery(
        "CREATE TABLE IF NOT EXISTS `firewallrules` (
            RULE_ID INT(11) NOT NULL AUTO_INCREMENT,
            HARDWARE_ID INT(11) NOT NULL,
            DIRECTION VARCHAR(255) NOT NULL,
            ENABLED VARCHAR(255) NOT NULL,
            SOURCE VARCHAR(255) NOT NULL,
            SOURCE_PORT VARCHAR(255) DEFAULT NULL,
            DESTINATION VARCHAR(255) NOT NULL,
            DESTINATION_PORT VARCHAR(255) NOT NULL,
            ACTION VARCHAR(255) NOT NULL,
            PROTOCOL VARCHAR(255) NOT NULL,
            COMMENT VARCHAR(255) DEFAULT NULL,
            OTHER VARCHAR(255) DEFAULT NULL,
            PRIMARY KEY (RULE_ID, HARDWARE_ID)
        ) ENGINE=INNODB;"
    );
}

/**
 * This function is called on removal and is used to
 * destroy database schema for the plugin
 */
function extension_delete_firewallrules()
{
    $commonObject = new ExtensionCommon;
    $commonObject->sqlQuery("DROP TABLE IF EXISTS `firewallrules`");
}

/**
 * This function is called on plugin upgrade
 */
function extension_upgrade_firewallrules()
{
    // You may add upgrade logic here if needed in future
}
?>
