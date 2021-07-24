<?php

$xml = simplexml_load_file('file.xml', 'SimpleXMLElement', LIBXML_NOCDATA);

// get host
$tmp = new \stdClass();

// get ip address
$ipAttr = (array)$xml->IP['value'];
$ip = $ipAttr[0];
$tmp->host = $ip;

// get OS
$os = (array)$xml->IP->OS;
$tmp->host_os = $os[0];
$tmp->host_mac = '';
$tmp->host_start = '';
$tmp->host_end = '';
$tmp->plugin = [];

// GET INFO LEVEL VULNERABILITIES
foreach($xml->IP->INFOS->children() as $CAT) {
    
    foreach($CAT->children() as $INFO) {
        $plugin = new \stdClass();
        $plugin->id = (string)$INFO['number'];
        $plugin->name = (string)$INFO->TITLE;
        $plugin->description = preg_replace('/<p>/i', '<br>', (string)$INFO->DIAGNOSIS);
        $plugin->synopsis = preg_replace('/<p>/i', '<br>', (string)$INFO->CONSEQUENCE);
        if(empty($INFO->SOLUTION)) {
            $INFO->SOLUTION = 'N/A';
        } else {
            $INFO->SOLUTION = preg_replace('/<p>/i', '<br>', (string)$INFO->DIAGNOSIS);
        }
        $plugin->solution = (string)$INFO->SOLUTION;
        $plugin->risk = 'None';
        $plugin->output = preg_replace('/<p>/i', '<br>', (string)$INFO->RESULT);
        $plugin->protocol = (string)$CAT['protocol'];
        $plugin->port = (string)$CAT['port'];

        $references = '';
        if(!empty($INFO->VENDOR_REFERENCE_LIST)) {
            foreach($INFO->VENDOR_REFERENCE_LIST->children() as $VENDOR_REFERENCE) {
                $references = (string)$VENDOR_REFERENCE->ID . " - " . $VENDOR_REFERENCE->URL . "\n";
            }
            $references = trim($references);
            $plugin->see_also = $references;
        } else {
            $plugin->see_also = '';
        }

        $plugin->cve = (string)$INFO['cveid'];
        $plugin->cvss_base_score = '';
        $plugin->cvss_vector = '';
        $plugin->plugin_family = '';
        $plugin->severity = (string)$INFO['severity'];
        $plugin->service = '';
        $plugin->script_version = '';
        $plugin->plugin_modification_date = (string)$INFO->LAST_UPDATE;
        $plugin->plugin_publication_date = '';
        $plugin->plugin_type = '';
        $plugin->exploit_available = 0;
        $tmp->plugin[] = $plugin;
    }
}

// GET SERVICE LEVEL VULNERABILITIES
foreach($xml->IP->SERVICES->children() as $CAT) {
    
    foreach($CAT->children() as $SERVICE) {
        $plugin = new \stdClass();
        $plugin->id = (string)$SERVICE['number'];
        $plugin->name = (string)$SERVICE->TITLE;
        $plugin->description = preg_replace('/<p>/i', '<br>', (string)$SERVICE->DIAGNOSIS);
        $plugin->synopsis = preg_replace('/<p>/i', '<br>', (string)$SERVICE->CONSEQUENCE);
        if(empty($SERVICE->SOLUTION)) {
            $SERVICE->SOLUTION = 'N/A';
        } else {
            $SERVICE->SOLUTION = preg_replace('/<p>/i', '<br>', (string)$SERVICE->DIAGNOSIS);
        }
        $plugin->solution = (string)$SERVICE->SOLUTION;
        $plugin->risk = 'None';
        $plugin->output = preg_replace('/<p>/i', '<br>', (string)$SERVICE->RESULT);
        $plugin->protocol = (string)$CAT['protocol'];
        $plugin->port = (string)$CAT['port'];

        $references = '';
        if(!empty($SERVICE->VENDOR_REFERENCE_LIST)) {
            foreach($SERVICE->VENDOR_REFERENCE_LIST->children() as $VENDOR_REFERENCE) {
                $references = (string)$VENDOR_REFERENCE->ID . " - " . $VENDOR_REFERENCE->URL . "\n";
            }
            $references = trim($references);
            $plugin->see_also = $references;
        } else {
            $plugin->see_also = '';
        }

        $plugin->cve = (string)$SERVICE['cveid'];
        $plugin->cvss_base_score = '';
        $plugin->cvss_vector = '';
        $plugin->plugin_family = '';
        $plugin->severity = (string)$SERVICE['severity'];
        $plugin->service = '';
        $plugin->script_version = '';
        $plugin->plugin_modification_date = (string)$SERVICE->LAST_UPDATE;
        $plugin->plugin_publication_date = '';
        $plugin->plugin_type = '';
        $plugin->exploit_available = 0;
        $tmp->plugin[] = $plugin;
    }
}

// GET SERVICE LEVEL VULNERABILITIES
foreach($xml->IP->VULNS->children() as $CAT) {
    
    foreach($CAT->children() as $VULN) {
        $plugin = new \stdClass();
        $plugin->id = (string)$VULN['number'];
        $plugin->name = (string)$VULN->TITLE;
        $plugin->description = preg_replace('/<p>/i', '<br>', (string)$VULN->DIAGNOSIS);
        $plugin->synopsis = preg_replace('/<p>/i', '<br>', (string)$VULN->CONSEQUENCE);
        if(empty($VULN->SOLUTION)) {
            $VULN->SOLUTION = 'N/A';
        } else {
            $VULN->SOLUTION = preg_replace('/<p>/i', '<br>', (string)$VULN->DIAGNOSIS);
        }
        $plugin->solution = (string)$VULN->SOLUTION;
        $plugin->risk = 'None';
        $plugin->output = preg_replace('/<p>/i', '<br>', (string)$VULN->RESULT);
        $plugin->protocol = (string)$CAT['protocol'];
        $plugin->port = (string)$CAT['port'];

        $references = '';
        if(!empty($VULN->VENDOR_REFERENCE_LIST)) {
            foreach($VULN->VENDOR_REFERENCE_LIST->children() as $VENDOR_REFERENCE) {
                $references = (string)$VENDOR_REFERENCE->ID . " - " . $VENDOR_REFERENCE->URL . "\n";
            }
            $references = trim($references);
            $plugin->see_also = $references;
        } else {
            $plugin->see_also = '';
        }

        $plugin->cve = (string)$VULN['cveid'];
        $plugin->cvss_base_score = '';
        $plugin->cvss_vector = '';
        $plugin->plugin_family = '';
        $plugin->severity = (string)$VULN['severity'];
        $plugin->service = '';
        $plugin->script_version = '';
        $plugin->plugin_modification_date = (string)$VULN->LAST_UPDATE;
        $plugin->plugin_publication_date = '';
        $plugin->plugin_type = '';
        $plugin->exploit_available = 0;
        $tmp->plugin[] = $plugin;
    }
}

// final extracted output from xml in array form to be used to store in database
print_r($tmp);