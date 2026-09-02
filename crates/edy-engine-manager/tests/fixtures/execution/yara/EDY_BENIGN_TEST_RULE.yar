rule EDY_BENIGN_TEST_RULE
{
    meta:
        description = "Harmless EDY VERDICT synthetic validation marker"
    strings:
        $marker = "EDY_BENIGN_YARA_MARKER_NON_MALICIOUS"
    condition:
        $marker
}
