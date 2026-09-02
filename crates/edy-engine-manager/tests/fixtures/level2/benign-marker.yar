rule EDY_LEVEL2_BENIGN_MARKER {
    meta:
        source = "EDY VERDICT project synthetic fixture"
        version = "1"
        purpose = "Benign adapter test only; not a malware signature"
    strings:
        $marker = "EDY_LEVEL2_BENIGN_MARKER"
    condition:
        $marker
}
