from watson.ioc_strings import find_interesting_strings


def test_flags_ip_address():
    strings = [{"string": "beacon to 192.168.1.1 every 60s", "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == [
        {"string": "beacon to 192.168.1.1 every 60s", "source": "static_strings", "reason": "ip"}
    ]


def test_flags_url():
    strings = [{"string": "http://evil.example.com/payload.bin", "source": "decoded_strings"}]

    result = find_interesting_strings(strings)

    assert result == [
        {
            "string": "http://evil.example.com/payload.bin",
            "source": "decoded_strings",
            "reason": "url",
        }
    ]


def test_flags_registry_key():
    strings = [{"string": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Run", "source": "stack_strings"}]

    result = find_interesting_strings(strings)

    assert result == [
        {
            "string": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Run",
            "source": "stack_strings",
            "reason": "registry_key",
        }
    ]


def test_flags_windows_path():
    strings = [{"string": "C:\\Windows\\System32\\evil.exe", "source": "tight_strings"}]

    result = find_interesting_strings(strings)

    assert result == [
        {
            "string": "C:\\Windows\\System32\\evil.exe",
            "source": "tight_strings",
            "reason": "windows_path",
        }
    ]


def test_flags_email():
    strings = [{"string": "attacker@evil-domain.com", "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == [
        {"string": "attacker@evil-domain.com", "source": "static_strings", "reason": "email"}
    ]


def test_excludes_boring_strings():
    strings = [{"string": "hello from watson test fixture", "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == []


def test_does_not_flag_asn1_oid_as_ip():
    # real false positive found against a live sample: X.509/crypto OIDs are
    # long dotted-numeric runs that a naive 4-group substring match catches
    strings = [
        {"string": "1.3.6.1.5.5.7.3.1", "source": "static_strings"},
        {"string": "2.16.840.1.101.3.4.1.21", "source": "static_strings"},
    ]

    result = find_interesting_strings(strings)

    assert result == []


def test_does_not_flag_short_well_known_oid_as_ip():
    # the harder case: some standard OID arcs (X.500 attribute types, X.509v3
    # extensions) are themselves exactly 4 segments with in-range values,
    # structurally indistinguishable from a real IP without knowing the arc
    strings = [
        {"string": "2.5.4.3", "source": "static_strings"},  # commonName
        {"string": "2.5.29.17", "source": "static_strings"},  # subjectAltName
    ]

    result = find_interesting_strings(strings)

    assert result == []


def test_does_not_flag_ip_with_out_of_range_octet():
    strings = [{"string": "999.999.999.999", "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == []


def test_flags_real_ip_embedded_in_longer_dotted_run_is_not_falsely_rejected():
    # a real 4-segment IP should still match even though the detection logic
    # now has to tell it apart from longer OID-style runs
    strings = [{"string": "192.168.1.1", "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == [{"string": "192.168.1.1", "source": "static_strings", "reason": "ip"}]


def test_does_not_flag_matches_inside_very_long_strings():
    # real false positive: a multi-hundred character CLI usage-help string
    # containing an incidental "C:\..." substring isn't a useful IOC on its own
    long_usage_text = (
        "Rubeus.exe asktgt /user:USER </password:PASSWORD> "
        "[/createnetonly:C:\\Windows\\System32\\cmd.exe] [/domain:DOMAIN] "
        "[/dc:DOMAIN_CONTROLLER] [/outfile:FILENAME] [/ptt] [/luid] [/nowrap] "
        "[/opsec] [/nopac] [/oldsam] [/proxyurl:https://KDC_PROXY/kdcproxy]"
    )
    strings = [{"string": long_usage_text, "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == []


def test_preserves_input_order_and_skips_non_matches():
    strings = [
        {"string": "hello from watson test fixture", "source": "static_strings"},
        {"string": "192.168.1.1", "source": "static_strings"},
        {"string": "hello.c", "source": "static_strings"},
        {"string": "attacker@evil-domain.com", "source": "static_strings"},
    ]

    result = find_interesting_strings(strings)

    assert [item["string"] for item in result] == ["192.168.1.1", "attacker@evil-domain.com"]
