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


def test_flags_multiple_different_iocs_in_one_short_string():
    strings = [{"string": "connect 1.2.3.4 via http://evil.com", "source": "static_strings"}]

    result = find_interesting_strings(strings)

    reasons = {item["reason"] for item in result}
    assert reasons == {"ip", "url"}
    assert all(item["string"] == "connect 1.2.3.4 via http://evil.com" for item in result)


def test_domain_candidate_inside_url_is_not_double_reported():
    strings = [{"string": "http://evil.example.com/payload.bin", "source": "decoded_strings"}]

    result = find_interesting_strings(strings)

    assert result == [
        {
            "string": "http://evil.example.com/payload.bin",
            "source": "decoded_strings",
            "reason": "url",
        }
    ]


def test_domain_candidate_inside_email_is_not_double_reported():
    strings = [{"string": "attacker@evil-domain.com", "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == [
        {"string": "attacker@evil-domain.com", "source": "static_strings", "reason": "email"}
    ]


def test_flags_real_domain_with_known_tld():
    strings = [{"string": "beacon reaches out to cnc.badguy.net", "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == [
        {
            "string": "beacon reaches out to cnc.badguy.net",
            "source": "static_strings",
            "reason": "domain",
        }
    ]


def test_does_not_flag_dotnet_namespace_as_domain():
    strings = [{"string": "System.Windows.Forms", "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == []


def test_does_not_flag_filename_as_domain():
    strings = [{"string": "readme.txt", "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == []


def test_flags_mozilla_style_user_agent():
    strings = [
        {
            "string": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "source": "static_strings",
        }
    ]

    result = find_interesting_strings(strings)

    assert result == [
        {
            "string": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "source": "static_strings",
            "reason": "user_agent",
        }
    ]


def test_does_not_flag_bare_version_string_as_user_agent():
    strings = [{"string": "gcc/9.3.0", "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == []


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


def test_scans_long_strings_and_extracts_compact_matches_instead_of_skipping():
    # same motivating case as before (a long CLI usage-help string), but the
    # behavior is now to extract compact matches rather than skip the whole
    # string: verified by actually running the regexes against this exact
    # text, not hand-derived, since the existing windows_path/url patterns'
    # greedy `\S+` legitimately capture the trailing "]" from the source text
    long_usage_text = (
        "Rubeus.exe asktgt /user:USER </password:PASSWORD> "
        "[/createnetonly:C:\\Windows\\System32\\cmd.exe] [/domain:DOMAIN] "
        "[/dc:DOMAIN_CONTROLLER] [/outfile:FILENAME] [/ptt] [/luid] [/nowrap] "
        "[/opsec] [/nopac] [/oldsam] [/proxyurl:https://KDC_PROXY/kdcproxy]"
    )
    strings = [{"string": long_usage_text, "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == [
        {
            "string": "C:\\Windows\\System32\\cmd.exe]",
            "source": "static_strings",
            "reason": "windows_path",
        },
        {
            "string": "https://KDC_PROXY/kdcproxy]",
            "source": "static_strings",
            "reason": "url",
        },
    ]


def test_preserves_input_order_and_skips_non_matches():
    strings = [
        {"string": "hello from watson test fixture", "source": "static_strings"},
        {"string": "192.168.1.1", "source": "static_strings"},
        {"string": "hello.c", "source": "static_strings"},
        {"string": "attacker@evil-domain.com", "source": "static_strings"},
    ]

    result = find_interesting_strings(strings)

    assert [item["string"] for item in result] == ["192.168.1.1", "attacker@evil-domain.com"]


def test_caps_matches_per_string_at_twenty():
    ips = " ".join(f"10.0.0.{i}" for i in range(1, 26))  # 25 distinct valid IPs, one string
    strings = [{"string": ips, "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert len(result) == 20


def test_does_not_flag_go_generic_type_name_as_domain():
    # real false positive: Go's math/big.Int type name collides with the
    # "int" gTLD once the candidate is lowercased before comparison
    strings = [{"string": "*big.Int", "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == []


def test_does_not_flag_capitalized_go_type_names_matching_common_word_tlds():
    strings = [
        {"string": "*pkix.Name", "source": "static_strings"},
        {"string": "*wasm.Store", "source": "static_strings"},
        {"string": "*yamux.Stream", "source": "static_strings"},
    ]

    result = find_interesting_strings(strings)

    assert result == []


def test_dedupes_identical_string_and_reason_across_multiple_entries():
    # the same literal string commonly occurs at several addresses in one
    # binary, arriving here as separate flattened entries
    strings = [
        {"string": "cnc.badguy.net", "source": "static_strings"},
        {"string": "cnc.badguy.net", "source": "static_strings"},
    ]

    result = find_interesting_strings(strings)

    assert result == [
        {"string": "cnc.badguy.net", "source": "static_strings", "reason": "domain"}
    ]


def test_dedupes_identical_extracted_match_across_multiple_long_strings():
    filler = "the quick brown fox jumps over the lazy dog " * 5  # well over 200 chars
    long_text_one = filler + "beacon reaches out to cnc.badguy.net for updates"
    long_text_two = filler + "second sample also beacons to cnc.badguy.net directly"
    strings = [
        {"string": long_text_one, "source": "static_strings"},
        {"string": long_text_two, "source": "static_strings"},
    ]

    result = find_interesting_strings(strings)

    assert result == [
        {"string": "cnc.badguy.net", "source": "static_strings", "reason": "domain"}
    ]


def test_flags_known_go_code_host_import_paths_as_go_import_path_not_domain():
    # real false positive class: Go embeds import paths for every package it
    # links in, and they're structurally indistinguishable from a real
    # domain (lowercase, real TLD) since the host is a real domain, it's just
    # a package-hosting one, not C2 infrastructure
    strings = [
        {
            "string": "golang.org/x/sys/windows.ERROR_DS_INVALID_SEARCH_FLAG",
            "source": "static_strings",
        },
        {
            "string": "github.com/tetratelabs/wazero/internal/sysfs.stdioFile.Pwrite",
            "source": "static_strings",
        },
        {"string": "gopkg.in/yaml.v2", "source": "static_strings"},
        {
            "string": "google.golang.org/protobuf/internal/impl",
            "source": "static_strings",
        },
        {"string": "k8s.io/apimachinery/pkg/util", "source": "static_strings"},
    ]

    result = find_interesting_strings(strings)

    assert all(item["reason"] == "go_import_path" for item in result)
    assert len(result) == 5


def test_flags_subdomain_of_known_go_code_host_as_go_import_path():
    strings = [{"string": "sigs.k8s.io/yaml", "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == [
        {"string": "sigs.k8s.io/yaml", "source": "static_strings", "reason": "go_import_path"}
    ]


def test_still_flags_real_domain_that_merely_resembles_a_code_host():
    # a lookalike host (not an exact match or subdomain of a known code
    # host) must still be flagged as a real domain, not swept into the
    # go_import_path bucket
    strings = [{"string": "beacon reaches out to evil-github.com", "source": "static_strings"}]

    result = find_interesting_strings(strings)

    assert result == [
        {
            "string": "beacon reaches out to evil-github.com",
            "source": "static_strings",
            "reason": "domain",
        }
    ]
