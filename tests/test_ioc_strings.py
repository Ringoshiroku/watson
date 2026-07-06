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


def test_preserves_input_order_and_skips_non_matches():
    strings = [
        {"string": "hello from watson test fixture", "source": "static_strings"},
        {"string": "192.168.1.1", "source": "static_strings"},
        {"string": "hello.c", "source": "static_strings"},
        {"string": "attacker@evil-domain.com", "source": "static_strings"},
    ]

    result = find_interesting_strings(strings)

    assert [item["string"] for item in result] == ["192.168.1.1", "attacker@evil-domain.com"]
