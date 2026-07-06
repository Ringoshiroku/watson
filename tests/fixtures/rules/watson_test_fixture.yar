rule watson_test_fixture_string
{
    strings:
        $a = "hello from watson test fixture"
    condition:
        $a
}
