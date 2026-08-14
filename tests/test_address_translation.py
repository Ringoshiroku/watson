from watson.address_translation import elf_file_offset_to_va, pe_file_offset_to_va


def test_pe_file_offset_to_va_resolves_offset_inside_a_section():
    sections = [{"raw_offset": 0x400, "raw_size": 0x200, "rva": 0x1000}]

    assert pe_file_offset_to_va(0x450, 0x140000000, sections) == 0x140000000 + 0x1000 + 0x50


def test_pe_file_offset_to_va_includes_the_section_start_boundary():
    sections = [{"raw_offset": 0x400, "raw_size": 0x200, "rva": 0x1000}]

    assert pe_file_offset_to_va(0x400, 0x140000000, sections) == 0x140000000 + 0x1000


def test_pe_file_offset_to_va_excludes_the_section_end_boundary():
    sections = [{"raw_offset": 0x400, "raw_size": 0x200, "rva": 0x1000}]

    assert pe_file_offset_to_va(0x600, 0x140000000, sections) is None


def test_pe_file_offset_to_va_returns_none_before_any_section():
    sections = [{"raw_offset": 0x400, "raw_size": 0x200, "rva": 0x1000}]

    assert pe_file_offset_to_va(0x10, 0x140000000, sections) is None


def test_pe_file_offset_to_va_returns_none_for_no_sections():
    assert pe_file_offset_to_va(0x450, 0x140000000, []) is None


def test_pe_file_offset_to_va_picks_the_matching_section_among_several():
    sections = [
        {"raw_offset": 0x400, "raw_size": 0x200, "rva": 0x1000},
        {"raw_offset": 0x600, "raw_size": 0x200, "rva": 0x2000},
    ]

    assert pe_file_offset_to_va(0x650, 0x140000000, sections) == 0x140000000 + 0x2000 + 0x50


def test_elf_file_offset_to_va_resolves_offset_inside_a_segment():
    segments = [{"offset": 0x1000, "filesz": 0x500, "vaddr": 0x401000}]

    assert elf_file_offset_to_va(0x1050, segments) == 0x401000 + 0x50


def test_elf_file_offset_to_va_includes_the_segment_start_boundary():
    segments = [{"offset": 0x1000, "filesz": 0x500, "vaddr": 0x401000}]

    assert elf_file_offset_to_va(0x1000, segments) == 0x401000


def test_elf_file_offset_to_va_excludes_the_segment_end_boundary():
    segments = [{"offset": 0x1000, "filesz": 0x500, "vaddr": 0x401000}]

    assert elf_file_offset_to_va(0x1500, segments) is None


def test_elf_file_offset_to_va_returns_none_for_no_segments():
    assert elf_file_offset_to_va(0x1050, []) is None


def test_elf_file_offset_to_va_picks_the_matching_segment_among_several():
    segments = [
        {"offset": 0x1000, "filesz": 0x500, "vaddr": 0x401000},
        {"offset": 0x2000, "filesz": 0x500, "vaddr": 0x500000},
    ]

    assert elf_file_offset_to_va(0x2050, segments) == 0x500000 + 0x50
