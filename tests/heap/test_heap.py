import gdb

import pwndbg
import pwndbg.heap
import pwndbg.gdblib.symbol
import pwndbg.gdblib.memory
import tests

HEAP_MALLOC_CHUNK = tests.binaries.get("heap_malloc_chunk.out")


def generate_expected_malloc_chunk_output(chunks):
    expected = {}
    expected["allocated"] = [
        "Allocated chunk | PREV_INUSE",
        f"Addr: {chunks['allocated'].address}",
        f"Size: 0x{int(chunks['allocated']['mchunk_size' if 'mchunk_size' in (f.name for f in chunks['allocated'].type.fields()) else 'size']):02x}",
        "",
    ]

    expected["tcache"] = [
        f"Free chunk ({'tcache' if pwndbg.heap.current.has_tcache else 'fastbins'}) | PREV_INUSE",
        f"Addr: {chunks['tcache'].address}",
        f"Size: 0x{int(chunks['tcache']['mchunk_size' if 'mchunk_size' in (f.name for f in chunks['tcache'].type.fields()) else 'size']):02x}",
        f"fd: 0x{int(chunks['tcache']['fd']):02x}",
        "",
    ]

    expected["fast"] = [
        "Free chunk (fastbins) | PREV_INUSE",
        f"Addr: {chunks['fast'].address}",
        f"Size: 0x{int(chunks['fast']['mchunk_size' if 'mchunk_size' in (f.name for f in chunks['fast'].type.fields()) else 'size']):02x}",
        f"fd: 0x{int(chunks['fast']['fd']):02x}",
        "",
    ]

    expected["small"] = [
        "Free chunk (smallbins) | PREV_INUSE",
        f"Addr: {chunks['small'].address}",
        f"Size: 0x{int(chunks['small']['mchunk_size' if 'mchunk_size' in (f.name for f in chunks['small'].type.fields()) else 'size']):02x}",
        f"fd: 0x{int(chunks['small']['fd']):02x}",
        f"bk: 0x{int(chunks['small']['bk']):02x}",
        "",
    ]

    expected["large"] = [
        "Free chunk (largebins) | PREV_INUSE",
        f"Addr: {chunks['large'].address}",
        f"Size: 0x{int(chunks['large']['mchunk_size' if 'mchunk_size' in (f.name for f in chunks['large'].type.fields()) else 'size']):02x}",
        f"fd: 0x{int(chunks['large']['fd']):02x}",
        f"bk: 0x{int(chunks['large']['bk']):02x}",
        f"fd_nextsize: 0x{int(chunks['large']['fd_nextsize']):02x}",
        f"bk_nextsize: 0x{int(chunks['large']['bk_nextsize']):02x}",
        "",
    ]

    expected["unsorted"] = [
        "Free chunk (unsortedbin) | PREV_INUSE",
        f"Addr: {chunks['unsorted'].address}",
        f"Size: 0x{int(chunks['unsorted']['mchunk_size' if 'mchunk_size' in (f.name for f in chunks['unsorted'].type.fields()) else 'size']):02x}",
        f"fd: 0x{int(chunks['unsorted']['fd']):02x}",
        f"bk: 0x{int(chunks['unsorted']['bk']):02x}",
        "",
    ]

    return expected


def test_malloc_chunk_command(start_binary):
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("break break_here")
    gdb.execute("continue")

    chunks = {}
    results = {}
    chunk_types = ["allocated", "tcache", "fast", "small", "large", "unsorted"]
    for name in chunk_types:
        chunks[name] = pwndbg.gdblib.memory.poi(
            pwndbg.heap.current.malloc_chunk, gdb.lookup_symbol(f"{name}_chunk")[0].value()
        )
        results[name] = gdb.execute(f"malloc_chunk {name}_chunk", to_string=True).splitlines()

    expected = generate_expected_malloc_chunk_output(chunks)

    for name in chunk_types:
        assert results[name] == expected[name]


def check_malloc_chunk_command_heuristic(force_parsing_asm=False):
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")
    # Force the heap heuristic to parse asm code by messing up the memory
    if force_parsing_asm:
        # Get the page we want to mess up
        page = pwndbg.heap.current.possible_page_of_symbols
        # Read original memory
        original_memory = pwndbg.gdblib.memory.read(page.vaddr, page.memsz)
        # Write garbage
        pwndbg.gdblib.memory.write(page.vaddr, b"\xff" * page.memsz)
        # Mess up the memory and then we fetch `main_arena` and `mp_` to avoid heap heuristics find the address of the symbol via parsing the memory
        # Note: Only `main_arena` and `mp_` will parse the memory
        assert pwndbg.heap.current.main_arena is not None
        assert pwndbg.heap.current.mp is not None
        # Write back the original memory
        pwndbg.gdblib.memory.write(page.vaddr, original_memory)

    chunks = {}
    results = {}
    chunk_types = ["allocated", "tcache", "fast", "small", "large", "unsorted"]
    for name in chunk_types:
        chunks[name] = pwndbg.heap.current.malloc_chunk(
            gdb.lookup_symbol(f"{name}_chunk")[0].value()
        )
        results[name] = gdb.execute(f"malloc_chunk {name}_chunk", to_string=True).splitlines()

    expected = generate_expected_malloc_chunk_output(chunks)

    for name in chunk_types:
        assert results[name] == expected[name]


def test_malloc_chunk_command_heuristic_level1(start_binary):
    # TODO: Support other architectures or different libc versions
    # Level 1: We can get the address of symbols from debug symbols
    start_binary(HEAP_MALLOC_CHUNK)
    # If this works, the structs of heuristics work
    check_malloc_chunk_command_heuristic()


def test_malloc_chunk_command_heuristic_level2_1(start_binary):
    # TODO: Support other architectures or different libc versions
    # Level 2.1: We don't have debug symbols, we need to find the address by parsing the assembly code
    # Note: We allow `main_arena` to be found by the magic about `__malloc_hook`
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set debug-file-directory")
    # If this works, we successfully parsed the assembly code
    check_malloc_chunk_command_heuristic(force_parsing_asm=True)


def test_malloc_chunk_command_heuristic_level2_2(start_binary):
    # TODO: Support other architectures or different libc versions
    # Level 2.2: We don't have debug symbols, we need to find the address by parsing the assembly code
    # Note: We NOT allow `main_arena` to be found by the magic about `__malloc_hook`
    start_binary(HEAP_MALLOC_CHUNK)

    def mock_address(original):
        def _mock_address(symbol, *args, **kwargs):
            if symbol == "__malloc_hook":
                return None
            return original(symbol, *args, **kwargs)

        return _mock_address

    # Mock the address of `__malloc_hook` to None
    pwndbg.gdblib.symbol.address = mock_address(pwndbg.gdblib.symbol.address)
    pwndbg.gdblib.symbol.static_linkage_symbol_address = mock_address(
        pwndbg.gdblib.symbol.static_linkage_symbol_address
    )
    gdb.execute("set debug-file-directory")
    # If this works, we successfully parsed the assembly code
    check_malloc_chunk_command_heuristic(force_parsing_asm=True)


def test_malloc_chunk_command_heuristic_level3(start_binary):
    # TODO: Support other architectures or different libc versions
    # Level 3: We have no symbols from libc, we try to make heap commands work by parsing the memory
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set debug-file-directory")

    def mock_address(symbol, *args, **kwargs):
        return None

    # Mock address of all symbols to None
    pwndbg.gdblib.symbol.address = mock_address
    pwndbg.gdblib.symbol.static_linkage_symbol_address = mock_address
    # If this works, we successfully parsed the memory.
    check_malloc_chunk_command_heuristic()


def test_global_max_fast_heuristic(start_binary):
    # TODO: Support other architectures or different libc versions
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set debug-file-directory")
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    global_max_fast = pwndbg.heap.current.global_max_fast
    if pwndbg.gdblib.ptrsize == 4:
        assert global_max_fast == 0x40
    else:
        assert global_max_fast == 0x80


def test_thread_arena_heuristic_with_main_arena(start_binary):
    # TODO: Support other architectures or different libc versions
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set debug-file-directory")
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Is there a good way to test `thread_arena` works without `main_arena`?
    assert pwndbg.heap.current.thread_arena == pwndbg.heap.current.main_arena.address
