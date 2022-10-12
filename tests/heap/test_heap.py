import gdb

import pwndbg
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.symbol
import pwndbg.heap
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
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    def mock_address(original):
        def _mock_address(symbol, *args, **kwargs):
            if symbol == "global_max_fast":
                return None
            return original(symbol, *args, **kwargs)

        _mock_address.original = original
        return _mock_address

    # Mock the address of `global_max_fast` to None
    pwndbg.gdblib.symbol.address = mock_address(pwndbg.gdblib.symbol.address)
    assert pwndbg.gdblib.symbol.address("global_max_fast") is None
    pwndbg.gdblib.symbol.static_linkage_symbol_address = mock_address(
        pwndbg.gdblib.symbol.static_linkage_symbol_address
    )
    assert pwndbg.gdblib.symbol.static_linkage_symbol_address("global_max_fast") is None

    # Use the heuristic to find the address of `global_max_fast`
    assert pwndbg.heap.current.global_max_fast
    old_global_max_fast = pwndbg.heap.current.global_max_fast

    global_max_fast_addr_via_heuristic = pwndbg.heap.current._global_max_fast_addr

    # Restore the original functions
    pwndbg.gdblib.symbol.address = pwndbg.gdblib.symbol.address.original
    pwndbg.gdblib.symbol.static_linkage_symbol_address = (
        pwndbg.gdblib.symbol.static_linkage_symbol_address.original
    )

    # Use the debug symbol to find the address of `global_max_fast`
    global_max_fast_addr_via_debug_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
        "global_max_fast"
    ) or pwndbg.gdblib.symbol.address("global_max_fast")
    assert global_max_fast_addr_via_debug_symbol is not None

    # Check is two addresses are the same
    new_global_max_fast = pwndbg.heap.current.global_max_fast
    debug = gdb.execute("disass _int_malloc", to_string=True)
    assert global_max_fast_addr_via_heuristic == global_max_fast_addr_via_debug_symbol


def test_thread_arena_heuristic(start_binary):
    # TODO: Support other architectures or different libc versions
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    def mock_address(original):
        def _mock_address(symbol, *args, **kwargs):
            if symbol == "thread_arena":
                return None
            return original(symbol, *args, **kwargs)

        _mock_address.original = original
        return _mock_address

    # Mock the address of `thread_arena` to None
    pwndbg.gdblib.symbol.address = mock_address(pwndbg.gdblib.symbol.address)
    assert pwndbg.gdblib.symbol.address("thread_arena") is None
    pwndbg.gdblib.symbol.static_linkage_symbol_address = mock_address(
        pwndbg.gdblib.symbol.static_linkage_symbol_address
    )
    assert pwndbg.gdblib.symbol.static_linkage_symbol_address("thread_arena") is None

    # Use heuristic to find the value of `thread_arena`
    thread_arena_via_heuristic = pwndbg.heap.current.thread_arena

    # Restore the original functions
    pwndbg.gdblib.symbol.address = pwndbg.gdblib.symbol.address.original
    pwndbg.gdblib.symbol.static_linkage_symbol_address = (
        pwndbg.gdblib.symbol.static_linkage_symbol_address.original
    )

    # Use the debug symbol to find the value of `thread_arena`
    thread_arena_via_debug_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
        "thread_arena"
    ) or pwndbg.gdblib.symbol.address("thread_arena")
    assert thread_arena_via_debug_symbol is not None
    thread_arena_via_debug_symbol = pwndbg.gdblib.memory.u(thread_arena_via_debug_symbol)
    assert thread_arena_via_debug_symbol > 0

    # Check is two addresses are the same
    assert thread_arena_via_heuristic == thread_arena_via_debug_symbol
