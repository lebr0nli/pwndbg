import gdb

import pwndbg
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.symbol
import pwndbg.gdblib.typeinfo
import pwndbg.glibc
import pwndbg.heap
import re
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


def test_malloc_chunk_command_heuristic(start_binary):
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("set debug-file-directory")
    gdb.execute("break break_here")
    gdb.execute("continue")

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


class mock_for_heuristic:
    def __init__(self, mock_symbols=[], mock_all=False, mess_up_memory=False):
        self.mock_symbols = mock_symbols
        self.mock_all = mock_all
        self.saved_address_func = pwndbg.gdblib.symbol.address
        self.saved_static_linkage_symbol_address_func = (
            pwndbg.gdblib.symbol.static_linkage_symbol_address
        )
        self.mess_up_memory = mess_up_memory
        if mess_up_memory:
            self.page = pwndbg.heap.current.possible_page_of_symbols
            self.saved_memory = pwndbg.gdblib.memory.read(self.page.vaddr, self.page.memsz)

    def __enter__(self):
        def mock(original):
            def _mock(symbol, *args, **kwargs):
                if self.mock_all:
                    return None
                for s in self.mock_symbols:
                    if s == symbol:
                        return None
                return original(symbol, *args, **kwargs)

            return _mock

        pwndbg.gdblib.symbol.address = mock(pwndbg.gdblib.symbol.address)
        pwndbg.gdblib.symbol.static_linkage_symbol_address = mock(
            pwndbg.gdblib.symbol.static_linkage_symbol_address
        )
        if self.mess_up_memory:
            pwndbg.gdblib.memory.write(self.page.vaddr, b"\xff" * self.page.memsz)

    def __exit__(self, exc_type, exc_value, traceback):
        pwndbg.gdblib.symbol.address = self.saved_address_func
        pwndbg.gdblib.symbol.static_linkage_symbol_address = (
            self.saved_static_linkage_symbol_address_func
        )
        if self.mess_up_memory:
            pwndbg.gdblib.memory.write(self.page.vaddr, self.saved_memory)


def test_main_arena_heuristic(start_binary):
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Level 1: We check we can get the address of `main_arena` from debug symbols and the struct of `main_arena` is correct
    assert pwndbg.heap.current.main_arena is not None
    main_arena_addr_via_debug_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
        "main_arena"
    ) or pwndbg.gdblib.symbol.address("main_arena")
    # Check the address of `main_arena` is correct
    assert pwndbg.heap.current.main_arena.address == main_arena_addr_via_debug_symbol
    # Check the struct size is correct
    assert (
        pwndbg.heap.current.main_arena.type.sizeof
        == pwndbg.gdblib.typeinfo.lookup_types("struct malloc_state").sizeof
    )
    pwndbg.heap.current = type(pwndbg.heap.current)()  # Reset the heap

    # Level 2.1: We check we can get the address of `main_arena` by parsing the assembly code of `malloc_trim`
    with mock_for_heuristic(["main_arena"], mess_up_memory=True):
        assert pwndbg.heap.current.main_arena is not None
        # Check the address of `main_arena` is correct
        assert pwndbg.heap.current.main_arena.address == main_arena_addr_via_debug_symbol
    pwndbg.heap.current = type(pwndbg.heap.current)()  # Reset the heap

    # Level 2.2: No `__malloc_hook` this time, because it's possible to find `main_arena` by some magic about it
    with mock_for_heuristic(["main_arena", "__malloc_hook"], mess_up_memory=True):
        assert pwndbg.heap.current.main_arena is not None
        # Check the address of `main_arena` is correct
        assert pwndbg.heap.current.main_arena.address == main_arena_addr_via_debug_symbol
    pwndbg.heap.current = type(pwndbg.heap.current)()  # Reset the heap

    # Level 3: We check we can get the address of `main_arena` by parsing the memory
    with mock_for_heuristic(mock_all=True):
        # Check the address of `main_arena` is correct
        assert pwndbg.heap.current.main_arena.address == main_arena_addr_via_debug_symbol


# FIXME: We still have bug for GLIBC >= 2.35 in this heuristic because the size of `malloc_par` is changed
# So this test will fail for the tests on ubuntu 22.04 probably
# TODO: Fix the bug and enable this test
def test_mp_heuristic(start_binary):
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Level 1: We check we can get the address of `mp_` from debug symbols and the struct of `mp_` is correct
    assert pwndbg.heap.current.mp is not None
    mp_addr_via_debug_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
        "mp_"
    ) or pwndbg.gdblib.symbol.address("mp_")
    # Check the address of `main_arena` is correct
    assert pwndbg.heap.current.mp.address == mp_addr_via_debug_symbol
    # Check the struct size is correct
    assert (
        pwndbg.heap.current.mp.type.sizeof
        == pwndbg.gdblib.typeinfo.lookup_types("struct malloc_par").sizeof
    )
    pwndbg.heap.current = type(pwndbg.heap.current)()  # Reset the heap

    # Level 2: We check we can get the address of `mp_` by parsing the assembly code of `__libc_free`
    with mock_for_heuristic(["mp_"], mess_up_memory=True):
        assert pwndbg.heap.current.mp is not None
        # Check the address of `mp_` is correct
        assert pwndbg.heap.current.mp.address == mp_addr_via_debug_symbol
    pwndbg.heap.current = type(pwndbg.heap.current)()  # Reset the heap

    # Level 3: We check we can get the address of `mp_` by parsing the memory
    with mock_for_heuristic(mock_all=True):
        # Check the address of `mp_` is correct
        assert pwndbg.heap.current.mp.address == mp_addr_via_debug_symbol


def test_global_max_fast_heuristic(start_binary):
    # TODO: Support other architectures or different libc versions
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Use the debug symbol to find the address of `global_max_fast`
    global_max_fast_addr_via_debug_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
        "global_max_fast"
    ) or pwndbg.gdblib.symbol.address("global_max_fast")
    assert global_max_fast_addr_via_debug_symbol is not None

    # Mock the address of `global_max_fast` to None
    with mock_for_heuristic(["global_max_fast"]):
        # Use heuristic to find `global_max_fast`
        assert pwndbg.heap.current.global_max_fast is not None
        # Check the address of `global_max_fast` is correct
        assert pwndbg.heap.current._global_max_fast_addr == global_max_fast_addr_via_debug_symbol


def test_thread_arena_heuristic(start_binary):
    # TODO: Support other architectures or different libc versions
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Use the debug symbol to find the value of `thread_arena`
    thread_arena_via_debug_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
        "thread_arena"
    ) or pwndbg.gdblib.symbol.address("thread_arena")
    assert thread_arena_via_debug_symbol is not None
    thread_arena_via_debug_symbol = pwndbg.gdblib.memory.u(thread_arena_via_debug_symbol)
    assert thread_arena_via_debug_symbol > 0

    # Mock the address of `thread_arena` to None
    with mock_for_heuristic(["thread_arena"]):
        assert pwndbg.gdblib.symbol.address("thread_arena") is None
        # Check the value of `thread_arena` is correct
        assert pwndbg.heap.current.thread_arena == thread_arena_via_debug_symbol


def test_heuristic_page(start_binary):
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    debug1 = gdb.execute("info files", to_string=True)
    debug2 = pwndbg.glibc.get_got_plt_address()
    assert pwndbg.heap.current.possible_page_of_symbols is not None
