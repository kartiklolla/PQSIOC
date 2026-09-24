/* Like LiteX's demo linker script, except everything -- code, data, bss,
 * heap and stack -- lives in main_ram. The demo's layout puts data, bss and
 * the stack in the 8 KB SRAM, far too small for ML-DSA and 8 KB frames. */
INCLUDE generated/output_format.ld
ENTRY(_start)

__DYNAMIC = 0;

INCLUDE generated/regions.ld

SECTIONS
{
	.text :
	{
		_ftext = .;
		*crt0*(.text)
		KEEP(*crt0*(.text))
		KEEP(*(.text.isr))
		*(.text .stub .text.* .gnu.linkonce.t.*)
		_etext = .;
	} > main_ram

	.rodata :
	{
		. = ALIGN(8);
		_frodata = .;
		*(.rodata .rodata.* .gnu.linkonce.r.*)
		*(.rodata1)
		*(.srodata .srodata.*)
		*(.got .got.*)
		*(.toc .toc.*)
		FILL(0);
		. = ALIGN(8);
		_erodata = .;
	} > main_ram

	.preinit_array :
	{
		. = ALIGN(8);
		PROVIDE_HIDDEN (__preinit_array_start = .);
		KEEP(*(SORT(.preinit_array.*)))
		KEEP(*(.preinit_array))
		PROVIDE_HIDDEN (__preinit_array_end = .);
	} > main_ram

	.init_array :
	{
		. = ALIGN(8);
		PROVIDE_HIDDEN (__init_array_start = .);
		KEEP(*(SORT(.init_array.*)))
		KEEP(*(.init_array))
		KEEP(*(SORT(.ctors.*)))
		KEEP(*(.ctors))
		PROVIDE_HIDDEN (__init_array_end = .);
	} > main_ram

	.fini_array :
	{
		. = ALIGN(8);
		PROVIDE_HIDDEN (__fini_array_start = .);
		KEEP(*(SORT(.fini_array.*)))
		KEEP(*(.fini_array))
		KEEP(*(SORT(.dtors.*)))
		KEEP(*(.dtors))
		PROVIDE_HIDDEN (__fini_array_end = .);
	} > main_ram

	.data :
	{
		. = ALIGN(8);
		_fdata = .;
		*(.data .data.* .gnu.linkonce.d.*)
		*(.data1)
		_gp = ALIGN(16);
		*(.sdata .sdata.* .gnu.linkonce.s.*)
		FILL(0);
		. = ALIGN(8);
		_edata = .;
	} > main_ram

	.bss :
	{
		. = ALIGN(8);
		_fbss = .;
		*(.dynsbss)
		*(.sbss .sbss.* .gnu.linkonce.sb.*)
		*(.scommon)
		*(.dynbss)
		*(.bss .bss.* .gnu.linkonce.b.*)
		*(COMMON)
		. = ALIGN(8);
		_ebss = .;
		_end = .;
	} > main_ram
}

/* Stack: the top 1 MB of main_ram. Heap (picolibc sbrk): everything
 * between the end of bss and the stack. */
PROVIDE(_fstack = ORIGIN(main_ram) + LENGTH(main_ram) - 16);
PROVIDE(__heap_start = _end);
PROVIDE(__heap_end = ORIGIN(main_ram) + LENGTH(main_ram) - 0x100000);

/* .data is linked in place, so crt0's copy from "ROM" is a no-op. */
PROVIDE(_fdata_rom = LOADADDR(.data));
PROVIDE(_edata_rom = LOADADDR(.data) + SIZEOF(.data));
