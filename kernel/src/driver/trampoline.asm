[bits 16]
[org 0x8000]

trampoline:
    ; Perform short jump to actual code to make some space for
    ; configuration variables
    jmp short startup_ap
    times 8 - ($ - trampoline) nop

    ; PML4 pointer
    .page_table: dq 0
    ; Pointer to kernel AP initialization routine
    .code: dq 0x1234
    ; Pointer to Kernel instance
    .kernel: dq 0
    ; Pointer to new processor's stack
    .stack: dq 0
    ; Processor's APIC ID
    .apic_id: dq 0

startup_ap:

    ; Disable interrupts as we can't perform mode-switch with interrupts enabled
    cli

    ; Clear segment registers
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax

    ; initialize stack to invalid value
    mov sp, 0

    ; Load PML4 tables
    mov edi, [trampoline.page_table]
    mov cr3, edi

    ; Enable global pages, PAE and PS
    mov eax, cr4
    or eax, 1 << 7 | 1 << 5 | 1 << 4
    mov cr4, eax

    ; load protected mode GDT
    lgdt [gdtr]

    ; Enable Long Mode
    mov ecx, 0xC0000080
    rdmsr
    ; Set the Long Mode and No-Execute bits
    or eax, 1 << 11 | 1 << 8
    wrmsr

    ; Enable Paging and Protected Mode
    mov ebx, cr0
    or ebx, 1 << 31 | 1 << 16 | 1
    mov cr0, ebx

    ; far jump to enable Long Mode and load CS with the first entry of GDT
    jmp 0b01000:long_mode_ap

USE64
long_mode_ap:
    ; Reload segment registers to the second entry of GDT
    mov ax, 0b10000
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Initialize stack
    mov rsp, [trampoline.stack]

    ; Set arguments
    mov rdi, [trampoline.apic_id]
    mov rsi, [trampoline.kernel]

    ; Perform jump to kernel's AP initialization routine
    mov rax, qword [trampoline.code]
    jmp rax

; GDT entries
;
; Thanks to https://gitlab.redox-os.org/redox-os/kernel/-/blob/master/src/asm/x86_64/trampoline.asm

struc GDTEntry
    .limitl resw 1
    .basel resw 1
    .basem resb 1
    .attribute resb 1
    .flags__limith resb 1
    .baseh resb 1
endstruc

attrib:
    .present              equ 1 << 7
    .ring1                equ 1 << 5
    .ring2                equ 1 << 6
    .ring3                equ 1 << 5 | 1 << 6
    .user                 equ 1 << 4
;user
    .code                 equ 1 << 3
;   code
    .conforming           equ 1 << 2
    .readable             equ 1 << 1
;   data
    .expand_down          equ 1 << 2
    .writable             equ 1 << 1
    .accessed             equ 1 << 0
;system
;   legacy
    .tssAvailabe16        equ 0x1
    .ldt                  equ 0x2
    .tssBusy16            equ 0x3
    .call16               equ 0x4
    .task                 equ 0x5
    .interrupt16          equ 0x6
    .trap16               equ 0x7
    .tssAvailabe32        equ 0x9
    .tssBusy32            equ 0xB
    .call32               equ 0xC
    .interrupt32          equ 0xE
    .trap32               equ 0xF
;   long mode
    .ldt32                equ 0x2
    .tssAvailabe64        equ 0x9
    .tssBusy64            equ 0xB
    .call64               equ 0xC
    .interrupt64          equ 0xE
    .trap64               equ 0xF

flags:
    .granularity equ 1 << 7
    .available equ 1 << 4
;user
    .default_operand_size equ 1 << 6
;   code
    .long_mode equ 1 << 5
;   data
    .reserved equ 1 << 5

struc TSSEntry
    .reserved1 resd 1
    .rsp0 resq 1
    .rsp1 resq 1
    .rsp2 resq 1
    .reserved2 resd 1
    .reserved3 resd 1
    .ist1 resq 1
    .ist2 resq 1
    .ist3 resq 1
    .ist4 resq 1
    .ist5 resq 1
    .ist6 resq 1
    .ist7 resq 1
    .reserved4 resd 1
    .reserved5 resd 1
    .reserved6 resw 1
    .iopb resw 1
endstruc

gdtr:
    dw gdt.end + 1  ; size
    dq gdt          ; offset

gdt:
.null equ $ - gdt
    dq 0

.kernel_code equ $ - gdt
istruc GDTEntry
    at GDTEntry.limitl, dw 0
    at GDTEntry.basel, dw 0
    at GDTEntry.basem, db 0
    at GDTEntry.attribute, db attrib.present | attrib.user | attrib.readable | attrib.code | attrib.accessed
    at GDTEntry.flags__limith, db flags.long_mode
    at GDTEntry.baseh, db 0
iend

.kernel_data equ $ - gdt
istruc GDTEntry
    at GDTEntry.limitl, dw 0
    at GDTEntry.basel, dw 0
    at GDTEntry.basem, db 0
; AMD System Programming Manual states that the writeable bit is ignored in long mode, but ss can not be set to this descriptor without it
    at GDTEntry.attribute, db attrib.present | attrib.user | attrib.writable | attrib.accessed
    at GDTEntry.flags__limith, db 0
    at GDTEntry.baseh, db 0
iend

.user_code equ $ - gdt
istruc GDTEntry
    at GDTEntry.limitl, dw 0
    at GDTEntry.basel, dw 0
    at GDTEntry.basem, db 0
    at GDTEntry.attribute, db attrib.present | attrib.user | attrib.ring3 | attrib.readable | attrib.code | attrib.accessed
    at GDTEntry.flags__limith, db flags.long_mode
    at GDTEntry.baseh, db 0
iend

.user_data equ $ - gdt
istruc GDTEntry
    at GDTEntry.limitl, dw 0
    at GDTEntry.basel, dw 0
    at GDTEntry.basem, db 0
; AMD System Programming Manual states that the writeable bit is ignored in long mode, but ss can not be set to this descriptor without it
    at GDTEntry.attribute, db attrib.present | attrib.user | attrib.ring3 | attrib.writable | attrib.accessed
    at GDTEntry.flags__limith, db 0
    at GDTEntry.baseh, db 0
iend

.end equ $ - gdt