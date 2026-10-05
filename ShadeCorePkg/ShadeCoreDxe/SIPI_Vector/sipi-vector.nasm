;
; (c) FFRI Security, Inc., 2026 / Author: FFRI Security, Inc.
;

BITS 16
org 0x0000
cli
cld
jmp start16
times 8-($-$$) db 0

; --------------- FILL IN THESE AFTER COMPILE ---------------
header_stack:   dq 0x1111111111111111    ; 0x08
header_cr3:     dq 0x2222222222222222    ; 0x10
header_entry:   dq 0x3333333333333333    ; 0x18

gdtr:
    dw gdt_end - gdt_start - 1           ; 0x20
header_gdt_start:
    dd gdt_start  ; Add 0xVV000 to this value later  ; 0x22
times 8-($-gdtr) db 0

start32_jmp_ptr:
  dd 0
  dw 0
times 8-($-start32_jmp_ptr) db 0

start64_jmp_ptr:
  dd 0
  dw 0
times 8-($-start64_jmp_ptr) db 0

times 64-($-$$) db 0

; --------------- Main Code ---------------
start16:
  ; Set DS, SS to the same val as CS
  mov ax, cs
  mov ds, ax
  mov es, ax
  mov fs, ax
  mov gs, ax

  ; Init stack 0xVV000+0x1000 ~ 0xVV000+0x1FFF
  add ax, 0x100  ; Use next segment
  mov ss, ax
  mov sp, 0xFF0 ; sp=0x2FF0 when VV=1
  mov bp, sp

  ; Load GDT
  lgdt [ds:gdtr]

  ; Calculate start32 absolute addr
  mov ax, cs
  shl ax, 4
  add ax, start32
  mov word [start32_jmp_ptr + 0], ax
  mov word [start32_jmp_ptr + 2], 0
  ; GDT[1] CS value for far jump
  mov word [start32_jmp_ptr + 4], 0x08

  ; Enable protected mode
  mov eax, cr0
  and edx, 0x7FFFFFFF
  or eax, 1  ; PE=1
  mov cr0, eax

  ; Save CS.Base to BX
  mov bx, cs
  shl bx, 4

  ; Switch CS to point to GDT[1] by far jump
  o32 jmp far [cs:start32_jmp_ptr]


BITS 32
start32:
  ; Setup data segments  GDT[2]
  mov ax, 0x10
  mov ds, ax
  mov es, ax
  mov ss, ax

  ; Prepare Stack
  xor edx, edx
  mov dx, bx
  add edx, header_stack
  mov esp, [edx]

  ; Preapre CR3
  xor edx, edx
  mov dx, bx
  add edx, header_cr3
  mov eax, [edx]
  mov cr3, eax

  ; Calculate start64 absolute addr
  xor esi, esi
  xor eax, eax
  mov si, bx
  mov ax, bx
  add eax, start64
  add esi, start64_jmp_ptr
  mov [esi], eax
  ; GDT[3] CS value for far jump
  add esi, 4
  mov word [esi], 0x18
  sub esi, 4

  ; Enable PAE
  mov eax, cr4
  or eax, (1<<5)
  mov cr4, eax

  ; Enable Long Mode
  mov ecx, 0xC0000080
  rdmsr
  or eax, (1<<8)
  wrmsr

  ; Enable Paging
  mov eax, cr0
  or eax, (1<<31)
  mov cr0, eax

  ; Switch CS to point to GDT[3]
  jmp far [esi]
  ;jmp 0x18:start64


BITS 64
start64:
  ; Setup data segments GDT[4]
  mov ax, 0x20
  mov ds, ax
  mov es, ax
  mov ss, ax

  ; Jump to C code
  xor rdx, rdx
  mov dx, bx
  add rdx, header_stack
  mov rsp, [rdx]

  xor rdx, rdx
  mov dx, bx
  add rdx, header_entry
  mov rax, [rdx]
  jmp rax



; --------------- GDT ---------------
ALIGN 8
gdt_start:

segment_descriptor_null:      ; 0x00
  dw  0x0000  ; Limit
  dw  0x0000  ; Base
  db  0x00    ; Base
  db  0x00    ; Access
  db  0x00    ; Limit/Flags
  db  0x00    ; Base
segment_descriptor_32bit_code:      ; 0x08
  dw  0xffff  ; Limit
  dw  0x0000  ; Base
  db  0x00    ; Base
  db  0x9a    ; Access RW,E,S,P
  db  0xcf    ; Limit/Flags DB,G
  db  0x00    ; Base
segment_descriptor_32bit_data:      ;0x10
  dw  0xffff  ; Limit
  dw  0x0000  ; Base
  db  0x00    ; Base
  db  0x92    ; Access RW,S,P
  db  0xcf    ; Limit/Flags DB,G
  db  0x00    ; Base
segment_descriptor_64bit_code:    ; 0x18
  dw  0xffff  ; Limit
  dw  0x0000  ; Base
  db  0x00    ; Base
  db  0x9a    ; Access RW,E,S,P
  db  0xaf    ; Limit/Flags L,G
  db  0x00    ; Base
segment_descriptor_64bit_data:    ; 0x20
  dw  0xffff  ; Limit
  dw  0x0000  ; Base
  db  0x00    ; Base
  db  0x92    ; Access RW,S,P
  db  0xcf    ; Limit/Flags DB,G
  db  0x00    ; Base
gdt_end:

