.text:0000000000036C30                         ExecVMREAD      proc near               ; CODE XREF: CheckVM+21↑p
.text:0000000000036C30 0F 78 0A                                vmread  qword ptr [rdx], rcx
.text:0000000000036C33 0F 94 C0                                setz    al
.text:0000000000036C36 0F 92 C1                                setb    cl
.text:0000000000036C39 12 C1                                   adc     al, cl
.text:0000000000036C3B C3                                      retn
.text:0000000000036C3B                         ExecVMREAD      endp

.text:000000000001FD84                         CheckVM         proc near               ; DATA XREF: .pdata:000000000004F960↓o
.text:000000000001FD84
.text:000000000001FD84                         var_28          = byte ptr -28h
.text:000000000001FD84                         var_18          = dword ptr -18h
.text:000000000001FD84                         var_14          = dword ptr -14h
.text:000000000001FD84                         var_10          = dword ptr -10h
.text:000000000001FD84
.text:000000000001FD84                         ; FUNCTION CHUNK AT .text:000000000003724A SIZE 00000023 BYTES
.text:000000000001FD84
.text:000000000001FD84                         ; __unwind { // __C_specific_handler
.text:000000000001FD84 40 53                                   push    rbx
.text:000000000001FD86 48 83 EC 40                             sub     rsp, 40h
.text:000000000001FD8A B3 01                                   mov     bl, 1
.text:000000000001FD8C 88 5C 24 20                             mov     [rsp+48h+var_28], bl
.text:000000000001FD90 33 C0                                   xor     eax, eax
.text:000000000001FD92 89 44 24 30                             mov     [rsp+48h+var_18], eax
.text:000000000001FD96 89 44 24 34                             mov     [rsp+48h+var_14], eax
.text:000000000001FD9A 89 44 24 38                             mov     [rsp+48h+var_10], eax
.text:000000000001FD9E
.text:000000000001FD9E                         loc_1FD9E:                              ; DATA XREF: .rdata:0000000000049114↓o
.text:000000000001FD9E                         ;   __try { // __except at VMNotFound
.text:000000000001FD9E 48 8D 54 24 34                          lea     rdx, [rsp+48h+var_14]
.text:000000000001FDA3 33 C9                                   xor     ecx, ecx
.text:000000000001FDA5 E8 86 6E 01 00                          call    ExecVMREAD
.text:000000000001FDAA 88 5C 24 20                             mov     [rsp+48h+var_28], bl
.text:000000000001FDAE EB 16                                   jmp     short VMFound
.text:000000000001FDAE                         ;   } // starts at 1FD9E
.text:000000000001FDB0                         ; ---------------------------------------------------------------------------
.text:000000000001FDB0
.text:000000000001FDB0                         VMNotFound:                             ; DATA XREF: .rdata:0000000000049114↓o
.text:000000000001FDB0                         ;   __except(loc_3724A) // owned by 1FD9E
.text:000000000001FDB0 0F B6 5C 24 20                          movzx   ebx, [rsp+48h+var_28]
.text:000000000001FDB5 33 C0                                   xor     eax, eax
.text:000000000001FDB7 81 7C 24 30 1D 00 00 C0                 cmp     [rsp+48h+var_18], 0C000001Dh
.text:000000000001FDBF 0F 44 D8                                cmovz   ebx, eax
.text:000000000001FDC2 88 5C 24 20                             mov     [rsp+48h+var_28], bl
.text:000000000001FDC6
.text:000000000001FDC6                         VMFound:                                ; CODE XREF: CheckVM+2A↑j
.text:000000000001FDC6 F6 DB                                   neg     bl
.text:000000000001FDC8 1B C9                                   sbb     ecx, ecx
.text:000000000001FDCA 81 C1 55 01 00 00                       add     ecx, 155h
.text:000000000001FDD0 45 33 C9                                xor     r9d, r9d
.text:000000000001FDD3 45 8D 41 0C                             lea     r8d, [r9+0Ch]
.text:000000000001FDD7 48 8D 54 24 30                          lea     rdx, [rsp+48h+var_18]
.text:000000000001FDDC E8 27 09 01 00                          call    SendPacketToServer
.text:000000000001FDE1 48 83 C4 40                             add     rsp, 40h
.text:000000000001FDE5 5B                                      pop     rbx
.text:000000000001FDE6 C3                                      retn
.text:000000000001FDE6                         ; } // starts at 1FD84
.text:000000000001FDE6                         CheckVM         endp



.text:000000000001FDF0 48 89 5C 24 08                          mov     [rsp+arg_0], rbx
.text:000000000001FDF5 57                                      push    rdi
.text:000000000001FDF6 48 83 EC 50                             sub     rsp, 50h
.text:000000000001FDFA 83 64 24 20 00                          and     [rsp+58h+var_38], 0
.text:000000000001FDFF 33 D2                                   xor     edx, edx        ; Val
.text:000000000001FE01 48 8D 4C 24 24                          lea     rcx, [rsp+58h+Dst] ; Dst
.text:000000000001FE06 44 8D 42 24                             lea     r8d, [rdx+24h]  ; Size
.text:000000000001FE0A E8 11 72 01 00                          call    memset
.text:000000000001FE0F 45 0F 20 C3                             mov     r11, cr8
.text:000000000001FE13 B8 0F 00 00 00                          mov     eax, 0Fh
.text:000000000001FE18 44 0F 22 C0                             mov     cr8, rax
.text:000000000001FE1C 48 8B 7C 24 38                          mov     rdi, [rsp+58h+var_20]
.text:000000000001FE21 44 8D 48 55                             lea     r9d, [rax+55h]
.text:000000000001FE25 4D 8B D1                                mov     r10, r9
.text:000000000001FE28
.text:000000000001FE28                         loc_1FE28:                              ; CODE XREF: sub_1FDF0+70↓j
.text:000000000001FE28 0F 31                                   rdtsc
.text:000000000001FE2A 48 C1 E2 20                             shl     rdx, 20h
.text:000000000001FE2E 48 0B C2                                or      rax, rdx
.text:000000000001FE31 33 C9                                   xor     ecx, ecx
.text:000000000001FE33 4C 8B C0                                mov     r8, rax
.text:000000000001FE36 B8 01 00 00 00                          mov     eax, 1
.text:000000000001FE3B 0F A2                                   cpuid
.text:000000000001FE3D 89 44 24 20                             mov     [rsp+58h+var_38], eax
.text:000000000001FE41 89 5C 24 24                             mov     [rsp+58h+Dst], ebx
.text:000000000001FE45 89 4C 24 28                             mov     [rsp+58h+var_30], ecx
.text:000000000001FE49 89 54 24 2C                             mov     [rsp+58h+var_2C], edx
.text:000000000001FE4D 0F 31                                   rdtsc
.text:000000000001FE4F 48 C1 E2 20                             shl     rdx, 20h
.text:000000000001FE53 48 0B C2                                or      rax, rdx
.text:000000000001FE56 49 2B C0                                sub     rax, r8
.text:000000000001FE59 48 03 F8                                add     rdi, rax
.text:000000000001FE5C 49 83 EA 01                             sub     r10, 1
.text:000000000001FE60 75 C6                                   jnz     short loc_1FE28
.text:000000000001FE62 48 8B 5C 24 40                          mov     rbx, [rsp+58h+var_18]
.text:000000000001FE67 48 89 7C 24 38                          mov     [rsp+58h+var_20], rdi
.text:000000000001FE6C
.text:000000000001FE6C                         loc_1FE6C:                              ; CODE XREF: sub_1FDF0+9B↓j
.text:000000000001FE6C 0F 31                                   rdtsc
.text:000000000001FE6E 48 C1 E2 20                             shl     rdx, 20h
.text:000000000001FE72 48 0B C2                                or      rax, rdx
.text:000000000001FE75 48 8B C8                                mov     rcx, rax
.text:000000000001FE78 0F 31                                   rdtsc
.text:000000000001FE7A 48 C1 E2 20                             shl     rdx, 20h
.text:000000000001FE7E 48 0B C2                                or      rax, rdx
.text:000000000001FE81 48 2B C1                                sub     rax, rcx
.text:000000000001FE84 48 03 D8                                add     rbx, rax
.text:000000000001FE87 49 83 E9 01                             sub     r9, 1
.text:000000000001FE8B 75 DF                                   jnz     short loc_1FE6C
.text:000000000001FE8D 48 89 5C 24 40                          mov     [rsp+58h+var_18], rbx
.text:000000000001FE92 41 0F B6 CB                             movzx   ecx, r11b
.text:000000000001FE96 44 0F 22 C1                             mov     cr8, rcx
.text:000000000001FE9A 48 8D 0D 4F 73 01 00                    lea     rcx, qword_371F0
.text:000000000001FEA1 E9 B4 59 0A 00                          jmp     loc_C585A