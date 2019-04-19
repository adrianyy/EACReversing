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