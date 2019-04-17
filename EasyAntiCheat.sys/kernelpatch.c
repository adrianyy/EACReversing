void __usercall CheckForKernelPatches(__int64 a1@<rcx>, __int64 a2@<rdx>, signed int a3@<r14d>)
{
  signed int v5; // ebx
  _IMAGE_DOS_HEADER *ntoskrnlBase; // rbp
  int v7; // ebx
  signed int v8; // ebx
  bool v9; // sf
  unsigned int v10; // eax
  char v11; // [rsp+30h] [rbp-58h]
  __int64 v12; // [rsp+38h] [rbp-50h]
  _IMAGE_NT_HEADERS64 *v13; // [rsp+40h] [rbp-48h]
  _IMAGE_NT_HEADERS64 *a4; // [rsp+48h] [rbp-40h]
  UNICODE_STRING ntoskrnlPath; // [rsp+50h] [rbp-38h]
  char v16; // [rsp+60h] [rbp-28h]
  __int64 v17; // [rsp+68h] [rbp-20h]
  unsigned __int64 fileLength; // [rsp+A0h] [rbp+18h]
  _IMAGE_DOS_HEADER *fileBuffer; // [rsp+A8h] [rbp+20h]

  v5 = 2;
  ntoskrnlBase = (_IMAGE_DOS_HEADER *)GetNtoskrnlBase();
  if ( ntoskrnlBase && GetNtoskrnlPath(&ntoskrnlPath, a3) )
  {
    if ( (MEMORY[0xFFFFF7800000026C] > 6u
       || MEMORY[0xFFFFF7800000026C] == 6 && (MEMORY[0xFFFFF78000000270] == 2 || MEMORY[0xFFFFF78000000270] == 3))
      && CompareUnicodeStrings((__int64)&ntoskrnlPath, (_WORD *)(StringTable + 4752)) )// \SystemRoot\system32\ntoskrnl.exe
    {
      v5 = 1;
    }
    else if ( ReadFileW(&ntoskrnlPath, (__int64 *)&fileBuffer, (ULONG *)&fileLength) )
    {
      if ( (unsigned int)fileLength >= 0x1000 )
        v5 = !ValidatePeHeader(ntoskrnlBase, 0x1000ui64, &fileLength, &v13)
          || !ValidatePeHeader(fileBuffer, 0x1000ui64, &fileLength, &a4)
          || v13->FileHeader.NumberOfSections != a4->FileHeader.NumberOfSections
          || v13->FileHeader.TimeDateStamp != a4->FileHeader.TimeDateStamp
          || v13->OptionalHeader.AddressOfEntryPoint != a4->OptionalHeader.AddressOfEntryPoint
          || v13->OptionalHeader.CheckSum != a4->OptionalHeader.CheckSum
          || v13->OptionalHeader.SizeOfImage != a4->OptionalHeader.SizeOfImage;
      if ( fileBuffer )
        FreePool((__int64)fileBuffer);
    }
    FreeUnicodeString(&ntoskrnlPath);
  }
  v7 = v5 - 1;
  if ( !v7 )
  {
    v8 = -1073610745;
    goto LABEL_47;
  }
  if ( v7 == 1 )
  {
    v8 = -1073610744;
LABEL_47:
    sub_33230(a2, (unsigned int)v8);
    return;
  }
  v8 = 0;
  v9 = MEMORY[0xFFFFF7800000026C] - 6 < 0;
  if ( MEMORY[0xFFFFF7800000026C] > 6u
    || MEMORY[0xFFFFF7800000026C] == 6
    && (MEMORY[0xFFFFF78000000270] == 2 || (v9 = MEMORY[0xFFFFF78000000270] - 3 < 0, MEMORY[0xFFFFF78000000270] == 3)) )
  {
    if ( GetBCDData((_UNICODE_STRING *)&v16, (UNICODE_STRING *)&v11, a3) )
    {
      if ( v12 )
      {
        if ( CompareUnicodeStrings((__int64)&v11, (_WORD *)(StringTable + 1003))// \Windows\system32\winload.exe
          && CompareUnicodeStrings((__int64)&v11, (_WORD *)(StringTable + 1063)) )// \Windows\system32\winload.efi
        {
          v8 = 0xC0020010;
        }
        FreeUnicodeString(&v11);
      }
      if ( v17 )
      {
        if ( CompareUnicodeStrings((__int64)&v16, (_WORD *)(StringTable + 1123)) )// ntoskrnl.exe
          v8 = 0xC0020011;
        FreeUnicodeString(&v16);
      }
    }
    else
    {
      sub_3329C(a2, 81i64, 0i64);
    }
    v9 = v8 < 0;
    if ( v8 )
      goto LABEL_47;
  }
  sub_25ECC(a2, 1073807366i64, v9);
  v10 = sub_13F3C(a1, a2);
  if ( v10 == 0x40031000 )
    sub_25BF4(0x40031000, a2, a3);
  else
    sub_33230(a2, v10);
  qword_4E0D0 = 0i64;
  qword_4E0D8 = 0i64;
  qword_4E0E0 = 0i64;
  qword_4E0E8 = 0i64;
}

char __usercall GetBCDData@<al>(_UNICODE_STRING *a1@<rdx>, UNICODE_STRING *a2@<rcx>, signed int a3@<r14d>)
{
  char v3; // di
  _UNICODE_STRING *v4; // rsi
  UNICODE_STRING *v5; // rbp
  __int64 globalDataTable; // rbx
  __int64 v7; // rdx
  unsigned __int16 v9; // [rsp+20h] [rbp-128h]
  void *Src; // [rsp+28h] [rbp-120h]
  __m128i v11; // [rsp+30h] [rbp-118h]
  char Dst; // [rsp+40h] [rbp-108h]
  char v13; // [rsp+8Ch] [rbp-BCh]
  __int128 v14; // [rsp+ECh] [rbp-5Ch]
  __int16 v15; // [rsp+FCh] [rbp-4Ch]

  v3 = 0;
  v4 = a1;
  v5 = a2;
  if ( !a2 || !a1 )
    return 0;
  *(_QWORD *)&a2->Length = 0i64;
  a2->Buffer = 0i64;
  *(_QWORD *)&a1->Length = 0i64;
  a1->Buffer = 0i64;
  if ( QuerySystemBootEnvironmentInformation(&v11, a3) && sub_12080((unsigned __int8 *)&v11, (__int64)&v9) )
  {
    globalDataTable = StringTable;
    v15 = 0;
    memmove(&Dst, (const void *)(StringTable + 188), 0xBCui64);// \Registry\Machine\BCD00000000\Objects\{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\Elements\xxxxxxxx
    memmove(&v13, Src, v9);
    _mm_storeu_si128((__m128i *)&v14, _mm_loadu_si128((const __m128i *)(globalDataTable + 378)));
    ReadRegistryUnicodeString(globalDataTable + 396, &Dst, (__int64)v5, a3);
    v7 = StringTable + 396;
    _mm_storeu_si128((__m128i *)&v14, _mm_loadu_si128((const __m128i *)(StringTable + 412)));
    ReadRegistryUnicodeString(v7, &Dst, (__int64)v4, a3);
    FreeUnicodeString(&v9);
  }
  if ( v5->Buffer || v4->Buffer )
    v3 = 1;
  return v3;
}