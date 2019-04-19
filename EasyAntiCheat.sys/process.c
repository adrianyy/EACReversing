char __usercall CheckProcess@<al>(__int64 a1@<rdx>, unsigned int *buffer@<rcx>, int a3@<esi>)
{
  __int64 *v4; // rdi
  char result; // al
  char *v6; // rcx
  signed int v7; // eax
  __int64 v8; // rdx
  __int64 v9; // rcx
  __int64 v11; // rcx
  char *v12; // r9
  unsigned __int64 v13; // rdx
  _DWORD *v14; // rdx
  char v15; // [rsp+20h] [rbp-48h]
  char v16; // [rsp+30h] [rbp-38h]
  PVOID process; // [rsp+78h] [rbp+10h] MAPDST

  v15 = 0;
  v4 = 0i64;
  if ( !buffer )
    return 0;
  v6 = (char *)buffer + 15;
  if ( v6 < (char *)buffer || (unsigned __int64)v6 >= MmUserProbeAddress )
  {
    ExRaiseAccessViolation(v6, a1);
    result = 0;
  }
  else if ( *buffer && *(_QWORD *)(buffer + 1) && buffer[3] )
  {
    if ( import_PsLookupProcessByProcessId )
      v7 = import_PsLookupProcessByProcessId(*buffer, &process);
    else
      v7 = 0xC0000002;
    if ( v7 >= 0 )
    {
      if ( AttachToProcess((__int64)process, (__int64)&v16) )
      {
        LOBYTE(v9) = 1;
        v4 = (__int64 *)CheckCurrentProcess(v9, v8);
        if ( process )
          DetachFromProcess((__int64)process, (__int64)&v16, (char)v4, a3);
      }
      ObfDereferenceObject(process);
    }
    if ( v4 )
    {
      v11 = buffer[3];
      v12 = *(char **)(buffer + 1);
      if ( buffer[3] )
      {
        v13 = (unsigned __int64)&v12[v11 - 1];
        if ( v13 < (unsigned __int64)v12 || v13 >= MmUserProbeAddress )
          ExRaiseAccessViolation(v11, v13);
      }
      v14 = (_DWORD *)*v4;
      if ( *(_DWORD *)*v4 < (unsigned int)v11 )
        LODWORD(v11) = *v14;
      memmove(v12, v14, (unsigned int)v11);
      v15 = 1;
      sub_20430(v4);
    }
    result = v15;
  }
  else
  {
    result = 0;
  }
  return result;
}

UNK_BUFFER3 *__fastcall CheckCurrentProcess(__int64 a1, __int64 a2)
{
  char v3; // r14 MAPDST
  __int64 currentProcess; // rax MAPDST
  UNK_BUFFER3 *buffer; // rax MAPDST
  _IMAGE_DOS_HEADER *v8; // rax
  _IMAGE_DOS_HEADER *v9; // rax
  unsigned int processFlags; // esi
  _IMAGE_DOS_HEADER *baseAddress; // rbx
  __int64 v12; // rdx
  bool v13; // al
  __int64 v14; // rdx
  __int64 v15; // rcx
  __int64 currentProcess2; // rax MAPDST
  __int64 currentProcessID2; // rax
  bool v19; // cf
  int v20; // eax
  bool v21; // cf
  int v22; // eax
  bool v23; // cf
  int v24; // eax
  bool v25; // cf
  int v26; // eax
  bool v27; // cf
  int v28; // eax
  __int64 parentPID; // rax
  signed int v30; // eax
  PVOID v31; // rcx
  char v32; // al
  char v33; // al
  UNICODE_STRING *v34; // r13
  __int64 v35; // rdx
  _IMAGE_DOS_HEADER *v36; // rax
  unsigned __int64 v37; // rcx
  unsigned __int16 *v38; // rbx
  int v39; // eax
  unsigned int *v40; // rax
  char filename; // [rsp+50h] [rbp-38h]
  unsigned __int16 v43; // [rsp+58h] [rbp-30h]
  unsigned __int8 v44; // [rsp+5Ah] [rbp-2Eh]
  unsigned __int16 v45; // [rsp+5Ch] [rbp-2Ch]
  unsigned int v46; // [rsp+98h] [rbp+10h]
  PVOID parentProcess; // [rsp+A0h] [rbp+18h]
  __int64 currentProcessID; // [rsp+A8h] [rbp+20h]

  v3 = a1;
  v3 = 0;
  currentProcess = import_PsGetCurrentProcess(a1, a2);
  if ( import_PsGetProcessId )
    currentProcessID = import_PsGetProcessId(currentProcess);
  else
    currentProcessID = 0i64;
  buffer = (UNK_BUFFER3 *)AllocatePool(816i64);
  if ( !buffer )
    goto LABEL_99;
  memset(buffer, 0, 0x330ui64);
  v8 = (_IMAGE_DOS_HEADER *)GetProcessBaseAddress(currentProcess);
  buffer->base_address = v8;
  if ( !v8 )
  {
    v9 = (_IMAGE_DOS_HEADER *)GetUsermodeModule(0i64);
    buffer->base_address = v9;
    if ( !v9 )
      goto LABEL_99;
  }
  if ( IsWin32ConsoleSubsystem(currentProcess) )
  {
    processFlags = 0x8001;
  }
  else if ( HasComDescriptor(buffer->base_address) )
  {
    processFlags = 9;
  }
  else if ( GetUsermodeModule((UNICODE_STRING *)(StringTable + 5202)) )// msvbvm60.dll
  {
    processFlags = 17;
  }
  else
  {
    processFlags = 1;
    if ( GetUsermodeModule((UNICODE_STRING *)(StringTable + 4894)) )// perl512.dll
      processFlags = 4097;
  }
  baseAddress = buffer->base_address;
  v13 = IsDbgUiRemoteBreakinPatchedToCallLdrShutdownProcess() || HasBlankNamedSections((__int64)baseAddress, v12);
  if ( v13 )
    processFlags |= 0x20u;
  if ( IsObufuscatedByVMP((__int64)buffer->base_address, v12) )// check for .vmp0 section
    processFlags |= 0x40u;
  currentProcess2 = import_PsGetCurrentProcess(v15, v14);
  if ( import_PsGetProcessId )
    currentProcessID2 = import_PsGetProcessId(currentProcess2);
  else
    currentProcessID2 = 0i64;
  if ( !IsProtectedGameProcessMaybe(currentProcessID2) && GetProcessFileName(currentProcess2, &filename) )
  {
    v19 = *(_QWORD *)&filename < *(_QWORD *)(StringTable + 5148);// dllhost.exe
    if ( *(_QWORD *)&filename != *(_QWORD *)(StringTable + 5148)
      || (v19 = v43 < *(_WORD *)(StringTable + 5156), v43 != *(_WORD *)(StringTable + 5156))
      || (v19 = v44 < *(_BYTE *)(StringTable + 5158), v44 != *(_BYTE *)(StringTable + 5158)) )
    {
      v20 = -v19 - (v19 - 1);
    }
    else
    {
      v20 = 0;
    }
    if ( !v20 )
      goto processname_matched;
    v21 = *(_QWORD *)&filename < *(_QWORD *)(StringTable + 4545);// svchost.exe
    if ( *(_QWORD *)&filename != *(_QWORD *)(StringTable + 4545)
      || (v21 = v43 < *(_WORD *)(StringTable + 4553), v43 != *(_WORD *)(StringTable + 4553))
      || (v21 = v44 < *(_BYTE *)(StringTable + 4555), v44 != *(_BYTE *)(StringTable + 4555)) )
    {
      v22 = -v21 - (v21 - 1);
    }
    else
    {
      v22 = 0;
    }
    if ( !v22 )
      goto processname_matched;
    v23 = *(_QWORD *)&filename < *(_QWORD *)(StringTable + 5160);// taskhost.exe
    if ( *(_QWORD *)&filename != *(_QWORD *)(StringTable + 5160)
      || (v23 = *(_DWORD *)&v43 < *(_DWORD *)(StringTable + 5168), *(_DWORD *)&v43 != *(_DWORD *)(StringTable + 5168)) )
    {
      v24 = -v23 - (v23 - 1);
    }
    else
    {
      v24 = 0;
    }
    if ( !v24 )
      goto processname_matched;
    v25 = *(_QWORD *)&filename < *(_QWORD *)(StringTable + 5173);// taskhostex.exe
    if ( *(_QWORD *)&filename != *(_QWORD *)(StringTable + 5173)
      || (v25 = *(_DWORD *)&v43 < *(_DWORD *)(StringTable + 5181), *(_DWORD *)&v43 != *(_DWORD *)(StringTable + 5181))
      || (v25 = v45 < *(_WORD *)(StringTable + 5185), v45 != *(_WORD *)(StringTable + 5185)) )
    {
      v26 = -v25 - (v25 - 1);
    }
    else
    {
      v26 = 0;
    }
    if ( !v26
      || ((v27 = *(_QWORD *)&filename < *(_QWORD *)(StringTable + 5188),
           *(_QWORD *)&filename != *(_QWORD *)(StringTable + 5188))// taskhostw.exe
       || (v27 = *(_DWORD *)&v43 < *(_DWORD *)(StringTable + 5196), *(_DWORD *)&v43 != *(_DWORD *)(StringTable + 5196))
       || (v27 = (unsigned __int8)v45 < *(_BYTE *)(StringTable + 5200), (_BYTE)v45 != *(_BYTE *)(StringTable + 5200)) ? (v28 = -v27 - (v27 - 1)) : (v28 = 0),
          !v28) )
    {
processname_matched:                            // this is executed if process name equals any of listed above
      processFlags |= 0x2000u;
      if ( currentProcess2 )
      {
        if ( import_PsGetProcessInheritedFromUniqueProcessId )
          parentPID = import_PsGetProcessInheritedFromUniqueProcessId(currentProcess2);
        else
          parentPID = 0i64;
      }
      else
      {
        parentPID = 0i64;
      }
      if ( parentPID )
      {
        v30 = import_PsLookupProcessByProcessId ? (unsigned int)import_PsLookupProcessByProcessId(
                                                                  parentPID,
                                                                  &parentProcess) : -1073741822;
        if ( v30 >= 0 )
        {
          if ( MEMORY[0xFFFFF7800000026C] != 5 )
          {
            v31 = parentProcess;
            if ( !parentProcess )
            {
LABEL_72:
              processFlags |= 0x4000u;
LABEL_74:
              ObfDereferenceObject(v31);
              goto LABEL_76;
            }
            if ( !QueryTokenIntegrityLevel((__int64)parentProcess, (__int64)&v46) || v46 < 0x4000 )
            {
              v31 = parentProcess;
              goto LABEL_72;
            }
          }
          v31 = parentProcess;
          goto LABEL_74;
        }
      }
      processFlags |= 0x4000u;
    }
  }
LABEL_76:
  if ( v3 && (!currentProcess ? (v32 = 0) : (v32 = GetProcessPath(currentProcess, (__int64)&buffer->process_path)), v32)
    || v3 && GetMappedFilename(-1i64, (__int64)buffer->base_address, (__int64)&buffer->process_path, 0)
    || v3
    && (!currentProcessID ? (v33 = 0) : (v33 = GetProcessImageFileName(&buffer->process_path, currentProcessID, 0)), v33)
    || (v34 = &buffer->process_path, GetProcessPathOrCommandLine(currentProcess, 1, (__int64)&buffer->process_path)) )
  {
    buffer->success = 1;
    v34 = &buffer->process_path;
    if ( IsFileInSystemDirectory(&buffer->process_path) )
      processFlags |= 0x200u;
  }
  v36 = buffer->base_address;
  v37 = (unsigned __int64)&v36[63].e_lfanew + 3;
  if ( (_IMAGE_DOS_HEADER *)((char *)&v36[63].e_lfanew + 3) < v36 || v37 >= MmUserProbeAddress )
  {
    ExRaiseAccessViolation(v37, v35);
  }
  else
  {
    v38 = (unsigned __int16 *)((unsigned __int64)v34 & -(signed __int64)(buffer->success != 0));
    v39 = GetProcessBitness2(currentProcess);
    v40 = CopyProcessInformation(buffer->base_address, 0x1000ui64, 0i64, processFlags, v39, v38, currentProcessID, 0i64);
    *(_QWORD *)&buffer->char0 = v40;
    if ( v40 )
    {
      if ( !buffer->success && GetProcessFileName(currentProcess, &filename) )
        CopyString(*(_QWORD *)&buffer->char0 + 22i64, 0x100ui64, &filename);
      v3 = 1;
    }
  }
LABEL_99:
  if ( !v3 && buffer )
  {
    sub_20430((__int64 *)&buffer->char0);
    buffer = 0i64;
  }
  return buffer;
}

unsigned int *__fastcall CopyProcessInformation(_IMAGE_DOS_HEADER *baseAddress, unsigned __int64 a2, unsigned __int64 a3, unsigned int a4, int a5, unsigned __int16 *a6, __int16 a7, _QWORD *a8)
{
  _DWORD *buffer; // rax MAPDST
  __int64 v14; // rdx
  bool v15; // al
  _WORD *v16; // rcx
  __int64 v17; // r9
  unsigned __int64 v18; // r8
  signed int v19; // eax
  unsigned __int16 v20; // dx
  signed __int64 v21; // rdx
  __int64 v22; // r9
  _QWORD *v23; // r13
  char *v24; // rcx
  int v25; // eax
  _IMAGE_NT_HEADERS64 *v26; // rdx
  _IMAGE_SECTION_HEADER *v27; // rcx
  USHORT v28; // r8
  __int64 v29; // rdi
  int v30; // er13
  unsigned int *v31; // rax
  unsigned int *v32; // rbx
  _IMAGE_NT_HEADERS64 *ntHeader; // [rsp+28h] [rbp-E0h]
  char *Src; // [rsp+30h] [rbp-D8h]
  _DWORD *v35; // [rsp+38h] [rbp-D0h]
  _DWORD *v36; // [rsp+40h] [rbp-C8h]
  int v38; // [rsp+50h] [rbp-B8h]
  _IMAGE_SECTION_HEADER *v39; // [rsp+58h] [rbp-B0h]
  char debugstring; // [rsp+60h] [rbp-A8h]

  buffer = (_DWORD *)AllocatePool(4676i64);
  if ( !buffer )
    return 0i64;
  memset(buffer, 0, 0x244ui64);
  *(_QWORD *)(buffer + 1) = baseAddress;
  buffer[3] = a2;
  buffer[4] = a4;
  if ( a5 )
    *((_BYTE *)buffer + 20) = a5;
  else
    *((_BYTE *)buffer + 20) = 64;
  *((_WORD *)buffer + 267) = a7;
  v15 = !a6 || !*((_QWORD *)a6 + 1) || !*a6 || !a6[1];
  if ( !v15 )
  {
    v16 = (_WORD *)((char *)buffer + 22);
    v17 = 0i64;
    v18 = 0i64;
    v19 = 0;
    if ( *(_BYTE *)a6 & 1 || (v20 = a6[1], v20 & 1) || *a6 > v20 || v20 > 0xFFFEu )
    {
      v19 = 0xC000000D;
    }
    else if ( !*((_QWORD *)a6 + 1) && (*a6 || v20) )
    {
      v19 = -1073741811;
    }
    if ( v19 >= 0 )
    {
      v17 = *((_QWORD *)a6 + 1);
      v18 = (unsigned __int64)*a6 >> 1;
    }
    if ( v19 < 0 )
    {
      *v16 = 0;
    }
    else
    {
      v21 = 256i64;
      v22 = v17 - (_QWORD)v16;
      do
      {
        if ( !v18 )
          break;
        *v16 = *(_WORD *)((char *)v16 + v22);
        ++v16;
        --v21;
        --v18;
      }
      while ( v21 );
      if ( !v21 )
        --v16;
      *v16 = 0;
    }
    if ( sub_289F0(a6, (__int64)&ntHeader) )
      *((_BYTE *)buffer + 21) = (unsigned __int64)(*a6 - (unsigned int)ntHeader) >> 1;
  }
  v23 = buffer + 145;
  v35 = buffer + 145;
  if ( baseAddress && a2 && (unsigned __int64)baseAddress < MmHighestUserAddress )
  {
    v24 = (char *)baseAddress + a2 - 1;
    if ( v24 < (char *)baseAddress || (unsigned __int64)v24 >= MmUserProbeAddress )
    {
      ExRaiseAccessViolation(v24, v14);
    }
    else if ( ValidatePeHeader(baseAddress, a2, 0i64, &ntHeader) && (v25 = IsPe64Or32Bit(baseAddress), (v38 = v25) != 0) )
    {
      *((_BYTE *)buffer + 20) = v25;
      v26 = ntHeader;
      buffer[134] = ntHeader->FileHeader.TimeDateStamp;
      *((_WORD *)buffer + 270) = v26->FileHeader.Machine;
      *((_WORD *)buffer + 271) = v26->FileHeader.Characteristics;
      *((_WORD *)buffer + 284) = 0;
      if ( v25 == 64 )
        buffer[136] = v26->OptionalHeader.ImageBase;
      else
        buffer[136] = HIDWORD(v26->OptionalHeader.ImageBase);
      buffer[137] = v26->OptionalHeader.SizeOfImage;
      buffer[138] = v26->OptionalHeader.BaseOfCode;
      buffer[139] = v26->OptionalHeader.SizeOfCode;
      buffer[140] = v26->OptionalHeader.AddressOfEntryPoint;
      buffer[141] = v26->OptionalHeader.CheckSum;
      v36 = buffer + 145;
      v27 = (_IMAGE_SECTION_HEADER *)((char *)&v26->OptionalHeader + v26->FileHeader.SizeOfOptionalHeader);
      v28 = 0;
      while ( v28 < v26->FileHeader.NumberOfSections )
      {
        if ( (_IMAGE_SECTION_HEADER *)((char *)&v27->Characteristics + 3) < v27
          || (unsigned __int64)&v27->Characteristics + 3 >= MmUserProbeAddress )
        {
          ExRaiseAccessViolation(v27, v26);
          break;
        }
        *v23 = *(_QWORD *)v27->Name;
        ++*((_WORD *)buffer + 284);
        ++v28;
        ++v27;
        v39 = v27;
        ++v23;
        v36 = v23;
      }
      v35 = v23;
      if ( CopyRawDataFromDebugDirectory(baseAddress, (__int64)&debugstring) )
      {
        Src = &debugstring;
        InitAnsiString((ANSI_STRING *)&ntHeader, &debugstring);
        v29 = (unsigned __int16)ntHeader;
        memmove(v23, Src, (unsigned __int16)ntHeader);
        v23 = (_QWORD *)((char *)v23 + v29);
        v35 = v23;
        *((_WORD *)buffer + 287) = v29;
      }
    }
    else
    {
      buffer[4] |= 0x80u;
    }
  }
  v30 = (_DWORD)v23 - (_DWORD)buffer;
  *buffer = v30;
  v31 = (unsigned int *)AllocatePool((unsigned int)(v30 + a3));
  v32 = v31;
  if ( v31 )
  {
    memmove(v31, buffer, (unsigned int)*buffer);
    if ( a3 > 0 )
    {
      if ( a8 )
        *a8 = (char *)v32 + *v32;
    }
  }
  FreePool((__int64)buffer);
  return v32;
}