char __usercall CheckServiceTable@<al>(signed int a1@<r14d>)
{
  unsigned int v2; // er12
  unsigned __int64 lstar; // rax MAPDST
  unsigned __int64 lstarEnd; // rbp
  unsigned int serviceTableHash; // edi
  unsigned int systemVersion; // eax MAPDST
  __int64 packetType; // rcx
  SystemServiceDescriptorTable *ssdt; // rsi
  unsigned int *detectionBuffer; // rbp
  unsigned int *functionDetectionBuffer; // r12
  unsigned int index; // ebx
  _BYTE *functionName; // rcx
  char *zwSyscallFunction; // rax MAPDST
  __int64 syscallIndex; // rax
  char *syscallFunctionFromSDDT; // rcx
  ULONG numOfServices; // edx
  unsigned int v20; // [rsp+40h] [rbp+8h]

  systemVersion = GetSystemVersion();
  v2 = systemVersion;
  v20 = systemVersion;
  lstar = __readmsr(0xC0000082);
  lstarEnd = (lstar & 0xFFFFFFFFFFFFF000ui64) + 0xFF1;
  if ( KeGetCurrentIrql() > 1u )
    return 0;
  serviceTableHash = 0;
  if ( !lstar )
    return 0;
  if ( !IsAddressWithinNtoskrnl(lstar) )
  {
    systemVersion = GetSystemVersion();
    packetType = 328i64;
    v20 = systemVersion;
LABEL_5:
    SendPacketToServer(packetType, (__int64)&v20, 4i64);
    return 0;
  }
  if ( lstar >= lstarEnd )
  {
LABEL_14:
    ssdt = 0i64;
  }
  else
  {
    while ( 1 )
    {
      if ( (*(_DWORD *)lstar & 0xFFFFFF) == 0x158D4C// lea r10, [rip+offset]
                                                // lea r11, [rip+offset]
                                                // test [something]
        && (*(_DWORD *)(lstar + 7) & 0xFFFFFF) == 0x1D8D4C
        && *(_BYTE *)(lstar + 14) == 0xF7u )
      {
        ssdt = (SystemServiceDescriptorTable *)(*(unsigned int *)(lstar + 3) + lstar + 7);
        if ( IsAddressWithinNtoskrnl((unsigned __int64)ssdt) )
          break;
      }
      if ( ++lstar >= lstarEnd )
        goto LABEL_14;
    }
  }
  if ( !ssdt )
    return 0;
  if ( !IsAddressWithinNtoskrnl((unsigned __int64)ssdt) )
  {
    packetType = 327i64;
    goto LABEL_5;
  }
  if ( !(unsigned __int8)MmIsAddressValid(ssdt) )
    return 0;
  detectionBuffer = (unsigned int *)AllocatePool(72i64);
  memset(detectionBuffer, 0, 72ui64);
  *detectionBuffer = v2;
  functionDetectionBuffer = detectionBuffer + 3;
  index = 0;
  do
  {
    if ( index )
    {
      switch ( index )
      {
        case 1u:
          functionName = (_BYTE *)(StringTable + 4658);// ZwDeviceIoControlFile
          break;
        case 2u:
          functionName = (_BYTE *)(StringTable + 4680);// ZwQueryInformationProcess
          break;
        case 3u:
          functionName = (_BYTE *)(StringTable + 4706);// ZwQuerySystemInformation
          break;
        case 4u:
          functionName = (_BYTE *)(StringTable + 4731);// ZwQueryVirtualMemory
          break;
        default:
          functionName = 0i64;
          break;
      }
    }
    else
    {
      functionName = (_BYTE *)(StringTable + 4645);// ZwCreateFile
    }
    zwSyscallFunction = (char *)GetKernelSyscallFunctionForNtdllFunction(functionName, a1);
    if ( zwSyscallFunction )
    {
      functionDetectionBuffer[1] = UnkHashFunction(zwSyscallFunction, 0x40i64, 0i64);
      if ( GetSyscallIndexFromFunction(&v20, (unsigned __int64)zwSyscallFunction, a1) )
      {
        syscallIndex = v20;
        *functionDetectionBuffer = v20;
        if ( (unsigned int)syscallIndex > 0xFFF || (unsigned int)syscallIndex >= ssdt->NumberOfServices )
          syscallFunctionFromSDDT = 0i64;
        else
          syscallFunctionFromSDDT = (char *)ssdt->ServiceTableBase
                                  + ((unsigned __int64)*((unsigned int *)ssdt->ServiceTableBase + syscallIndex) >> 4);
        functionDetectionBuffer[2] = UnkHashFunction(syscallFunctionFromSDDT, 64i64, 0i64);
      }
    }
    ++index;
    functionDetectionBuffer += 3;
  }
  while ( index < 5 );
  numOfServices = ssdt->NumberOfServices;
  if ( numOfServices <= 0xFFF )
    serviceTableHash = HashCRC32((char *)ssdt->ServiceTableBase, 4 * numOfServices, 0);
  detectionBuffer[1] = serviceTableHash;
  detectionBuffer[2] = ssdt->NumberOfServices;
  SendPacketToServer(317i64, (__int64)detectionBuffer, 72i64);
  FreePool((__int64)detectionBuffer);
  return 1;
}

_WORD *__usercall GetKernelSyscallFunctionForNtdllFunction@<rax>(_BYTE *funcName@<rcx>, signed int a2@<r14d>)
{
  _WORD *v3; // rbx Gets kernel ZwXXX function address which  is equivallent to ntdll Nt/ZwXXX function
  _WORD *result; // rax
  unsigned int copySize; // edi
  char *ntdllExportRva; // rax
  int ntdllSyscallIndex; // er12
  unsigned int i; // edi
  char *ntdllByte; // r13
  int v12; // eax
  __int64 zwFuncIt; // rsi
  char foundRet; // r13
  int syscallIndexOffset; // er15
  unsigned int ntoskrnlOffset; // edi
  unsigned int j; // er14
  unsigned int instructionSize; // eax
  int v19; // ecx
  void *v20; // rcx
  char v21; // al
  _WORD *addr; // rcx
  _BYTE *addr0; // r8 MAPDST
  unsigned __int64 currentOffset; // rdx
  unsigned __int8 v26; // [rsp+48h] [rbp-2E0h]
  __int64 v27; // [rsp+50h] [rbp-2D8h]
  __int64 v28; // [rsp+58h] [rbp-2D0h]
  _WORD *sectionVa; // [rsp+60h] [rbp-2C8h]
  unsigned __int64 v30; // [rsp+68h] [rbp-2C0h]
  char *ntoskrnlBuffer0; // [rsp+70h] [rbp-2B8h] MAPDST
  unsigned __int8 v33; // [rsp+80h] [rbp-2A8h]
  __int64 v34; // [rsp+95h] [rbp-293h]
  __int64 v35; // [rsp+9Dh] [rbp-28Bh]
  char ntdllBuffer[64]; // [rsp+B0h] [rbp-278h]
  char ntoskrnlBuffer[120]; // [rsp+F0h] [rbp-238h]
  unsigned int size; // [rsp+330h] [rbp+8h]
  void *bufferIt; // [rsp+338h] [rbp+10h] MAPDST
  size_t instructionSize_; // [rsp+340h] [rbp+18h]
  unsigned __int64 sectionSize; // [rsp+348h] [rbp+20h]

  v3 = 0i64;
  v26 = 0;
  result = 0i64;
  v27 = 0i64;
  v28 = 0i64;
  if ( funcName && *funcName )
  {
    copySize = 0;
    if ( StringTable != 0xFFFFFFFFFFFFDB93i64
      && ReadFileA((const char *)(StringTable + 0x246D), (__int64)&bufferIt, (__int64)&size) )// \SystemRoot\system32\ntdll.dll
    {
      ntdllExportRva = GetPeExportRva((_IMAGE_DOS_HEADER *)bufferIt, size, (unsigned __int64)funcName);
      if ( ntdllExportRva )
      {
        copySize = size - (_DWORD)ntdllExportRva;
        if ( size - (unsigned int)ntdllExportRva > 64 )
          copySize = 64;
        memmove(ntdllBuffer, (char *)bufferIt + (_QWORD)ntdllExportRva, copySize);
      }
      if ( bufferIt )
        FreePool((__int64)bufferIt);
    }
    if ( copySize )
    {
      if ( GetNtoskrnlSection('txet.', &sectionVa, &sectionSize) )
      {
        ntdllSyscallIndex = 0;
        for ( i = 0; i < 0x10; i += v12 )
        {
          ntdllByte = &ntdllBuffer[i];
          v12 = GetInstructionSize(&v33, &ntdllBuffer[i], a2);
          if ( _bittest((const signed __int32 *)&v35 + 1, 0xCu) )
            break;
          if ( *ntdllByte == 0xB8u )            // mov     eax, ??h
          {
            ntdllSyscallIndex = *(_DWORD *)&ntdllBuffer[i + 1];
            break;
          }
          if ( *ntdllByte == 0xC2u || *ntdllByte == 0xC3u )
            break;
        }
        if ( ntdllSyscallIndex )
        {
          zwFuncIt = (__int64)FindExport((DATA_HASH_BUFFER *)&unk_47588);// can be any ZwXX function
          if ( zwFuncIt )
          {
            foundRet = 0;
            syscallIndexOffset = 0;
            ntoskrnlOffset = 0;
            for ( j = 0; j < 0x10; ++j )
            {
              instructionSize = GetInstructionSize(&v33, (_BYTE *)zwFuncIt, j);
              size = instructionSize;
              if ( _bittest((const signed __int32 *)&v35 + 1, 0xCu) )
                break;
              instructionSize_ = instructionSize;
              bufferIt = &ntoskrnlBuffer[ntoskrnlOffset];
              memmove(&ntoskrnlBuffer[ntoskrnlOffset], (const void *)zwFuncIt, instructionSize);
              if ( *(_BYTE *)zwFuncIt == 0xB8u )
              {
                syscallIndexOffset = ntoskrnlOffset + 1;
                *(_DWORD *)&ntoskrnlBuffer[ntoskrnlOffset + 1] = ntdllSyscallIndex;
              }
              else
              {
                if ( *(_BYTE *)zwFuncIt == 0xC2u || *(_BYTE *)zwFuncIt == 0xC3u )
                {
                  if ( *(_BYTE *)zwFuncIt == 0xC2u )
                    *(_WORD *)&ntoskrnlBuffer[ntoskrnlOffset + 1] = 0xAAAAu;
                  ntoskrnlOffset += size;
                  foundRet = 1;
                  break;
                }
                v19 = HIDWORD(v35);
                if ( _bittest(&v19, 9u) || _bittest(&v19, 8u) )
                {
                  v26 = v33;
                  v27 = v34;
                  v28 = v35;
                  v20 = bufferIt;
                  if ( bufferIt )
                  {
                    v21 = sub_17FB0((unsigned __int64)bufferIt, &v26);
                    v20 = bufferIt;
                  }
                  else
                  {
                    v21 = 0;
                  }
                  if ( !v21 )
                  {
                    memset(v20, 170, instructionSize_);
                    *(_BYTE *)bufferIt = *(_BYTE *)zwFuncIt;
                  }
                  if ( *(_BYTE *)zwFuncIt == 0xE9u )
                  {
                    ntoskrnlOffset += size;
                    goto LABEL_46;
                  }
                }
              }
              ntoskrnlOffset += size;
              zwFuncIt += instructionSize_;
            }
            if ( !foundRet )
              goto LABEL_60;
LABEL_46:
            if ( syscallIndexOffset && ntoskrnlOffset >= 2 && ntoskrnlOffset <= sectionSize )
            {
              for ( addr = sectionVa;
                    addr < (_WORD *)((char *)sectionVa + sectionSize - ntoskrnlOffset);
                    addr = (_WORD *)((char *)addr + 1) )
              {
                if ( *addr == *(_WORD *)ntoskrnlBuffer )
                {
                  addr0 = addr;
                  addr0 = addr;
                  ntoskrnlBuffer0 = ntoskrnlBuffer;
                  ntoskrnlBuffer0 = ntoskrnlBuffer;
                  currentOffset = 0i64;
                  v30 = 0i64;
                  while ( currentOffset < ntoskrnlOffset && (*addr0 == *ntoskrnlBuffer0 || *ntoskrnlBuffer0 == 0xAAu) )
                  {
                    v30 = ++currentOffset;
                    ++addr0;
                    ++ntoskrnlBuffer0;
                  }
                  if ( currentOffset == ntoskrnlOffset )
                  {
                    v3 = addr;
                    break;
                  }
                }
              }
            }
          }
        }
LABEL_60:
        result = v3;
      }
      else
      {
        result = 0i64;
      }
    }
    else
    {
      result = 0i64;
    }
  }
  return result;
}