char __fastcall CheckForSuspiciousModules(__int64 a1)
{
  char suspiciousModulesFound; // di
  __int64 *processes; // rax MAPDST
  unsigned int processCount; // esi
  __int64 *pProcess; // rbp
  __int64 v7; // rsi

  suspiciousModulesFound = 0;
  processes = (__int64 *)AllocatePool(4096i64);
  if ( processes )
  {
    processCount = Get512RunningProcessesFromThreads(processes);
    if ( processCount )
    {
      ObfDereferenceObject((PVOID)*processes);
      if ( processCount > 1 )
      {
        pProcess = processes + 1;
        v7 = processCount - 1;
        do
        {
          if ( !suspiciousModulesFound && !sub_1F140(a1) )
            suspiciousModulesFound = IsProcessRunningSuspiciousModule(*pProcess, v7);
          ObfDereferenceObject((PVOID)*pProcess);
          ++pProcess;
          --v7;
        }
        while ( v7 );
      }
    }
    FreePool((__int64)processes);
  }
  return suspiciousModulesFound;
}

char __usercall IsProcessRunningSuspiciousModule@<al>(__int64 process@<rcx>, int a2@<esi>)
{
  char v3; // bl
  char v5; // [rsp+20h] [rbp-38h]

  v3 = 0;
  if ( AttachToProcess(process, (__int64)&v5) )
  {
    if ( GetUsermodeModule((UNICODE_STRING *)(StringTable + 4830))// Dumper.dll
      && GetUsermodeModule((UNICODE_STRING *)(StringTable + 4852))// Glob.dll
      && GetUsermodeModule((UNICODE_STRING *)(StringTable + 4870))// mswsock.dll
      && GetUsermodeModule((UNICODE_STRING *)(StringTable + 4894))// perl512.dll
      || GetUsermodeModule((UNICODE_STRING *)(StringTable + 4918))// vmclientcore.dll
      || GetUsermodeModule((UNICODE_STRING *)(StringTable + 4952))// vmwarewui.dll
      || GetUsermodeModule((UNICODE_STRING *)(StringTable + 4980))// virtualbox.dll
      || GetUsermodeModule((UNICODE_STRING *)(StringTable + 5010))// qtcorevbox4.dll
      || GetUsermodeModule((UNICODE_STRING *)(StringTable + 5042))// vboxvmm.dll
      || GetUsermodeModule((UNICODE_STRING *)(StringTable + 5066)) )// netredirect.dll
    {
      v3 = 1;
    }
    if ( process )
      DetachFromProcess(process, (__int64)&v5, process, a2);
  }
  return v3;
}

char CheckRunningPrograms()
{
  char v0; // bp
  HANDLE *processes; // rax MAPDST
  unsigned int status; // er13
  unsigned int index; // esi
  HANDLE *current; // r12
  signed int v6; // eax
  char v7; // bl
  __int64 v8; // rbx
  unsigned __int64 v9; // r8
  SYSTEM_MODULE_INFORMATION *moduleInformation; // rax MAPDST
  __int64 v11; // r8
  ULONG v13; // esi
  USHORT *v14; // rdi
  CHAR *v15; // rdx
  __int64 v16; // r8
  __int64 v17; // r8
  ANSI_STRING a1; // [rsp+20h] [rbp-48h]
  char v20; // [rsp+30h] [rbp-38h]
  PVOID process; // [rsp+70h] [rbp+8h]

  v0 = 0;
  processes = (HANDLE *)AllocatePool(2048i64);
  if ( !processes )
    goto LABEL_34;
  status = GetRunningProcesses(processes, 0x100u, 0i64, 0i64);
  if ( status > 0 )
  {
    index = 0;
    current = processes;
    while ( 1 )
    {
      if ( *current )
      {
        v6 = import_PsLookupProcessByProcessId ? (unsigned int)import_PsLookupProcessByProcessId(*current, &process) : 0xC0000002;
        if ( v6 >= 0 )
        {
          v7 = GetProcessFileName((__int64)process, &v20);
          ObfDereferenceObject(process);
          if ( v7 )
          {
            v8 = StringTable;
            if ( strstrIgnoreCase(&v20, (_BYTE *)(StringTable + 8018), 7ui64)// dbgview
              || strstrIgnoreCase(&v20, (_BYTE *)(v8 + 8026), v9)// devenv
              || strstrIgnoreCase(&v20, (_BYTE *)(v8 + 8034), 3ui64) )// tv_
            {
              break;
            }
          }
        }
      }
      ++index;
      ++current;
      if ( index >= status )
        goto LABEL_16;
    }
    v0 = 1;
  }
LABEL_16:
  FreePool((__int64)processes);
  if ( !v0 )
  {
LABEL_34:
    moduleInformation = (SYSTEM_MODULE_INFORMATION *)QuerySystemModuleInformation(0);
    if ( moduleInformation )
    {
      v13 = 0;
      if ( moduleInformation->Count > 0 )
      {
        v14 = &moduleInformation->Module[0].OffsetToFileName;
        while ( 1 )
        {
          if ( *(_QWORD *)(v14 - 11) >= MmSystemRangeStart )
          {
            v15 = (char *)v14 + *v14 + 2;
            a1.Buffer = v15;
            if ( v15 )
            {
              SetAnsiStringLength(&a1, v15);
            }
            else
            {
              a1.Length = 0;
              a1.MaximumLength = 0;
            }
            LOBYTE(v11) = 1;
            if ( !(unsigned int)strstr2((__int64)&a1, (const char *)(StringTable + 8038), v11) )// Dbgv.sys
              break;
            LOBYTE(v16) = 1;
            if ( !(unsigned int)strstr2((__int64)&a1, (const char *)(StringTable + 8047), v16) )// PROCMON23.sys
              break;
            LOBYTE(v17) = 1;
            if ( !(unsigned int)strstr2((__int64)&a1, (const char *)(StringTable + 8061), v17) )// dbk64.sys
              break;
          }
          ++v13;
          v14 += 148;
          if ( v13 >= moduleInformation->Count )
            goto LABEL_30;
        }
        v0 = 1;
      }
LABEL_30:
      FreePool((__int64)moduleInformation);
    }
  }
  return v0;
}

bool __fastcall SomeModuleCheck(UNICODE_STRING *a1)
{
  UNICODE_STRING *v1; // rbx
  __int64 v2; // rdi
  bool result; // al

  v1 = a1;
  result = 0;
  if ( a1 )
  {
    if ( a1->Buffer )
    {
      if ( a1->Length )
      {
        if ( a1->MaximumLength )
        {
          v2 = StringTable;
          if ( CompareUnicodeStringsIgnoreCase(a1, (unsigned __int16 *)(StringTable + 8467))//  \System32\atmfd.dll
            || CompareUnicodeStringsIgnoreCase(v1, (unsigned __int16 *)(v2 + 8507))//  \System32\cdd.dll
            || CompareUnicodeStringsIgnoreCase(v1, (unsigned __int16 *)(v2 + 8543))// \System32\rdpdd.dll
            || CompareUnicodeStringsIgnoreCase(v1, (unsigned __int16 *)(v2 + 8583))// \System32\vga.dll
            || CompareUnicodeStringsIgnoreCase(v1, (unsigned __int16 *)(v2 + 8619)) )// \System32\workerdd.dll
          {
            result = 1;
          }
        }
      }
    }
  }
  return result;
}