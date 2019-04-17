__int64 ScanSystemThreads()
{
  __int64 result; // rax
  __int64 currentProcessId; // r14
  int isSystemThread; // er11
  __int64 systemBigPoolInformation; // r12
  SYSTEM_MODULE_INFORMATION *systemModuleInformation; // r13
  CONTEXT *context; // rsi
  unsigned __int64 currentThreadId; // rbx
  signed int status0; // eax
  STACKWALK_ENTRY *entry; // rdi
  __int64 v10; // rcx
  int entryIndex; // er10
  __int64 v12; // r11
  unsigned __int64 v13; // rcx
  int status1; // eax
  __int64 threadProcessId; // rax
  STACKWALK_BUFFER stackwalkBuffer; // [rsp+30h] [rbp-238h]
  PVOID threadObject; // [rsp+270h] [rbp+8h] MAPDST
  __int64 win32StartAddress; // [rsp+278h] [rbp+10h] MAPDST
 
  result = import_PsGetCurrentThreadProcessId();
  currentProcessId = result;
  if ( import_PsIsSystemThread )
  {
    result = import_PsIsSystemThread(__readgsqword(0x188u));
    isSystemThread = (unsigned __int8)result;
  }
  else
  {
    isSystemThread = 0;
  }
  if ( isSystemThread )
  {
    result = import_PsGetCurrentProcess();
    if ( result == PsInitialSystemProcess )
    {
      systemBigPoolInformation = QuerySystemInformation(0x42i64, 0x100000i64, 0x2000000i64);
      result = QuerySystemModuleInformation();
      systemModuleInformation = (SYSTEM_MODULE_INFORMATION *)result;
      if ( result )
      {
        context = (CONTEXT *)AllocatePool(0x4D0i64);
        if ( context )
        {
          currentThreadId = 4i64;
          do
          {
            if ( import_PsLookupThreadByThreadId )
              status0 = import_PsLookupThreadByThreadId(currentThreadId, &threadObject);
            else
              status0 = 0xC0000002;
            if ( status0 >= 0 )
            {
              if ( GetProcessId((__int64)threadObject) == currentProcessId
                && threadObject != (PVOID)__readgsqword(0x188u)
                && StackwalkThread((__int64)threadObject, context, &stackwalkBuffer)
                && stackwalkBuffer.EntryCount > 0u )
              {
                entry = stackwalkBuffer.Entries;
                while ( 1 )
                {
                  if ( !GetModuleEntryForAddress(entry->RipValue, &systemModuleInformation->Count) )
                  {
                    if ( !v10 )
                      break;
                    if ( !v12 )
                      break;
                    v13 = *(_QWORD *)(v12 + 24);
                    if ( !v13
                      || *(_DWORD *)(v12 + 32) <= 0u
                      || entry->RipValue < v13
                      || entry->RipValue >= v13 + *(unsigned int *)(v12 + 32) )
                    {
                      break;
                    }
                  }
                  ++entry;
                  if ( (unsigned int)(entryIndex + 1) >= stackwalkBuffer.EntryCount )
                    goto LABEL_30;
                }
                status1 = QueryWin32StartAddress((__int64)threadObject, &win32StartAddress);
                if ( status1 < 0 )
                  win32StartAddress = 0i64;
                threadProcessId = GetProcessId((__int64)threadObject);
                PerformAdditionalScans(         // This is virtualized.
                                                // Probably checks if address is within any big pool and sends report to server.
                  threadProcessId,
                  (unsigned int)currentThreadId,
                  win32StartAddress,
                  systemModuleInformation,
                  systemBigPoolInformation,
                  &stackwalkBuffer);
              }
LABEL_30:
              ObfDereferenceObject(threadObject);
            }
            currentThreadId += 4i64;
          }
          while ( currentThreadId < 0x3000 );
          FreePool((__int64)context);
        }
        result = FreePool((__int64)systemModuleInformation);
      }
      if ( systemBigPoolInformation )
        result = FreePool(systemBigPoolInformation);
    }
  }
  return result;
}
 
char __fastcall StackwalkThread(__int64 threadObject, CONTEXT *context, STACKWALK_BUFFER *stackwalkBuffer)
{
  char status; // di
  _QWORD *stackBuffer; // rax MAPDST
  size_t copiedSize; // rax
  DWORD64 startRip; // rdx
  unsigned int index; // ebp
  unsigned __int64 rip0; // rcx
  DWORD64 rsp0; // rdx
  __int64 functionTableEntry; // rax
  __int64 moduleBase; // [rsp+40h] [rbp-48h]
  __int64 v17; // [rsp+48h] [rbp-40h]
  __int64 v18; // [rsp+50h] [rbp-38h]
  unsigned __int64 sectionVa; // [rsp+90h] [rbp+8h]
  __int64 sectionSize; // [rsp+A8h] [rbp+20h]
 
  status = 0;
  if ( !threadObject )
    return 0;
  if ( !stackwalkBuffer )
    return 0;
  memset(context, 0, 0x4D0ui64);
  memset(stackwalkBuffer, 0, 0x208ui64);
  if ( !import_RtlVirtualUnwind )
  {
    import_RtlVirtualUnwind = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD))FindExport((__int64)&unk_47420);
    if ( !import_RtlVirtualUnwind )
      return 0;
  }
  if ( !import_RtlLookupFunctionEntry )
  {
    import_RtlLookupFunctionEntry = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD))FindExport((__int64)&unk_473F0);
    if ( !import_RtlLookupFunctionEntry )
      return 0;
  }
  stackBuffer = (_QWORD *)AllocatePool(4096i64);
  if ( stackBuffer )
  {
    copiedSize = CopyThreadKernelStack(threadObject, 4096i64, stackBuffer, 4096);
    if ( copiedSize )
    {
      if ( copiedSize != 4096 && copiedSize >= 0x48 )
      {
        if ( GetNtoskrnlSection('txet.', &sectionVa, &sectionSize) )
        {
          startRip = stackBuffer[7];
          if ( startRip >= sectionVa && startRip < sectionSize + sectionVa )
          {
            status = 1;
            context->Rip = startRip;
            context->Rsp = (DWORD64)(stackBuffer + 8);
            index = 0;
            do
            {
              rip0 = context->Rip;
              rsp0 = context->Rsp;
              stackwalkBuffer->Entries[stackwalkBuffer->EntryCount].RipValue = rip0;
			  stackwalkBuffer->Entries[stackwalkBuffer->EntryCount++].RspValue = rsp0;
              if ( rip0 < MmSystemRangeStart )
                break;
              if ( rsp0 < MmSystemRangeStart )
                break;
              functionTableEntry = import_RtlLookupFunctionEntry(rip0, &moduleBase, 0i64);
              if ( !functionTableEntry )
                break;
              import_RtlVirtualUnwind(0i64, moduleBase, context->Rip, functionTableEntry, context, &v18, &v17, 0i64);
              if ( !context->Rip )
              {
                stackwalkBuffer->Succeded = 1;
                break;
              }
              ++index;
            }
            while ( index < 0x20 );
          }
        }
      }
    }
    FinalizeFreePool((__int64)stackBuffer);
  }
  return status;
}
 
size_t __usercall CopyThreadKernelStack@<rax>(__int64 threadObject@<rcx>, __int64 maxSize@<rdx>, void *outStackBuffer@<r8>, signed int a4@<r14d>)
{
  size_t copiedSize; // rsi
  __int64 threadStateOffset; // r12 MAPDST
  __int64 kernelStackOffset; // r14
  unsigned int threadStackBaseOffset; // eax
  unsigned __int64 threadStackBase; // rdi
  unsigned int threadStackLimitOffset; // eax
  unsigned __int64 threadStackLimit; // rbp
  int isSystemThread; // er11
  const void **pKernelStack; // r12
  __int64 v16; // rdx
  unsigned int threadLockOffset; // eax
  KSPIN_LOCK *threadLock; // rcx
  void (__fastcall *v19)(_QWORD, __int64); // rax
  unsigned __int8 oldIrql; // [rsp+50h] [rbp+8h]
 
  copiedSize = 0i64;
  threadStateOffset = (unsigned int)GetThreadStateOffset(a4);
  kernelStackOffset = (unsigned int)GetKernelStackOffset();
  threadStackBaseOffset = GetThreadStackBaseOffset();
  if ( threadObject && threadStackBaseOffset )
    threadStackBase = *(_QWORD *)(threadStackBaseOffset + threadObject);
  else
    threadStackBase = 0i64;
  threadStackLimitOffset = GetThreadStackLimitOffset();
  if ( !threadObject )
    return 0i64;
  threadStackLimit = threadStackLimitOffset ? *(_QWORD *)(threadStackLimitOffset + threadObject) : 0i64;
  isSystemThread = import_PsIsSystemThread ? (unsigned __int8)import_PsIsSystemThread(threadObject) : 0;
  if ( !isSystemThread
    || !outStackBuffer
    || !(_DWORD)threadStateOffset
    || !(_DWORD)kernelStackOffset
    || !threadStackBase
    || !threadStackLimit
    || KeGetCurrentIrql() > 1u
    || threadObject == __readgsqword(0x188u) )
  {
    return 0i64;
  }
  pKernelStack = (const void **)(threadObject + kernelStackOffset);
  memset(outStackBuffer, 0, 0x1000ui64);
  if ( LockThread(&oldIrql, threadObject, 0x1000) )
  {
    if ( !(unsigned __int8)PsIsThreadTerminating(threadObject)
      && *(_BYTE *)(threadStateOffset + threadObject) == 5
      && (unsigned __int64)*pKernelStack > threadStackLimit
      && (unsigned __int64)*pKernelStack < threadStackBase
      && MmGetPhysicalAddress(*pKernelStack) )
    {
      copiedSize = threadStackBase - (_QWORD)*pKernelStack;
      if ( copiedSize > 0x1000 )
        copiedSize = 0x1000i64;
      memmove(outStackBuffer, *pKernelStack, copiedSize);
    }
    if ( MEMORY[0xFFFFF7800000026C] >= 6u && (MEMORY[0xFFFFF7800000026C] != 6 || MEMORY[0xFFFFF78000000270]) )
    {
      threadLockOffset = GetThreadLockOffset(0x1000);
      threadLock = (KSPIN_LOCK *)((threadObject + threadLockOffset) & -(signed __int64)(threadLockOffset != 0));
      if ( threadLock )
      {
        KeReleaseSpinLockFromDpcLevel(threadLock);
        __writecr8(oldIrql);
      }
    }
    else
    {
      v19 = (void (__fastcall *)(_QWORD, __int64))qword_4DF00;
      if ( qword_4DF00
        || (v19 = (void (__fastcall *)(_QWORD, __int64))FindExport((__int64)&unk_46D00),
            (qword_4DF00 = (__int64)v19) != 0) )
      {
        LOBYTE(v16) = oldIrql;
        v19(0i64, v16);
      }
    }
  }
  return copiedSize;
}