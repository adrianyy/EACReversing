__int64 FindHiddenProcess()
{
  __int64 hiddenProcess; // rbx
  __int64 *processesFromThreads; // r12
  HANDLE *processes; // r14
  unsigned int *list; // r15
  unsigned int processFromThreadCount; // eax
  __int64 processFromThreadCount0; // rsi
  unsigned int processCount; // eax MAPDST
  unsigned int processIndex; // ebp MAPDST
  __int64 *currentProcess; // r13
  __int64 processFromThreadIndex; // rdi
  __int64 *currentProcessFromThread; // rbp
  __int64 pid; // r13
  signed int status; // eax
  __int64 hiddenProcessId; // r11
  HANDLE *v17; // rax
  PVOID *v18; // rdi
  PVOID processObject; // [rsp+50h] [rbp+8h]

  hiddenProcess = 0i64;
  processesFromThreads = (__int64 *)AllocatePool(4096i64);
  if ( processesFromThreads )
  {
    processes = (HANDLE *)AllocatePool(4096i64);
    if ( processes )
    {
      list = CreateUniqueList(1);
      if ( list )
      {
        processFromThreadCount = Get512RunningProcessesFromThreads(processesFromThreads);
        processFromThreadCount0 = processFromThreadCount;
        if ( processFromThreadCount )
        {
          processCount = GetRunningProcesses(processes, 512u, 0i64, 0i64);
          if ( processCount )
          {
            if ( (_DWORD)processFromThreadCount0 != 512 && processCount != 512 )
            {
              processIndex = 0;
              if ( processCount )
              {
                currentProcess = (__int64 *)processes;
                while ( AddListEntry((__int64)list, *currentProcess, 0i64, 0) )
                {
                  ++processIndex;
                  ++currentProcess;
                  if ( processIndex >= processCount )
                    goto LABEL_12;
                }
              }
              else
              {
LABEL_12:
                processFromThreadIndex = 0i64;
                if ( (_DWORD)processFromThreadCount0 )
                {
                  currentProcessFromThread = processesFromThreads;
                  while ( 1 )
                  {
                    pid = import_PsGetProcessId ? import_PsGetProcessId(*currentProcessFromThread) : 0i64;
                    status = import_PsLookupProcessByProcessId ? (unsigned int)import_PsLookupProcessByProcessId(
                                                                                 pid,
                                                                                 &processObject) : 0xC0000002;
                    if ( status < 0 )
                      break;
                    ObfDereferenceObject(processObject);
                    if ( !IsEntryPresentInList((__int64)list, pid) )
                      break;
                    processFromThreadIndex = (unsigned int)(processFromThreadIndex + 1);
                    ++currentProcessFromThread;
                    if ( (unsigned int)processFromThreadIndex >= (unsigned int)processFromThreadCount0 )
                      goto LABEL_38;
                  }
                  hiddenProcess = processesFromThreads[processFromThreadIndex];
                  if ( hiddenProcess )
                  {
                    processCount = GetRunningProcesses(processes, 0x200u, 0i64, 0i64);
                    if ( processCount )
                    {
                      if ( import_PsGetProcessId )
                        hiddenProcessId = import_PsGetProcessId(hiddenProcess);
                      else
                        hiddenProcessId = 0i64;
                      processIndex = 0;
                      if ( processCount )
                      {
                        v17 = processes;
                        while ( *v17 != (HANDLE)hiddenProcessId )
                        {
                          ++processIndex;
                          ++v17;
                          if ( processIndex >= processCount )
                            goto LABEL_35;
                        }
                        hiddenProcess = 0i64;
                      }
LABEL_35:
                      if ( hiddenProcess )
                        IsProcessExiting(hiddenProcess);
                    }
                    else
                    {
                      hiddenProcess = 0i64;
                    }
                  }
                }
              }
            }
          }
        }
LABEL_38:
        FreeList(list);
      }
      else
      {
        processFromThreadCount0 = (unsigned int)processObject;
      }
      FreePool((__int64)processes);
    }
    else
    {
      processFromThreadCount0 = (unsigned int)processObject;
    }
    if ( (_DWORD)processFromThreadCount0 )
    {
      v18 = (PVOID *)processesFromThreads;
      do
      {
        if ( *v18 != (PVOID)hiddenProcess )
          ObfDereferenceObject(*v18);
        ++v18;
        --processFromThreadCount0;
      }
      while ( processFromThreadCount0 );
    }
    FreePool((__int64)processesFromThreads);
  }
  return hiddenProcess;
}

__int64 __fastcall Get512RunningProcessesFromThreads(__int64 *buffer)
{
  unsigned int processCount; // edi
  unsigned __int64 currentTID; // rbx
  __int64 list; // rsi
  signed int v5; // eax
  __int64 process; // r12
  PVOID threadObject; // [rsp+40h] [rbp+8h]

  processCount = 0;
  currentTID = 4i64;
  if ( buffer )
  {
    if ( GetThreadProcess(__readgsqword(0x188u)) )
    {
      list = (__int64)CreateUniqueList(1);
      if ( list )
      {
        do
        {
          if ( processCount >= 512 )
            break;
          if ( import_PsLookupThreadByThreadId )
            v5 = import_PsLookupThreadByThreadId(currentTID, &threadObject);
          else
            v5 = 0xC0000002;
          if ( v5 >= 0 )
          {
            process = GetThreadProcess((__int64)threadObject);
            if ( !IsEntryPresentInList(list, process) )
            {
              import_ObfReferenceObject(process);
              *buffer = process;
              ++processCount;
              ++buffer;
              AddListEntry(list, process, 0i64, 0);
            }
            ObfDereferenceObject(threadObject);
          }
          currentTID += 4i64;
        }
        while ( currentTID < 0x3000 );
        FreeList((PVOID)list);
      }
    }
  }
  return processCount;
}

__int64 __fastcall GetRunningProcesses(HANDLE *outProcesses, unsigned int maxCount, unsigned __int8 (__fastcall *callback)(__int64, __int64), __int64 a4)
{
  unsigned int v4; // edi
  SYSTEM_PROCESS_INFO *processInformation; // rax MAPDST
  SYSTEM_PROCESS_INFO *entry; // rbx
  __int64 pid; // rcx

  v4 = 0;
  if ( !outProcesses || !maxCount )
    return 0i64;
  processInformation = (SYSTEM_PROCESS_INFO *)QuerySystemInformation_0(
                                                5u,
                                                (unsigned __int64)qword_80000,
                                                0x1000000u,
                                                0i64,
                                                a4);
  if ( processInformation )
  {
    entry = processInformation;
    if ( maxCount )
    {
      do
      {
        pid = (__int64)entry->UniqueProcessId;
        if ( pid && (!callback || callback(pid, a4)) )
        {
          ++v4;
          *outProcesses = entry->UniqueProcessId;
          ++outProcesses;
        }
        if ( !entry->NextEntryOffset )
          break;
        entry = (SYSTEM_PROCESS_INFO *)((char *)entry + entry->NextEntryOffset);
      }
      while ( v4 < maxCount );
    }
    FreePool((__int64)processInformation);
  }
  return v4;
}