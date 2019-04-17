Checked memory types:
[non-shared only ]  Executable.
[non-shared only ]  Executable and read-only.
[including shared]  Executable and read/write.
[non-shared only ]  Executable and copy-on-write.
[non-shared only ]  Non-cacheable and executable.
[non-shared only ]  Non-cacheable, executable, and read-only.
[including shared]  Non-cacheable, executable, and read/write.
[non-shared only ]  Non-cacheable, executable, and copy-on-write.
[non-shared only ]  Guard page and executable.
[non-shared only ]  Guard page, executable, and read-only.
[including shared]  Guard page, executable, and read/write.
[non-shared only ]  Guard page, executable, and copy-on-write.
[non-shared only ]  Non-cacheable, guard page, and executable.
[non-shared only ]  Non-cacheable, guard page, executable, and read-only.
[including shared]  Non-cacheable, guard page, executable, and read/write.
[non-shared only ]  Non-cacheable, guard page, executable, and copy-on-write.

char __fastcall ScanProcessWorkingSet(__int64 process, char previousMode, WORKINGSET_DETECTION_BUFFER **outDetectionBuffer)
{
  char v3; // bp
  MEMORY_WORKING_SET_INFORMATION *wsi; // rax MAPDST
  WORKINGSET_DETECTION_BUFFER *detectionBuffer; // rax MAPDST
  ULONG_PTR v12; // r12
  int *info; // rbx
  unsigned __int64 protection; // rax

  v3 = 0;
  if ( !outDetectionBuffer )
    return 0;
  *outDetectionBuffer = 0i64;
  wsi = (MEMORY_WORKING_SET_INFORMATION *)AllocatePool(0x100000i64);
  if ( !wsi )
    return v3;
  if ( !QueryVirtualMemory0(0i64, process, 1u, (__int64)wsi, previousMode, 0x100000i64) )// MemoryWorkingSetInformation
    goto LABEL_33;
  detectionBuffer = (WORKINGSET_DETECTION_BUFFER *)AllocatePool(2048i64);
  if ( detectionBuffer )
  {
    memset(detectionBuffer, 0, 2048ui64);
    detectionBuffer->usedBytes = 16;
    detectionBuffer->maxSize = 2048;
  }
  *outDetectionBuffer = detectionBuffer;
  if ( !detectionBuffer )
    goto LABEL_33;
  v12 = 0i64;
  if ( !wsi->NumberOfEntries )
    goto LABEL_32;
  info = (int *)wsi->WorkingSetInfo;
  do
  {
    protection = *(_QWORD *)info & 0x1Fi64;
    if ( protection > 19 )
    {
      if ( protection == 22 )
        goto check_entry;                       // Guard page, executable, and read/write.
      if ( protection != 23 )
      {
        if ( protection <= 25 )
          goto skip_entry;
        if ( protection > 27 )
        {
          if ( protection == 30 )
            goto check_entry;                   // Non-cacheable, guard page, executable, and read/write.
          if ( protection != 31 )
            goto skip_entry;
        }
      }
    }
    else if ( protection < 18 )
    {
      if ( protection < 2 )
        goto skip_entry;
      if ( protection > 3 )
      {
        if ( protection == 6 )
          goto check_entry;                     // Executable and read/write.
        if ( protection != 7 )
        {
          if ( protection <= 9 )
            goto skip_entry;
          if ( protection > 0xB )
          {
            if ( protection == 14 )
              goto check_entry;                 // Non-cacheable, executable, and read/write.
            if ( protection != 15 )
              goto skip_entry;
          }
        }
      }
    }
    if ( previousMode && !_bittest64((const signed __int64 *)info, 8u) )// bit 8 = shared
    {
check_entry:
      v3 = 1;
      CheckWorkingSetEntry(*outDetectionBuffer, info, previousMode);
    }
skip_entry:
    ++v12;
    info += 2;
  }
  while ( v12 < wsi->NumberOfEntries );
  if ( !v3 )
  {
LABEL_32:
    FreePool((__int64)*outDetectionBuffer);
    *outDetectionBuffer = 0i64;
  }
LABEL_33:
  FreePool((__int64)wsi);
  return v3;
}

char __usercall CheckWorkingSetEntry@<al>(WORKINGSET_DETECTION_BUFFER *detectionBuffer@<rdx>, int *pWsiInfo@<r8>, signed int previousMode@<r14d>)
{
  unsigned __int64 v3; // rax
  void *address; // rdi
  unsigned __int64 v7; // r9
  WORKINGSET_DETECTION_ENTRY *prevEntry; // r8
  int wsiInfo; // eax
  __int64 v10; // rdx
  UNICODE_STRING mappedFilename; // [rsp+30h] [rbp-88h]
  UNICODE_STRING string; // [rsp+40h] [rbp-78h]
  WORKINGSET_DETECTION_ENTRY detectionEntry; // [rsp+50h] [rbp-68h]
  MEMORY_BASIC_INFORMATION mbi; // [rsp+78h] [rbp-40h]

  detectionEntry.address = 0i64;
  LOBYTE(v3) = 0;
  address = (void *)(*(_QWORD *)pWsiInfo & 0xFFFFFFFFFFFFF000ui64);// extract page address
  *(_QWORD *)&detectionEntry.offsetFromAllocationBase = 0i64;
  *(_QWORD *)&detectionEntry.isShared = 0i64;
  *(_QWORD *)&detectionEntry.mappedFilename[7] = 0i64;
  detectionEntry.mappedFilename[15] = 0;
  if ( !detectionBuffer )
    return v3;
  LODWORD(v3) = detectionBuffer->maxSize;
  if ( (unsigned int)v3 < 0x10 )
    return v3;
  LODWORD(v3) = v3 - detectionBuffer->usedBytes;
  ++detectionBuffer->unk123;
  if ( (unsigned int)v3 < 33 )
    return v3;
  mbi.BaseAddress = address;
  LOBYTE(v3) = (signed int)QueryVirtualMemory((__int64)address, -1i64, 0, (__int64)&mbi, previousMode, 48i64, 0i64) >= 0;
  if ( !(_BYTE)v3 )
  {
    detectionEntry.address = (__int64)address;
LABEL_14:
    wsiInfo = *pWsiInfo;
    v10 = (unsigned int)detectionBuffer->count;
    detectionEntry.isShared = (*pWsiInfo & 0x100i64) != 0;
    detectionEntry.protection = wsiInfo & 0x1F;
    detectionBuffer->count = v10 + 1;
    LOBYTE(v3) = (unsigned __int64)memmove(&detectionBuffer->entries[v10], &detectionEntry, 33ui64);
    detectionBuffer->usedBytes += 33;
    return v3;
  }
  v7 = 0i64;
  if ( !detectionBuffer->count )
  {
LABEL_9:
    detectionEntry.address = (__int64)mbi.AllocationBase;
    detectionEntry.offsetFromAllocationBase = (_DWORD)address - LODWORD(mbi.AllocationBase);
    if ( GetMappedFilename(-1i64, (__int64)mbi.AllocationBase, (__int64)&mappedFilename, previousMode) )
    {
      if ( sub_289F0(&mappedFilename.Length, (__int64)&string) )
        CopyUnicodeStringToAnsiBuffer((__int64)detectionEntry.mappedFilename, 16i64, &string);
      FreeUnicodeString(&mappedFilename);
    }
    goto LABEL_14;
  }
  prevEntry = detectionBuffer->entries;
  while ( (PVOID)prevEntry->address != mbi.AllocationBase )
  {
    v3 = (unsigned int)detectionBuffer->count;
    ++v7;
    ++prevEntry;
    if ( v7 >= v3 )
      goto LABEL_9;
  }
  return v3;
}