SYSTEM_BIGPOOL_INFORMATION *__usercall CheckForTDL@<rax>(signed int a1@<r14d>)
{
  SYSTEM_BIGPOOL_INFORMATION *bigpoolInfo; // rax MAPDST
  ULONG index; // esi
  __int64 MmGetPhysicalAddress; // rdx
  SYSTEM_BIGPOOL_ENTRY1 *entry; // rbx
  char detectedTDL; // bp
  __int64 physicalAddress; // rax
  __int64 v8; // rax MAPDST
  unsigned __int64 v10; // rcx
  ULONG_PTR size; // rbx
  unsigned __int64 v12; // rcx
  __int64 alignedSize; // rbx
  __int64 v14; // rax
  __int64 v15; // rax MAPDST

  bigpoolInfo = (SYSTEM_BIGPOOL_INFORMATION *)QuerySystemInformation_0(0x42u, 0x100000u, 0x2000000u, 0i64, a1);
  if ( bigpoolInfo )
  {
    index = 0;
    if ( bigpoolInfo->Count )
    {
      MmGetPhysicalAddress = (__int64)import_MmGetPhysicalAddress;
      entry = (SYSTEM_BIGPOOL_ENTRY1 *)bigpoolInfo->AllocatedInfo;
      while ( 1 )
      {
        detectedTDL = 0;
        if ( *(_QWORD *)&entry->0 & 1 && entry->SizeInBytes >= 0x2000 )// if nonpaged
        {
          if ( entry->TagUlong == 'SldT' )
            break;
          if ( MmGetPhysicalAddress )
          {
            physicalAddress = ((__int64 (__fastcall *)(unsigned __int64))MmGetPhysicalAddress)((_QWORD)entry->VirtualAddress & 0xFFFFFFFFFFFFFFFEui64);
            MmGetPhysicalAddress = (__int64)import_MmGetPhysicalAddress;
          }
          else
          {
            physicalAddress = qword_4DBE8;
          }
          if ( physicalAddress )
          {
            v8 = MapPhysicalMemory(physicalAddress, 4096i64);
            if ( v8 )
            {
              if ( *(_QWORD *)(v8 + 0x184) == 0xB024BC8B48i64 )
              {
                detectedTDL = 0;
                if ( (unsigned int)HashCRC32((char *)(v8 + 0x184), 151u, 0) == 0xC8931AEB )
                  detectedTDL = 1;
              }
              if ( import_MmUnmapVideoDisplay )
                import_MmUnmapVideoDisplay(v8, 4096i64);
            }
            MmGetPhysicalAddress = (__int64)import_MmGetPhysicalAddress;
          }
        }
        else
        {
          detectedTDL = 0;
        }
        if ( detectedTDL )
          break;
        ++index;
        ++entry;
        if ( index >= bigpoolInfo->Count )
          goto LABEL_31;
      }
      v10 = (unsigned __int64)entry->VirtualAddress;
      size = entry->SizeInBytes;
      v12 = v10 & 0xFFFFFFFFFFFFFFFEui64;
      if ( size > (unsigned __int64)qword_80000 )
        size = (ULONG_PTR)qword_80000;
      alignedSize = size & 0xFFFFFFFFFFFFF000ui64;
      if ( MmGetPhysicalAddress )
        v14 = ((__int64 (__fastcall *)(unsigned __int64))MmGetPhysicalAddress)(v12);
      else
        v14 = qword_4DBE8;
      if ( v14 )
      {
        v15 = MapPhysicalMemory(v14, alignedSize);
        if ( v15 )
        {
          SendPacketToServer(133i64, v15, (unsigned int)alignedSize);
          if ( import_MmUnmapVideoDisplay )
            import_MmUnmapVideoDisplay(v15, alignedSize);
        }
      }
    }
LABEL_31:
    bigpoolInfo = (SYSTEM_BIGPOOL_INFORMATION *)FreePool((__int64)bigpoolInfo);
  }
  return bigpoolInfo;
}