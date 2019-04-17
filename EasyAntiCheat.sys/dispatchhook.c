char __usercall CheckDriverDispatch@<al>(DRIVER_OBJECT *driverObject@<rcx>, _DWORD *detectionData@<r8>, _DWORD *outStatus@<r9>, signed int a4@<r14d>)
{
  char v4; // bp
  PDRIVER_DISPATCH addr; // rdi
  SYSTEM_MODULE_INFORMATION *moduleInformation; // rax MAPDST
  ULONG moduleIndex; // ecx
  PVOID *cur; // r12
  _BYTE *fileName; // rdx
  unsigned __int64 nameLength; // rax
  size_t nameLength2; // rdi

  v4 = 0;
  if ( !driverObject )
  {
    if ( outStatus )
      *outStatus = 2;
    return 0;
  }
  addr = driverObject->MajorFunction[14];
  if ( !addr )
  {
    if ( outStatus )
      *outStatus = 4;
    return 0;
  }
  moduleInformation = (SYSTEM_MODULE_INFORMATION *)QuerySystemModuleInformation(a4);
  if ( !moduleInformation )
  {
    if ( outStatus )
      *outStatus = 5;
    return 0;
  }
  moduleIndex = 0;
  if ( moduleInformation->Count )
  {
    cur = &moduleInformation->Module[0].ImageBase;
    while ( (unsigned __int64)*cur < MmSystemRangeStart
         || (char *)addr < *cur
         || (char *)addr > (char *)*cur + *((unsigned int *)cur + 2) )
    {
      ++moduleIndex;
      cur += 37;
      if ( moduleIndex >= moduleInformation->Count )
        goto LABEL_29;
    }
    v4 = 1;
    if ( detectionData )
    {
      fileName = cur + 3;
      nameLength = 0i64;
      *detectionData = (_DWORD)addr - *(_DWORD *)cur;
      if ( cur == (PVOID *)0xFFFFFFFFFFFFFFE8i64 )
        goto LABEL_35;
      do
      {
        if ( !fileName[nameLength] )
          break;
        ++nameLength;
      }
      while ( nameLength < 256 );
      nameLength2 = 255i64;
      if ( nameLength < 255 )
      {
LABEL_35:
        nameLength2 = 0i64;
        if ( cur != (PVOID *)0xFFFFFFFFFFFFFFE8i64 )
        {
          do
          {
            if ( !fileName[nameLength2] )
              break;
            ++nameLength2;
          }
          while ( nameLength2 < 256 );
        }
      }
      memmove(detectionData + 2, fileName, nameLength2);
      *((_BYTE *)detectionData + nameLength2 + 8) = 0;
      detectionData[1] = *((_DWORD *)cur + 2);
    }
    if ( outStatus )
      *outStatus = 7;
  }
LABEL_29:
  FreePool((__int64)moduleInformation);
  if ( !v4 && outStatus )
    *outStatus = 6;
  return v4;
}