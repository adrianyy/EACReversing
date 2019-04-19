SYSTEM_MODULE_INFORMATION *__usercall LogAllLoadedDrivers@<rax>(signed int a1@<r14d>)
{
  signed __int64 v1; // r13
  SYSTEM_MODULE_INFORMATION *result; // rax
  SYSTEM_MODULE_INFORMATION *systemModuleInformation; // rdi
  _DWORD *logBuffer; // rsi
  _IMAGE_DOS_HEADER *moduleBuffer; // r14
  ULONG moduleIndex; // er15
  PVOID *currentModule; // r12
  __int64 moduleBase; // rcx
  signed __int64 moduleName; // rbp
  unsigned __int64 nameLength; // rbx
  __int64 offsetToFilename; // rax
  signed __int64 v12; // r13
  unsigned __int64 v13; // rdx
  _BYTE *v14; // rcx
  unsigned __int64 v15; // r8
  signed __int64 v16; // rbp
  char v17; // al
  __int64 checksumAndTimestamp; // [rsp+20h] [rbp-38h]
  ULONG entrypointRva; // [rsp+28h] [rbp-30h]
  __int16 nameLength0; // [rsp+2Ch] [rbp-2Ch]
  _IMAGE_NT_HEADERS64 *ntHeaders; // [rsp+60h] [rbp+8h]

  v1 = 4i64;
  result = (SYSTEM_MODULE_INFORMATION *)QuerySystemModuleInformation(a1);
  systemModuleInformation = result;
  if ( result )
  {
    if ( result->Count )
    {
      logBuffer = (_DWORD *)AllocatePool(0x2000i64);
      if ( logBuffer )
      {
        *logBuffer = 0;
        moduleBuffer = (_IMAGE_DOS_HEADER *)AllocatePool(4096i64);
        if ( moduleBuffer )
        {
          moduleIndex = 0;
          if ( systemModuleInformation->Count )
          {
            currentModule = &systemModuleInformation->Module[0].ImageBase;
            do
            {
              moduleBase = (__int64)*currentModule;
              if ( (unsigned __int64)*currentModule >= MmSystemRangeStart && moduleBase != EACBase )
              {
                if ( (unsigned __int64)(v1 + 270) > 0x2000 )
                  break;
                checksumAndTimestamp = 0i64;
                entrypointRva = 0;
                if ( CopyVirtualMemory(moduleBase, 4096i64, (__int64)moduleBuffer) == 4096
                  && ValidatePeHeader(moduleBuffer, 0x1000ui64, 0i64, &ntHeaders) )
                {
                  HIDWORD(checksumAndTimestamp) = ntHeaders->OptionalHeader.CheckSum;
                  LODWORD(checksumAndTimestamp) = ntHeaders->FileHeader.TimeDateStamp;
                  entrypointRva = ntHeaders->OptionalHeader.AddressOfEntryPoint;
                }
                moduleName = (signed __int64)(currentModule + 3);
                nameLength = 0i64;
                if ( currentModule != (PVOID *)0xFFFFFFFFFFFFFFE8i64 )
                {
                  do
                  {
                    if ( !*(_BYTE *)(nameLength + moduleName) )
                      break;
                    ++nameLength;
                  }
                  while ( nameLength < 0xFF );
                }
                nameLength0 = nameLength;
                if ( *((_WORD *)currentModule + 11) == 29
                  && strstrIgnoreCase((_BYTE *)currentModule + 0x18, (_BYTE *)(StringTable + 1187), 29ui64) )// \SystemRoot\system32\drivers\
                {
                  offsetToFilename = *((unsigned __int16 *)currentModule + 11);
                  moduleName += offsetToFilename;
                  LOWORD(nameLength) = nameLength - offsetToFilename;
                  nameLength0 = nameLength;
                }
                *(_QWORD *)((char *)logBuffer + v1) = checksumAndTimestamp;
                v12 = v1 + 14;
                v13 = 0x2000 - v12;
                *(_DWORD *)((char *)logBuffer + v12 - 6) = entrypointRva;
                *(_WORD *)((char *)logBuffer + v12 - 2) = nameLength0;
                v14 = (char *)logBuffer + v12;
                if ( v12 != 0x2000 && v13 <= 0x7FFFFFFF )
                {
                  if ( (unsigned __int16)nameLength <= 0x7FFFFFFEui64 )
                  {
                    v15 = (unsigned __int16)nameLength - v13;
                    v16 = moduleName - (_QWORD)v14;
                    do
                    {
                      if ( !(v15 + v13) )
                        break;
                      v17 = v14[v16];
                      if ( !v17 )
                        break;
                      *v14++ = v17;
                      --v13;
                    }
                    while ( v13 );
                    if ( !v13 )
                      --v14;
                  }
                  *v14 = 0;
                }
                v1 = (unsigned __int16)nameLength + v12;
                ++*logBuffer;
              }
              ++moduleIndex;
              currentModule += 37;
            }
            while ( moduleIndex < systemModuleInformation->Count );
          }
          FreePool((__int64)moduleBuffer);
        }
        SendPacketToServer(294i64, (__int64)logBuffer, (unsigned int)v1);
        FreePool((__int64)logBuffer);
      }
    }
    result = (SYSTEM_MODULE_INFORMATION *)FreePool((__int64)systemModuleInformation);
  }
  return result;
}

__int64 __usercall IterateDirectoriesRecursive@<rax>(UNICODE_STRING *argPath@<rdx>, __int64 *outBuffer@<rcx>, unsigned int a3@<r8d>, unsigned int a4@<r9d>, signed int a5@<r14d>, char a6)
{
  unsigned int index; // ebp
  __int64 directoryObject; // rbx
  signed int status; // eax
  OBJECT_DIRECTORY_INFORMATION *objectInfo; // rsi
  bool isDirectory; // al MAPDST
  bool isRoot; // bl
  unsigned __int16 fullLength; // r8
  DRIVER_OBJECT *driver; // rax MAPDST
  __int64 v16; // rax
  __int64 a6a; // [rsp+20h] [rbp-98h]
  bool isDriver; // [rsp+40h] [rbp-78h]
  int v21; // [rsp+44h] [rbp-74h]
  UNICODE_STRING path; // [rsp+48h] [rbp-70h]
  __int64 directoryHandle; // [rsp+58h] [rbp-60h]
  UNICODE_STRING argPathCopy; // [rsp+60h] [rbp-58h]
  OBJECT_ATTRIBUTES objectAttributes; // [rsp+70h] [rbp-48h]

  index = 0;
  v21 = 0;
  if ( !outBuffer )
    return 0i64;
  if ( !argPath )
    return 0i64;
  if ( !argPath->Buffer )
    return 0i64;
  if ( !argPath->Length )
    return 0i64;
  if ( !argPath->MaximumLength )
    return 0i64;
  if ( !a3 )
    return 0i64;
  if ( !a4 )
    return 0i64;
  directoryObject = GetDirectoryObjectType(a5);
  if ( !directoryObject || !AllocateCopyUnicodeString((__int64)&argPathCopy, argPath) )
    return 0i64;
  objectAttributes.Length = 48;
  objectAttributes.RootDirectory = 0i64;
  objectAttributes.ObjectName = &argPathCopy;
  objectAttributes.Attributes = 512;
  objectAttributes.SecurityDescriptor = 0i64;
  objectAttributes.SecurityQualityOfService = 0i64;
  if ( import_ObOpenObjectByName )
    status = import_ObOpenObjectByName(&objectAttributes, directoryObject, 0i64, 0i64, 1, 0i64, &directoryHandle);
  else
    status = 0xC0000002;
  if ( status >= 0 )
  {
    objectInfo = (OBJECT_DIRECTORY_INFORMATION *)AllocatePool(1024i64);
    if ( objectInfo )
    {
      if ( a3 > 0 )
      {
        do
        {
          LOBYTE(a6a) = 0;
          if ( (signed int)GetNextDirectoryObject((__int64)objectInfo, directoryHandle, 0x400u, a5, a6a, (__int64)&v21) < 0 )
            break;
          isDriver = CompareUnicodeStrings((__int64)&objectInfo->TypeName, (_WORD *)(StringTable + 1247)) == 0;// Driver
          isDirectory = CompareUnicodeStrings((__int64)&objectInfo->TypeName, (_WORD *)(StringTable + 1261)) == 0;// Directory
          if ( (isDriver || isDirectory)
            && argPath->Buffer
            && argPath->Length
            && argPath->MaximumLength
            && objectInfo->Name.Buffer
            && objectInfo->Name.Length
            && objectInfo->Name.MaximumLength )
          {
            isRoot = CompareUnicodeStrings((__int64)argPath, (_WORD *)(StringTable + 1217)) == 0;// \
            fullLength = objectInfo->Name.Length + argPath->Length;
            if ( !isRoot )
              fullLength += 2;
            if ( AllocatePoolForUnicodeString((__int64)&path, argPath, fullLength) )
            {
              if ( !isRoot && StringTable != 4294966079 )
                CopyUnicodeString(&path, StringTable + 1217);// \
              if ( (signed int)AppendUnicodeString(&path, objectInfo) >= 0 )
              {
                if ( isDirectory && a4 > 0 )
                {
                  index += IterateDirectoriesRecursive(&path, &outBuffer[index], a3 - index, a4 - 1, a5, a6);
                }
                else if ( isDriver )
                {
                  driver = (DRIVER_OBJECT *)OpenDriver(&path.Length);
                  if ( driver )
                  {
                    if ( !a6 || driver->DriverSection && driver->DriverStart && driver->DriverSize )
                    {
                      v16 = index++;
                      outBuffer[v16] = (__int64)driver;
                    }
                    else
                    {
                      ObfDereferenceObject(driver);
                    }
                  }
                }
              }
              FreeUnicodeString(&path);
            }
          }
        }
        while ( index < a3 );
      }
      FreePool((__int64)objectInfo);
    }
    CloseHandle(directoryHandle, a5);
  }
  FreeUnicodeString(&argPathCopy);
  return index;
}

char __usercall CheckDriverObjects@<al>(_QWORD *a1@<rcx>, _DWORD *a2@<rdx>, __int64 detectionBuffer@<r8>, signed int a4@<r14d>)
{
  char v4; // bl
  __int64 directoryObject; // rdi
  SYSTEM_MODULE_INFORMATION *moduleInfo; // rsi
  signed int v10; // ST20_4
  signed int v11; // eax
  OBJECT_DIRECTORY_INFORMATION *objectInfo; // rdi
  __int64 v14; // [rsp+20h] [rbp-88h]
  UNICODE_STRING v15; // [rsp+40h] [rbp-68h]
  OBJECT_ATTRIBUTES v2; // [rsp+50h] [rbp-58h]
  int v17; // [rsp+B0h] [rbp+8h]
  __int64 directoryHandle; // [rsp+C8h] [rbp+20h]

  v4 = 0;
  v17 = 0;
  if ( !a1 || !a2 || !detectionBuffer )
    return 0;
  directoryObject = GetDirectoryObjectType(a4);
  if ( directoryObject )
  {
    moduleInfo = (SYSTEM_MODULE_INFORMATION *)QuerySystemModuleInformation(a4);
    if ( moduleInfo )
    {
      InitializeUnicodeStringWithCStr(&v15, (_WORD *)(StringTable + 1221));// \Driver\
      v2.Length = 48;
      v2.ObjectName = &v15;
      v2.RootDirectory = 0i64;
      v2.Attributes = 512;
      v2.SecurityDescriptor = 0i64;
      v2.SecurityQualityOfService = 0i64;
      if ( import_ObOpenObjectByName )
      {
        v10 = 1;
        v11 = import_ObOpenObjectByName(&v2, directoryObject, 0i64, 0i64, v10, 0i64, &directoryHandle);
      }
      else
      {
        v11 = 0xC0000002;
      }
      if ( v11 >= 0 )
      {
        objectInfo = (OBJECT_DIRECTORY_INFORMATION *)AllocatePool(0x400i64);
        if ( objectInfo )
        {
          while ( 1 )
          {
            LOBYTE(v14) = 0;
            if ( (signed int)GetNextDirectoryObject(
                               (__int64)objectInfo,
                               directoryHandle,
                               0x400u,
                               a4,
                               v14,
                               (__int64)&v17) < 0 )
              break;
            if ( IsDriverNotBackedByModule(objectInfo, moduleInfo, a1, a2) )
            {
              AllocateCopyUnicodeString(detectionBuffer, &objectInfo->Name);
              v4 = 1;
              break;
            }
          }
          FreePool((__int64)objectInfo);
        }
        CloseHandle(directoryHandle, a4);
      }
      FreePool((__int64)moduleInfo);
    }
  }
  return v4;
}

char __fastcall IsDriverNotBackedByModule(OBJECT_DIRECTORY_INFORMATION *objectInfo, SYSTEM_MODULE_INFORMATION *moduleInfo, _QWORD *a3, _DWORD *a4)
{
  char v4; // bl
  unsigned __int64 v6; // rsi
  int v11; // eax
  signed int v12; // eax
  unsigned __int64 driverStart; // rcx
  __int64 v15; // rcx
  int v16; // er11
  DRIVER_OBJECT *driverObject; // [rsp+40h] [rbp-38h] MAPDST
  UNICODE_STRING driverName; // [rsp+48h] [rbp-30h]

  v4 = 0;
  v6 = (unsigned __int64)EACBase >> 32;
  if ( !import_IoDriverObjectType )
  {
    import_IoDriverObjectType = (__int64)FindExport(&unk_46B38);
    if ( !import_IoDriverObjectType )
      return 0;
  }
  if ( objectInfo )
  {
    if ( moduleInfo )
    {
      if ( a3 )
      {
        if ( a4 )
        {
          if ( (_DWORD)v6 )
          {
            driverName.Buffer = (PWSTR)AllocatePool(512i64);
            if ( driverName.Buffer )
            {
              driverName.Length = 0;
              driverName.MaximumLength = 512;
              if ( StringTable == 0xFFFFFFFFFFFFEE92i64 )
                v11 = 0;
              else
                v11 = CopyUnicodeString(&driverName, StringTable + 0x116E);// \Driver\
              if ( v11 >= 0 && (signed int)AppendUnicodeString(&driverName, objectInfo) >= 0 )
              {
                v12 = import_ObReferenceObjectByName ? (unsigned int)import_ObReferenceObjectByName(
                                                                       &driverName,
                                                                       576i64,
                                                                       0i64,
                                                                       0i64,
                                                                       *(_QWORD *)import_IoDriverObjectType,
                                                                       0,
                                                                       0i64,
                                                                       &driverObject) : 0xC0000002;
                if ( v12 >= 0 )
                {
                  driverStart = (unsigned __int64)driverObject->DriverStart;
                  if ( driverStart
                    && driverObject->DriverSize
                    && driverObject->DriverSection
                    && driverStart >> 32 == v6
                    && !FindModuleForAddress((unsigned __int64)driverObject->DriverStart, moduleInfo) )
                  {
                    *a3 = v15;
                    *a4 = v16;
                    v4 = 1;
                  }
                  ObfDereferenceObject(driverObject);
                }
              }
              FreePool((__int64)driverName.Buffer);
            }
          }
        }
      }
    }
  }
  return v4;
}

char __fastcall CheckUnloadedDrivers(unsigned __int16 *a1)
{
  UNK_BUFFER2 *v1; // rsi
  char v2; // r12
  __int64 SystemTime; // rdi
  __int64 TickCount; // rbx
  signed __int64 systemTimeFromTickCount; // rbx
  __int64 (__fastcall *MmGetPhysicalAddress)(__int64); // rax
  __int64 PhysMmUnloadedDrivers; // rax
  __int64 unloadedDrivers; // rax MAPDST
  unsigned __int64 index; // r14
  signed __int64 addr; // rax
  signed __int64 decIndex; // r15
  WCHAR *v13; // r13
  USHORT nameLength; // cx
  PWSTR nameBuffer; // rdx
  signed __int64 timeSinceUnload; // rbp
  __int64 bufferPhys; // rax
  LONG v18; // eax
  signed __int64 v19; // r9
  const wchar_t *v20; // r8
  unsigned __int16 v21; // ax
  unsigned __int64 v22; // rbp
  signed __int64 sizeLeft; // r10
  unsigned __int64 v24; // rdx
  __int16 *curCh; // r8
  signed int v26; // er9
  __int16 v27; // cx
  signed __int64 v28; // r11
  __int16 v29; // cx
  __int64 v30; // r15
  _MM_UNLOADED_DRIVER unloadedDriver; // [rsp+30h] [rbp-188h]
  __int64 v33; // [rsp+60h] [rbp-158h]
  UNICODE_STRING name; // [rsp+70h] [rbp-148h]
  char printfBuffer[256]; // [rsp+80h] [rbp-138h]
  __int64 MmUnloadedDrivers; // [rsp+1C8h] [rbp+10h]
  __int64 nullbyte; // [rsp+1D0h] [rbp+18h]
  __int64 SystemTime2; // [rsp+1D8h] [rbp+20h]

  v1 = (UNK_BUFFER2 *)a1;
  nullbyte = 0i64;
  v2 = 0;
  if ( !FindMmUnloadedDrivers(&MmUnloadedDrivers) )
    return 0;
  SystemTime = MEMORY[0xFFFFF78000000014];
  TickCount = MEMORY[0xFFFFF78000000320];
  SystemTime2 = MEMORY[0xFFFFF78000000014];
  systemTimeFromTickCount = KeQueryTimeIncrement() * TickCount;
  if ( !sub_30C04((__int64)v1, 1024u) )
    return v2;
  MmGetPhysicalAddress = import_MmGetPhysicalAddress;
  v1->bytesUsed = 0;
  v1->size = 1024;
  if ( MmGetPhysicalAddress )
    PhysMmUnloadedDrivers = MmGetPhysicalAddress(MmUnloadedDrivers);
  else
    PhysMmUnloadedDrivers = qword_4DBE8;
  if ( !PhysMmUnloadedDrivers )
    goto LABEL_68;
  unloadedDrivers = MapPhysicalMemory(PhysMmUnloadedDrivers, 2000i64);
  if ( !unloadedDrivers )
    goto LABEL_68;
  index = 0i64;
  addr = unloadedDrivers + 2000;
  decIndex = 50i64;
  while ( 1 )
  {
    --decIndex;
    v13 = 0i64;
    v33 = addr - 40;
    memmove(&unloadedDriver, (const void *)(addr - 40), 40ui64);
    nameLength = unloadedDriver.Name.Length;
    nameBuffer = unloadedDriver.Name.Buffer;
    if ( !unloadedDriver.Name.Length
      && !unloadedDriver.Name.MaximumLength
      && !unloadedDriver.Name.Buffer
      && !unloadedDriver.ModuleStart
      && !unloadedDriver.ModuleEnd
      && !unloadedDriver.UnloadTime )
    {
      if ( index > 0 && !byte_4DA66 )
      {
        SendPacketToServer(351i64, 0i64, 0i64);
        byte_4DA66 = 1;
      }
      goto next_entry;
    }
    ++index;
    timeSinceUnload = SystemTime - unloadedDriver.UnloadTime;
    if ( (signed __int64)(SystemTime - unloadedDriver.UnloadTime) > systemTimeFromTickCount )
      break;
    if ( timeSinceUnload <= 36000000000i64 )
      goto check_entry;
next_entry:
    addr = v33;
    if ( !decIndex )
      goto LABEL_63;
  }
  if ( byte_4DA67 )
  {
    SendPacketToServer(350i64, 0i64, 0i64);
    nameBuffer = unloadedDriver.Name.Buffer;
    nameLength = unloadedDriver.Name.Length;
    byte_4DA67 = 1;
  }
check_entry:
  if ( nameBuffer && nameLength && unloadedDriver.Name.MaximumLength )
  {
    if ( import_MmGetPhysicalAddress )
    {
      bufferPhys = import_MmGetPhysicalAddress(nameBuffer);
      nameLength = unloadedDriver.Name.Length;
    }
    else
    {
      bufferPhys = qword_4DBE8;
    }
    if ( bufferPhys && (v13 = (WCHAR *)MapPhysicalMemory(bufferPhys, nameLength)) != 0i64 )
    {
      unloadedDriver.Name.Buffer = v13;
      MmUnloadedDrivers = unloadedDriver.Name.Length;
    }
    else
    {
      unloadedDriver.Name.Buffer = 0i64;
      unloadedDriver.Name.Length = 0;
      unloadedDriver.Name.MaximumLength = 0;
    }
  }
  v18 = CompareUnicodeStrings((__int64)&unloadedDriver, (_WORD *)(StringTable + 7242));// easyanticheat.sys
  v19 = unloadedDriver.ModuleEnd - unloadedDriver.ModuleStart;
  if ( v18 != 0 || v19 != *(_DWORD *)(qword_4E080 + 32) )
  {
    if ( unloadedDriver.Name.Buffer && unloadedDriver.Name.Length > 0xD8u )
    {
      unloadedDriver.Name.Length = 216;
      unloadedDriver.Name.Buffer[108] = 0;
    }
    v20 = (const wchar_t *)(StringTable + 7278);// %wZ 0x%X %i
    _mm_storeu_si128((__m128i *)&name, _mm_loadu_si128((const __m128i *)&unloadedDriver));
    if ( (signed int)VsnwprintfWrapper(
                       (wchar_t *)printfBuffer,
                       0x100ui64,
                       v20,
                       &name,
                       v19,
                       ((unsigned __int64)(timeSinceUnload
                                         + ((unsigned __int128)(timeSinceUnload * (signed __int128)0xD6BF94D5E57A42BDi64) >> 64)) >> 63)
                     + ((signed __int64)(timeSinceUnload
                                       + ((unsigned __int128)(timeSinceUnload * (signed __int128)0xD6BF94D5E57A42BDi64) >> 64)) >> 23)) >= 0
      && !(v1->bytesUsed & 1) )
    {
      v21 = v1->size;
      if ( !(v21 & 1) && v1->bytesUsed <= v21 && v21 <= 0xFFFEu && (v1->pool || !v1->bytesUsed && !v21) )
      {
        v22 = (unsigned __int64)v1->bytesUsed >> 1;
        sizeLeft = 0x7FFFi64;
        v24 = ((unsigned __int64)v21 >> 1) - v22;
        curCh = (__int16 *)printfBuffer;
        v26 = 0;
        v27 = 0;
        if ( (unsigned __int64)v21 >> 1 == v22 )
          goto LABEL_72;
        v28 = 2 * v22 - (_QWORD)printfBuffer + v1->pool;
        do
        {
          if ( !sizeLeft )
            break;
          if ( *curCh == (_WORD)nullbyte )
            break;
          *(__int16 *)((char *)curCh + v28) = *curCh;
          --v24;
          ++curCh;
          --sizeLeft;
          ++v27;
        }
        while ( v24 );
        SystemTime = SystemTime2;
        if ( !v24 )
        {
          if ( sizeLeft )
          {
LABEL_72:
            if ( *curCh )
              v26 = 0x80000005;
          }
        }
        v29 = 2 * (v22 + v27);
        if ( v26 >= 0 )
          v2 = 1;
        v1->bytesUsed = v29;
      }
    }
  }
  if ( v13 && import_MmUnmapVideoDisplay )
    import_MmUnmapVideoDisplay(v13, MmUnloadedDrivers);
  if ( v1->bytesUsed != v1->size )
    goto next_entry;
LABEL_63:
  v30 = unloadedDrivers;
  if ( !index )
    SendPacketToServer(349i64, 0i64, 0i64);
  if ( import_MmUnmapVideoDisplay )
    import_MmUnmapVideoDisplay(v30, 2000i64);
  if ( !v2 )
LABEL_68:
    FreeUnicodeString(v1);
  return v2;
}