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