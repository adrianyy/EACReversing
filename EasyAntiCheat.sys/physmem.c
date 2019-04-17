bool __fastcall CheckForPhysicalHandle(_DWORD *a1)
{
  SYSTEM_HANDLE_INFORMATION *systemHandleInformation; // r12
  signed int v4; // er11
  PVOID v5; // rax
  unsigned __int64 index; // rbp
  PVOID sectionObjectType; // rcx
  char v8; // r13
  SYSTEM_HANDLE_TABLE_ENTRY_INFO *entry; // rsi
  char v10; // si
  char v11; // r13
  _UNICODE_STRING *v12; // rdx
  char v13; // al
  UNICODE_STRING v14; // [rsp+30h] [rbp-88h]
  UNICODE_STRING a1a; // [rsp+40h] [rbp-78h]
  char v16; // [rsp+50h] [rbp-68h]
  OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+60h] [rbp-58h]
  HANDLE SectionHandle; // [rsp+C0h] [rbp+8h]

  if ( !a1 )
    return 0;
  memset(a1, 0, 0x20ui64);
  if ( !import_ObIsKernelHandle || _InterlockedCompareExchange(&dword_4D8B0, 1, 0) )
    return 0;
  systemHandleInformation = (SYSTEM_HANDLE_INFORMATION *)QuerySystemInformation_0(
                                                           0x10u,
                                                           (unsigned __int64)qword_80000,
                                                           0x1000000u,
                                                           0i64,
                                                           1);
  if ( !systemHandleInformation )
    goto LABEL_43;
  InitializeUnicodeStringWithCStr(&a1a, (_WORD *)(StringTable + 7061));// \Device\PhysicalMemory
  ObjectAttributes.ObjectName = &a1a;
  ObjectAttributes.Length = 48;
  ObjectAttributes.RootDirectory = 0i64;
  ObjectAttributes.Attributes = 576;
  ObjectAttributes.SecurityDescriptor = 0i64;
  ObjectAttributes.SecurityQualityOfService = 0i64;
  if ( ZwOpenSection(&SectionHandle, 1u, &ObjectAttributes) >= 0 )
  {
    if ( import_ObReferenceObjectByHandle )
      v4 = import_ObReferenceObjectByHandle(SectionHandle, 1i64, 0i64);
    else
      v4 = 0xC0000002;
    v5 = SectionObjectType;
    if ( v4 < 0 )
      v5 = 0i64;
    SectionObjectType = v5;
    ZwClose(SectionHandle);
  }
  index = 0i64;
  if ( systemHandleInformation->Count <= 0 )
    goto LABEL_39;
  sectionObjectType = SectionObjectType;
  v8 = 0;
  entry = systemHandleInformation->Info;
  while ( 1 )
  {
    if ( entry->Object != sectionObjectType || !sectionObjectType || entry->ProcessId == 4 )
      goto LABEL_20;
    if ( !(unsigned __int8)import_ObIsKernelHandle(entry->Handle) )
      break;
    sectionObjectType = SectionObjectType;
LABEL_20:
    ++index;
    ++entry;
    if ( index >= systemHandleInformation->Count )
      goto LABEL_40;
  }
  if ( entry->ProcessId )
    v10 = GetProcessImageFileName(&v14, entry->ProcessId, 1);
  else
    v10 = 0;
  if ( v10 )
    v8 = sub_289F0(&v14.Length, (__int64)&v16);
  v11 = -v8;
  v12 = (_UNICODE_STRING *)((unsigned __int64)&v16 & -(signed __int64)(v11 != 0));
  if ( !a1[1] )
  {
    *(_BYTE *)a1 = 1;
    a1[1] = 13;
    if ( v12 )
    {
      if ( *(_QWORD *)(((unsigned __int64)&v16 & -(signed __int64)(v11 != 0)) + 8)
        && v12->Length
        && *(_WORD *)(((unsigned __int64)&v16 & -(signed __int64)(v11 != 0)) + 2)
        && !*((_BYTE *)a1 + 8) )
      {
        if ( a1 == (_DWORD *)-16i64 )
          v13 = 0;
        else
          v13 = AllocateCopyUnicodeString((__int64)(a1 + 4), v12);
        *((_BYTE *)a1 + 8) = v13;
      }
    }
  }
  if ( v10 )
    FreeUnicodeString(&v14);
LABEL_39:
  sectionObjectType = SectionObjectType;
LABEL_40:
  if ( sectionObjectType )
  {
    ObfDereferenceObject(sectionObjectType);
    SectionObjectType = 0i64;
  }
  FreePool((__int64)systemHandleInformation);
LABEL_43:
  _InterlockedExchange(&dword_4D8B0, 0);
  return a1[1] != 0;
}