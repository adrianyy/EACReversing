__int64 __usercall CheckOpenedHandles@<rax>(PVOID protectedProcessID@<rcx>, __int64 a2@<rdx>, unsigned __int64 a3@<r14>)
{
  char v3; // bp
  SYSTEM_HANDLE_INFORMATION *handleInformation; // rax MAPDST
  ULONG index; // esi
  __int64 entry; // rbx
  __int64 ownerProcess; // r13
  __int64 handle; // rbp
  char v12; // r15
  signed int v13; // ebp
  __int64 v14; // [rsp+20h] [rbp-88h]
  __int64 v15; // [rsp+28h] [rbp-80h]
  __int64 v16; // [rsp+30h] [rbp-78h]
  _PROCESS_BASIC_INFORMATION processInfo; // [rsp+40h] [rbp-68h]
  char v19; // [rsp+C0h] [rbp+18h]
  __int64 duplicatedHandle; // [rsp+C8h] [rbp+20h]

  v3 = 1;
  v19 = 1;
  if ( !ReportProcess )
    return 0i64;
  handleInformation = (SYSTEM_HANDLE_INFORMATION *)QuerySystemInformation_0(
                                                     0x10u,
                                                     (unsigned __int64)qword_80000,
                                                     0x1000000u,
                                                     0i64,
                                                     a3);
  if ( !handleInformation )
    return 0i64;
  index = 0;
  if ( handleInformation->Count )
  {
    entry = (__int64)&handleInformation->Info[0].GrantedAccess;
    while ( 1 )
    {
      if ( !v3 )
        goto LABEL_24;
      if ( *(_DWORD *)(entry - 16) > 4u && *(_DWORD *)(entry - 16) != (_DWORD)protectedProcessID )
      {
        ownerProcess = GetProcessHandleFromPID(*(unsigned int *)(entry - 0x10), 1104i64);
        if ( ownerProcess )
          break;
      }
LABEL_23:
      ++index;
      entry += 24i64;
      if ( index >= handleInformation->Count )
        goto LABEL_24;
    }
    if ( !byte_4DEF2 || byte_4DEF2 == *(_BYTE *)(entry - 12) )
    {
      a3 = __readgsqword(0x188u);
      handle = *(unsigned __int16 *)(entry - 0xA);
      v12 = GetPreviousMode(a3, a3);
      SetPreviousMode(0, a3, a3);
      if ( import_NtDuplicateObject )
      {
        LODWORD(v16) = 2;
        LODWORD(v15) = 512;
        LODWORD(v14) = 0;
        v13 = import_NtDuplicateObject(ownerProcess, handle, -1i64, &duplicatedHandle, v14, v15, v16);
      }
      else
      {
        v13 = -1073741822;
      }
      SetPreviousMode(v12, a3, a3);
      if ( v13 >= 0 )
      {
        if ( (signed int)QueryProcessInformation(0, duplicatedHandle, (__int64)&processInfo, 0x30u, a3, 0i64) < 0 )
        {
          CloseHandle(duplicatedHandle, a3);
        }
        else
        {
          CloseHandle(duplicatedHandle, a3);
          byte_4DEF2 = *(_BYTE *)(entry - 12);
          if ( (PVOID)processInfo.UniqueProcessId == protectedProcessID && (unsigned int)word_E063A & *(_DWORD *)entry )
          {
            v3 = ReportProcess(
                   protectedProcessID,
                   *(unsigned int *)(entry - 0x10),// handle owner PID
                   *(unsigned __int16 *)(entry - 10),// handle
                   *(_DWORD *)entry,            // access
                   (PVOID)a2);
            v19 = v3;
            goto LABEL_22;
          }
        }
      }
      v3 = v19;
    }
LABEL_22:
    CloseHandle(ownerProcess, a3);
    goto LABEL_23;
  }
LABEL_24:
  FreePool((__int64)handleInformation);
  return index;
}