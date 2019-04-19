void CheckDebugRegisters()
{
  __int64 v0; // rdx
  __int64 v1; // rcx
  __int64 v2; // rax
  __int64 currentProcessID; // rax
  __int64 *v4; // rax MAPDST
  unsigned __int64 dr7; // [rsp+38h] [rbp+10h]
  unsigned __int64 dr6; // [rsp+40h] [rbp+18h]

  ReadDR6_DR7(&dr6, &dr7);
  if ( (_BYTE)dr7 )
  {
    v2 = import_PsGetCurrentProcess(v1, v0);
    if ( import_PsGetProcessId )
      currentProcessID = import_PsGetProcessId(v2);
    else
      currentProcessID = 0i64;
    v4 = sub_29404(currentProcessID);
    if ( v4 )
    {
      sub_330E0((__int64)v4, 14i64, 0);
      sub_29534((__int64)v4);
    }
  }
}