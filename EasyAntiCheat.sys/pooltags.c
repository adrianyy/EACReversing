bool __usercall CheckForBannedPooltags@<al>(signed int a1@<r14d>)
{
  signed int v1; // ebx
  SYSTEM_POOLTAG_INFORMATION *pooltagInformation; // rax
  ULONG v3; // edx
  __int64 entry; // rcx

  v1 = 0;
  pooltagInformation = (SYSTEM_POOLTAG_INFORMATION *)QuerySystemInformation_0(0x16u, 0x10000u, 0x100000u, 0i64, a1);
  if ( pooltagInformation )
  {
    v3 = 0;
    if ( pooltagInformation->Count > 0 )
    {
      entry = (__int64)&pooltagInformation->TagInfo[0].PagedAllocs;
      do
      {
        if ( v1 == 3 )
          break;
        if ( *(_DWORD *)(entry - 4) != 'rcIC' || *(_DWORD *)entry <= *(_DWORD *)(entry + 4) )
        {
          if ( *(_DWORD *)(entry - 4) == 'csIC' && *(_DWORD *)entry > *(_DWORD *)(entry + 4) )
            v1 |= 2u;
        }
        else
        {
          v1 |= 1u;
        }
        ++v3;
        entry += 40i64;
      }
      while ( v3 < pooltagInformation->Count );
    }
    FreePool((__int64)pooltagInformation);
  }
  else
  {
    v1 = 3;
  }
  return v1 == 3;
}