char __fastcall HWID_HashProcessorFeatures(__int64 a1)
{
  __int64 v1; // rbx
  char *v3; // r11
  char *v4; // r8
  unsigned int v5; // edx
  _WORD *v6; // rcx
  char buffer[64]; // [rsp+20h] [rbp-A8h]

  v1 = a1;
  buffer[0] = 0;
  *(_QWORD *)&buffer[1] = 0i64;
  *(_QWORD *)&buffer[9] = 0i64;
  *(_WORD *)&buffer[17] = 0;
  buffer[19] = 0;
  *(_WORD *)&buffer[32] = 0;
  memset(&buffer[34], 0, 0x7Eui64);
  if ( !v1 )
    return 0;
  HashSHA(0xFFFFF78000000274i64, 0x40u, (DATA_HASH_BUFFER *)buffer);// ProcessorFeatures
  v3 = buffer;
  v4 = &buffer[34];
  v5 = 1;
  do
  {
    if ( v5 >= 0x40 )
      break;
    v5 += 2;
    v6 = (_WORD *)qword_4A230[(unsigned __int8)*v3++];
    *((_WORD *)v4 - 1) = *v6;
    *(_WORD *)v4 = v6[1];
    v4 += 4;
  }
  while ( v5 < 0x29 );
  return CreateUnicodeStringFromPWSTR(v1, &buffer[32]);
}

__int64 __fastcall HWID_GetScannedRegistryKeyName(unsigned int id)
{
  unsigned int v1; // ecx
  int v2; // ecx
  int v3; // ecx
  int v4; // ecx
  unsigned int v6; // ecx
  int v7; // ecx
  int v8; // ecx
  unsigned int v9; // ecx
  int v10; // ecx
  int v11; // ecx
  int v12; // ecx
  unsigned int v13; // ecx
  int v14; // ecx
  int v15; // ecx

  if ( id <= 0xC )
  {
    if ( id == 12 )
      return StringTable + 3117;                // \Registry\Machine\Hardware\Description\System\CentralProcessor\0
    if ( id > 6 )
    {
      v6 = id - 8;
      if ( !v6 )
        return StringTable + 2843;              // SystemProductName
      v7 = v6 - 1;
      if ( !v7 )
        return StringTable + 2879;              // \Registry\Machine\Hardware\DeviceMap\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0
      v8 = v7 - 1;
      if ( !v8 )
        return StringTable + 3069;              // Identifier
      if ( v8 == 1 )
        return StringTable + 3091;              // SerialNumber
    }
    else
    {
      if ( id == 6 )
        return StringTable + 2805;              // SystemManufacturer
      v1 = id - 1;
      if ( !v1 )
        return StringTable + 2473;              // \Registry\Machine\System\CurrentControlSet\Control\SystemInformation
      v2 = v1 - 1;
      if ( !v2 )
        return StringTable + 2611;              // ComputerHardwareId
      v3 = v2 - 1;
      if ( !v3 )
        return StringTable + 2649;              // \Registry\Machine\Hardware\Description\System\BIOS
      v4 = v3 - 1;
      if ( !v4 )
        return StringTable + 2751;              // BIOSVendor
      if ( v4 == 1 )
        return StringTable + 2773;              // BIOSReleaseDate
    }
    return 0i64;
  }
  if ( id <= 0x12 )
  {
    if ( id == 18 )
      return StringTable + 3661;                // ProductId
    v9 = id - 13;
    if ( !v9 )
      return StringTable + 3247;                // ProcessorNameString
    v10 = v9 - 1;
    if ( !v10 )
      return StringTable + 3287;                // \Registry\Machine\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000
    v11 = v10 - 1;
    if ( v11 )
    {
      v12 = v11 - 1;
      if ( !v12 )
        return StringTable + 3511;              // \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion
      if ( v12 == 1 )
        return StringTable + 3637;              // InstallDate
      return 0i64;
    }
    return StringTable + 3489;                  // DriverDesc
  }
  v13 = id - 19;
  if ( !v13 )
    return StringTable + 3681;                  // \Registry\Machine\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate
  v14 = v13 - 1;
  if ( !v14 )
    return StringTable + 3829;                  // SusClientId
  v15 = v14 - 1;
  if ( v15 )
  {
    if ( v15 != 1 )
      return 0i64;
    return StringTable + 3489;
  }
  return StringTable + 3853;                    // \Registry\Machine\System\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001
}

char __fastcall QueryWMIData(const __m128i *guid0, __int64 *outBuffer)
{
  char status; // bl
  _IMAGE_DOS_HEADER *IoWMIOpenBlock; // rdi
  __int64 v7; // rax
  __int128 guid1; // [rsp+20h] [rbp-28h]
  __int64 v1; // [rsp+58h] [rbp+10h]
  PVOID dataBlockObject; // [rsp+60h] [rbp+18h]

  status = 0;
  if ( !outBuffer )
    return 0;
  IoWMIOpenBlock = (_IMAGE_DOS_HEADER *)import_IoWMIOpenBlock;
  if ( !import_IoWMIOpenBlock )
  {
    IoWMIOpenBlock = FindExport((DATA_HASH_BUFFER *)&unk_46BE0);
    import_IoWMIOpenBlock = (__int64)IoWMIOpenBlock;
    if ( !IoWMIOpenBlock )
      return 0;
  }
  if ( !import_IoWMIQueryAllData )
  {
    import_IoWMIQueryAllData = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD))FindExport((DATA_HASH_BUFFER *)&unk_46BF8);
    if ( !import_IoWMIQueryAllData )
      return 0;
  }
  _mm_storeu_si128((__m128i *)&guid1, _mm_loadu_si128(guid0));
  if ( ((__int64 (__fastcall *)(__int128 *, signed __int64, PVOID *))IoWMIOpenBlock)(&guid1, 1i64, &dataBlockObject) >= 0 )
  {
    LODWORD(v1) = 0;
    if ( (unsigned int)import_IoWMIQueryAllData(dataBlockObject, &v1, 0i64) == 0xC0000023 )
    {
      v7 = AllocatePool((unsigned int)v1);
      *outBuffer = v7;
      if ( v7 )
      {
        if ( (signed int)import_IoWMIQueryAllData(dataBlockObject, &v1, v7) < 0 )
          FreePool(*outBuffer);
        else
          status = 1;
      }
    }
    ObfDereferenceObject(dataBlockObject);
  }
  return status;
}

__int64 __usercall GetMachineId@<rax>(__int64 a1@<rcx>, signed int a2@<r14d>)
{
  unsigned int v2; // ebx
  DATA_HASH_BUFFER *v3; // rdi
  char v4; // al
  unsigned __int16 v6; // [rsp+20h] [rbp-18h]
  __int64 v7; // [rsp+28h] [rbp-10h]

  v2 = 0;
  v3 = (DATA_HASH_BUFFER *)a1;
  if ( a1 )
  {
    if ( StringTable == 4294963241 )
      v4 = 0;
    else                                        // MachineId
      v4 = ReadRegistryUnicodeString(StringTable + 4281, (_WORD *)(StringTable + 4055), (__int64)&v6, a2);//  \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\Windows Activation Technologies\AdminObject\Store
    if ( v4 )
    {
      HashSHA(v7, v6, v3);
      v2 = 20;
      FreeUnicodeString(&v6);
    }
  }
  return v2;
}

char __usercall GetNtoskrnlProductVersion@<al>(UNICODE_STRING *outProductVersion@<rcx>, signed int a2@<r14d>)
{
  char v3; // di
  __int64 resourceAddr; // [rsp+20h] [rbp-28h]
  UNICODE_STRING path; // [rsp+28h] [rbp-20h]
  unsigned int size; // [rsp+58h] [rbp+10h]
  __int64 buffer; // [rsp+60h] [rbp+18h]
  _IMAGE_NT_HEADERS64 *a4; // [rsp+68h] [rbp+20h]

  v3 = 0;
  if ( GetNtoskrnlPath(&path, a2) )
  {
    if ( ReadFileW(&path, &buffer, &size) )
    {
      if ( ValidatePeHeader((_IMAGE_DOS_HEADER *)buffer, size, 0i64, &a4)
        && GetResourceSection(a4, buffer, &resourceAddr, &size) )
      {
        v3 = GetProductVersionFromResource(resourceAddr, size, outProductVersion);
      }
      if ( buffer )
        FreePool(buffer);
    }
    FreeUnicodeString(&path);
  }
  return v3;
}