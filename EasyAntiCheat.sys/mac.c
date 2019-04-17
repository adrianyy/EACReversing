char __fastcall HWID_GetMacAddress(int a1, __int64 a2)
{
  char v2; // bl
  char v6; // [rsp+30h] [rbp-18h]

  v2 = 0;
  v6 = 0;
  if ( !a2 || a1 != 6 )
    return 0;
  if ( GetFirstNetworkDeviceMacAddress((__int64)&GUID_DEVINTERFACE_NET, (HWIDBuffer *)&a1) )
  {
    if ( v6 )
      v2 = 1;
  }
  return v2;
}

char __fastcall GetFirstNetworkDeviceMacAddress(__int64 deviceGuid, HWIDBuffer *hwidBuffer)
{
  char notFound; // bl
  __int64 index; // r12 MAPDST
  signed int status; // eax
  _WORD *it; // rbp MAPDST
  signed __int64 invertedSize; // rcx MAPDST
  _WORD *tempIt; // rdi MAPDST
  bool isNull; // zf
  char v20; // dl
  UNICODE_STRING symbolicLink; // [rsp+20h] [rbp-38h]
  PVOID symbolicLinks; // [rsp+70h] [rbp+18h]

  notFound = 1;
  index = 0i64;
  if ( !GetAdapterMacAddressWrapper || KeGetCurrentIrql() )
    return 0;
  status = import_IoGetDeviceInterfaces ? (unsigned int)import_IoGetDeviceInterfaces(
                                                          deviceGuid,
                                                          0i64,
                                                          0i64,
                                                          &symbolicLinks) : 0xC0000002;
  if ( status < 0 )
    return 0;
  do
  {
    it = (char *)symbolicLinks + 2 * index;
    if ( !*it )
      break;
    invertedSize = -1i64;
    tempIt = (char *)symbolicLinks + 2 * index;
    do
    {
      if ( !invertedSize )
        break;
      isNull = *tempIt == 0;
      ++tempIt;
      --invertedSize;
    }
    while ( !isNull );
    if ( strstrIgnoreCaseW((_WORD *)symbolicLinks + index, (unsigned __int16 *)(StringTable + 828), ~invertedSize - 1) != it )// \??\PCI
      goto LABEL_16;
    InitializeUnicodeStringWithCStr(&symbolicLink, it);
    if ( !hwidBuffer )
      goto LABEL_15;
    if ( GetAdapterMacAddress(hwidBuffer->hwidType, &symbolicLink, hwidBuffer->uniqueIdentifier) == 1 )
    {
      hwidBuffer->found = 1;
LABEL_15:
      notFound = 0;
      goto LABEL_16;
    }
    notFound = 1;
LABEL_16:
    invertedSize = -1i64;
    tempIt = (char *)symbolicLinks + 2 * index;
    do
    {
      if ( !invertedSize )
        break;
      isNull = *tempIt == 0;
      ++tempIt;
      --invertedSize;
    }
    while ( !isNull );
    index += ~invertedSize;
  }
  while ( notFound );
  for ( index = 0i64; notFound; index += ~invertedSize )
  {
    it = (char *)symbolicLinks + 2 * index;
    if ( !*it )
      break;
    invertedSize = -1i64;
    tempIt = (char *)symbolicLinks + 2 * index;
    do
    {
      if ( !invertedSize )
        break;
      isNull = *tempIt == 0;
      ++tempIt;
      --invertedSize;
    }
    while ( !isNull );
    if ( strstrIgnoreCaseW((_WORD *)symbolicLinks + index, (unsigned __int16 *)(StringTable + 844), ~invertedSize - 1) == it )// \??\USB
    {
      InitializeUnicodeStringWithCStr(&symbolicLink, it);
      if ( hwidBuffer )
      {
        if ( GetAdapterMacAddress(hwidBuffer->hwidType, &symbolicLink, hwidBuffer->uniqueIdentifier) != 1 )
        {
          notFound = 1;
          goto LABEL_31;
        }
        hwidBuffer->found = 1;
      }
      notFound = 0;
    }
LABEL_31:
    invertedSize = -1i64;
    tempIt = (char *)symbolicLinks + 2 * index;
    do
    {
      if ( !invertedSize )
        break;
      isNull = *tempIt == 0;
      ++tempIt;
      --invertedSize;
    }
    while ( !isNull );
  }
  index = 0i64;
  if ( notFound )
  {
    while ( 1 )
    {
      it = (char *)symbolicLinks + 2 * index;
      if ( !*it )
        goto LABEL_46;
      InitializeUnicodeStringWithCStr(&symbolicLink, it);
      if ( !hwidBuffer )
        goto LABEL_41;
      if ( GetAdapterMacAddress(hwidBuffer->hwidType, &symbolicLink, hwidBuffer->uniqueIdentifier) == 1 )
        break;
      v20 = 1;
LABEL_42:
      invertedSize = -1i64;
      tempIt = (char *)symbolicLinks + 2 * index;
      do
      {
        if ( !invertedSize )
          break;
        isNull = *tempIt == 0;
        ++tempIt;
        --invertedSize;
      }
      while ( !isNull );
      index += ~invertedSize;
      if ( !v20 )
        goto LABEL_46;
    }
    hwidBuffer->found = 1;
LABEL_41:
    v20 = 0;
    goto LABEL_42;
  }
LABEL_46:
  ExFreePoolWithTag(symbolicLinks, 0);
  return 1;
}

char __fastcall GetAdapterMacAddress(__int64 a1, UNICODE_STRING *deviceName, UNICODE_STRING *outMacAddress)
{
  char result; // al
  char status1; // r13
  int macCrc32; // ebp
  __int64 v8; // rbx
  char v10; // r12
  signed int status; // edi
  int *v12; // rax
  int v13; // ecx
  int *v14; // rax
  int v15; // ecx
  int *v16; // rax
  int v17; // ecx
  int *v18; // rax
  int v19; // ecx
  int *v20; // rax
  int v21; // ecx
  int *v22; // rax
  char *addrNtDeviceIoControlFile; // rax MAPDST
  int v24; // edi MAPDST
  char checksPassed; // si
  int status0; // eax
  int *v29; // rax
  int v30; // ecx
  int *v31; // rax
  int v32; // ecx
  int *v33; // rax
  int v34; // ecx
  int *v35; // rax
  int v36; // ecx
  int *v37; // rax
  int v38; // ecx
  int *v39; // rax
  __int64 ioctl; // [rsp+28h] [rbp-100h]
  __int64 inputSize; // [rsp+38h] [rbp-F0h]
  __int64 inputSize2; // [rsp+40h] [rbp-E8h]
  PVOID outputSize; // [rsp+48h] [rbp-E0h]
  unsigned __int8 macAddress[6]; // [rsp+60h] [rbp-C8h]
  HANDLE fileHandle; // [rsp+68h] [rbp-C0h] MAPDST
  int v46; // [rsp+70h] [rbp-B8h]
  __int16 v47; // [rsp+74h] [rbp-B4h]
  int v48; // [rsp+76h] [rbp-B2h]
  __int16 v49; // [rsp+7Ah] [rbp-AEh]
  int v50; // [rsp+7Ch] [rbp-ACh]
  __int16 v51; // [rsp+80h] [rbp-A8h]
  int v52; // [rsp+82h] [rbp-A6h]
  __int16 v53; // [rsp+86h] [rbp-A2h]
  int v54; // [rsp+88h] [rbp-A0h]
  __int16 v55; // [rsp+8Ch] [rbp-9Ch]
  int v56; // [rsp+8Eh] [rbp-9Ah]
  __int16 v57; // [rsp+92h] [rbp-96h]
  __int64 outValue; // [rsp+B0h] [rbp-78h]
  __int64 addedBytes; // [rsp+B8h] [rbp-70h] MAPDST
  struct _IO_STATUS_BLOCK statusBlock; // [rsp+C0h] [rbp-68h]
  OBJECT_ATTRIBUTES objectAttributes; // [rsp+D0h] [rbp-58h]
  int objectId; // [rsp+138h] [rbp+10h]

  result = 0;
  objectId = 0x1010101;                         // OID_802_3_PERMANENT_ADDRESS
  status1 = 0;
  macAddress[0] = 0;
  *(_DWORD *)&macAddress[1] = 0;
  macAddress[5] = 0;
  macCrc32 = 0;
  if ( deviceName
    && deviceName->Buffer
    && deviceName->Length
    && deviceName->MaximumLength
    && outMacAddress
    && (_DWORD)a1 == 6 )
  {
    if ( !KeGetCurrentIrql() && !(unsigned __int8)import_KeAreAllApcsDisabled(a1) )
    {
      objectAttributes.Length = 48;
      objectAttributes.RootDirectory = 0i64;
      objectAttributes.Attributes = 512;
      objectAttributes.ObjectName = deviceName;
      objectAttributes.SecurityDescriptor = 0i64;
      objectAttributes.SecurityQualityOfService = 0i64;
      if ( ZwCreateFile(&fileHandle, 0x120089u, &objectAttributes, &statusBlock, 0i64, 0x80u, 7u, 1u, 0x20u, 0i64, 0) < 0 )
        return status1;
      v8 = __readgsqword(0x188u);
      v10 = GetPreviousMode(v8, 0);
      SetPreviousMode(0, v8, 0);
      if ( import_NtDeviceIoControlFile )
      {
        LODWORD(outputSize) = 6;
        LODWORD(inputSize) = 4;
        LODWORD(ioctl) = 0x170002;              // IOCTL_NDIS_QUERY_GLOBAL_STATS
        status = import_NtDeviceIoControlFile(
                   fileHandle,
                   0i64,
                   0i64,
                   0i64,
                   &statusBlock,
                   ioctl,
                   &objectId,
                   inputSize,
                   macAddress,
                   outputSize);
      }
      else
      {
        status = 0xC0000002;
      }
      SetPreviousMode(v10, v8, 0);
      if ( status >= 0 )
      {
        v12 = (int *)qword_4A230[macAddress[0]];
        v47 = '-';
        v49 = '-';
        v13 = *v12;
        v51 = '-';
        v14 = (int *)qword_4A230[macAddress[1]];
        v46 = v13;
        v53 = '-';
        v15 = *v14;
        v55 = '-';
        v16 = (int *)qword_4A230[macAddress[2]];
        v48 = v15;
        v57 = 0;
        v17 = *v16;
        v18 = (int *)qword_4A230[macAddress[3]];
        v50 = v17;
        v19 = *v18;
        v20 = (int *)qword_4A230[macAddress[4]];
        v52 = v19;
        v21 = *v20;
        v22 = (int *)qword_4A230[macAddress[5]];
        v54 = v21;
        v56 = *v22;
        status1 = CreateUnicodeStringFromPWSTR((__int64)outMacAddress, &v46);
        if ( status1 )
        {
          addrNtDeviceIoControlFile = (char *)GetNtDeviceIoControlFileAddress();
          v24 = sub_1705C(addrNtDeviceIoControlFile, 0x10i64, &addedBytes);
          if ( v24 && addedBytes )
          {
            checksPassed = 0;
            addrNtDeviceIoControlFile = (char *)GetNtDeviceIoControlFileAddress();
            if ( addrNtDeviceIoControlFile )
            {
              if ( v24 == 0x1290373
                && (unsigned int)sub_1705C((char *)CallNtDeviceIoControlFilePlus10, addedBytes, &outValue) == 0x1290373
                && outValue == addedBytes )
              {
                checksPassed = 1;
                NtDeviceIoControlFilePlus10 = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD, _QWORD))&addrNtDeviceIoControlFile[addedBytes];
              }
            }
            else
            {
              checksPassed = 0;
            }
            if ( checksPassed )
            {
              if ( v24 != 0x1290373 )
              {
                if ( !byte_4D8AB )
                {
                  SendPacketToServer(353i64, (__int64)&v24, 4i64);
                  byte_4D8AB = 1;
                }
                goto LABEL_37;
              }
              macCrc32 = HashCRC32((char *)macAddress, 6u, 0);
              LODWORD(inputSize2) = 4;
              status0 = CallNtDeviceIoControlFilePlus10_KernelMode(
                          (__int64)fileHandle,
                          0,
                          0,
                          (__int64)&statusBlock,
                          0x170002,
                          (unsigned __int64)&objectId,
                          inputSize2,
                          (unsigned __int64)macAddress);
              goto LABEL_30;
            }
          }
          if ( !byte_4D8AA )
          {
            SendPacketToServer(352i64, 0i64, 0i64);
            status0 = objectId;
            byte_4D8AA = 1;
LABEL_30:
            if ( macCrc32 )
            {
              if ( status0 >= 0 )
              {
                if ( macCrc32 != (unsigned int)HashCRC32((char *)macAddress, 6u, 0) && !byte_4DA64 )
                {
                  v29 = (int *)qword_4A230[macAddress[0]];
                  v47 = 45;
                  v30 = *v29;
                  v49 = 45;
                  v31 = (int *)qword_4A230[macAddress[1]];
                  v46 = v30;
                  v51 = 45;
                  v32 = *v31;
                  v53 = 45;
                  v33 = (int *)qword_4A230[macAddress[2]];
                  v48 = v32;
                  v55 = 45;
                  v34 = *v33;
                  v35 = (int *)qword_4A230[macAddress[3]];
                  v50 = v34;
                  v57 = 0;
                  v36 = *v35;
                  v37 = (int *)qword_4A230[macAddress[4]];
                  v52 = v36;
                  v38 = *v37;
                  v39 = (int *)qword_4A230[macAddress[5]];
                  v54 = v38;
                  v56 = *v39;
                  SendPacketToServer(354i64, (__int64)&v46, 64i64);
                  byte_4DA64 = 1;
                }
              }
              else if ( !byte_4DA65 )
              {
                SendPacketToServer(355i64, (__int64)&v24, 4i64);
                byte_4DA65 = 1;
              }
            }
            goto LABEL_37;
          }
        }
      }
LABEL_37:
      CloseHandle((__int64)fileHandle, 0);
      return status1;
    }
    result = 0;
  }
  return result;
}