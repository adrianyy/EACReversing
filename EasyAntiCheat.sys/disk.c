void __usercall SendDiskInformation(unsigned int a1@<ecx>, signed int a2@<r14d>)
{
  int crc32; // ebx
  unsigned int packetValueUnk; // ecx
  UNICODE_STRING deviceSerial; // [rsp+20h] [rbp-18h]

  deviceSerial.Length = 0;
  *(_QWORD *)&deviceSerial.MaximumLength = 0i64;
  crc32 = 0;
  *(_DWORD *)((char *)&deviceSerial.Buffer + 2) = 0;
  HIWORD(deviceSerial.Buffer) = 0;
  if ( QueryFilesystemDeviceSerial(3i64, &deviceSerial, a2)
    && deviceSerial.Buffer
    && deviceSerial.Length
    && deviceSerial.MaximumLength )
  {
    crc32 = HashCRC32((char *)deviceSerial.Buffer, deviceSerial.Length, deviceSerial.Length);
  }
  if ( !a1 || !crc32 || (packetValueUnk = 316, a1 != crc32) )
    packetValueUnk = 315;
  SendHWIDDataToServer(packetValueUnk, a1, crc32, &deviceSerial);
  if ( deviceSerial.Buffer && deviceSerial.Length )
  {
    if ( deviceSerial.MaximumLength )
      FreeUnicodeString(&deviceSerial);
  }
}

char __usercall QueryFilesystemDeviceSerial@<al>(__int64 a1@<rcx>, UNICODE_STRING *outData@<rdx>, signed int a3@<r14d>)
{
  char success; // bl
  _DEVICE_OBJECT *deviceObject; // rax MAPDST
  _DEVICE_OBJECT *filesystemDevice; // rax MAPDST
  UNICODE_STRING driverName; // [rsp+20h] [rbp-18h]

  success = 0;
  if ( !outData || KeGetCurrentIrql() || (unsigned __int8)import_KeAreAllApcsDisabled(a1) )
    return 0;
  InitializeUnicodeStringWithCStr(&driverName, (_WORD *)(StringTable + 4419));// \Driver\disk
  deviceObject = (_DEVICE_OBJECT *)GetLastDeviceObjectForDriver(&driverName, a3);
  if ( deviceObject )
  {
    filesystemDevice = (_DEVICE_OBJECT *)IoGetDeviceAttachmentBaseRef(deviceObject);
    if ( filesystemDevice )
    {
      if ( filesystemDevice != deviceObject )
        success = QueryDriveSmartOrStorageData(filesystemDevice, 3, outData);// 3 = query serial
      ObfDereferenceObject(filesystemDevice);
    }
    ObfDereferenceObject(deviceObject);
  }
  return success;
}

__int64 __usercall GetLastDeviceObjectForDriver@<rax>(UNICODE_STRING *driverName@<rcx>, signed int a2@<r14d>)
{
  unsigned int v2; // ebx
  __int64 lastDeviceObject; // r12
  _IMAGE_DOS_HEADER *v4; // rax
  __int64 IoDeviceObject; // rsi
  signed int status1; // edi MAPDST
  unsigned int access; // ST20_4
  unsigned int status0; // eax
  unsigned int bufferSize; // ebp
  __int64 deviceObjectList; // rsi
  __int64 lastDeviceIndex; // rcx
  PVOID *currentDeviceObject; // rdi
  PVOID *v16; // [rsp+20h] [rbp-78h]
  __int64 v17; // [rsp+28h] [rbp-70h]
  OBJECT_ATTRIBUTES objectAttributes; // [rsp+40h] [rbp-58h]
  __int64 deviceObjectNumber; // [rsp+A0h] [rbp+8h]
  PVOID driverObject; // [rsp+A8h] [rbp+10h]
  __int64 driverHandle; // [rsp+B0h] [rbp+18h]

  v2 = 0;
  lastDeviceObject = 0i64;
  LODWORD(deviceObjectNumber) = 0;
  if ( !driverName || !driverName->Buffer || !driverName->Length || !driverName->MaximumLength )
    return 0i64;
  objectAttributes.Length = 48;
  objectAttributes.RootDirectory = 0i64;
  objectAttributes.Attributes = 576;
  objectAttributes.ObjectName = driverName;
  objectAttributes.SecurityDescriptor = 0i64;
  objectAttributes.SecurityQualityOfService = 0i64;
  v4 = (_IMAGE_DOS_HEADER *)qword_4D8C8;
  if ( qword_4D8C8 || (v4 = FindExport(&unk_46B38), IoDeviceObject = 0i64, (qword_4D8C8 = (__int64)v4) != 0) )
    IoDeviceObject = *(_QWORD *)&v4->e_magic;
  if ( IoDeviceObject )
  {
    status1 = 0xC0000002;
    if ( import_ObOpenObjectByName )
    {
      access = 0x80000000;
      status1 = import_ObOpenObjectByName(&objectAttributes, IoDeviceObject, 0i64, 0i64, access, 0i64, &driverHandle);
    }
    else
    {
      status1 = 0xC0000002;
    }
    if ( status1 >= 0 )
    {
      if ( import_ObReferenceObjectByHandle )
      {
        v17 = 0i64;
        v16 = &driverObject;
        status1 = import_ObReferenceObjectByHandle(driverHandle, 1i64, IoDeviceObject);
      }
      else
      {
        status1 = 0xC0000002;
      }
      if ( status1 >= 0 )
      {
        if ( import_IoEnumerateDeviceObjectList )
          status0 = import_IoEnumerateDeviceObjectList(driverObject, 0i64, 0i64, &deviceObjectNumber, v16, v17);
        else
          status0 = 0xC0000002;
        if ( status0 == 0xC0000023 && (unsigned int)deviceObjectNumber > 0 )
        {
          bufferSize = 8 * deviceObjectNumber;
          deviceObjectList = AllocatePool((unsigned int)(8 * deviceObjectNumber));
          if ( deviceObjectList )
          {
            if ( import_IoEnumerateDeviceObjectList )
              status1 = import_IoEnumerateDeviceObjectList(
                          driverObject,
                          deviceObjectList,
                          bufferSize,
                          &deviceObjectNumber,
                          v16,
                          v17);
            if ( status1 >= 0 && (unsigned int)deviceObjectNumber > 0 )
            {
              lastDeviceIndex = (unsigned int)(deviceObjectNumber - 1);
              lastDeviceObject = *(_QWORD *)(deviceObjectList + 8 * lastDeviceIndex);
              if ( (unsigned int)lastDeviceIndex > 0 )
              {
                currentDeviceObject = (PVOID *)deviceObjectList;
                do
                {
                  ObfDereferenceObject(*currentDeviceObject);
                  ++v2;
                  ++currentDeviceObject;
                }
                while ( v2 < (signed int)deviceObjectNumber - 1 );
              }
            }
            FreePool(deviceObjectList);
          }
        }
        ObfDereferenceObject(driverObject);
      }
      CloseHandle(driverHandle, a2);
    }
  }
  return lastDeviceObject;
}

char __fastcall QueryDriveSmartOrStorageData(_DEVICE_OBJECT *deviceObject, int whatToQueryEnum, UNICODE_STRING *outData)
{
  char success; // bl

  success = 0;
  if ( !deviceObject
    || !outData
    || whatToQueryEnum != 2 && whatToQueryEnum != 3
    || KeGetCurrentIrql()
    || (unsigned __int8)import_KeAreAllApcsDisabled(deviceObject) )
  {
    return 0;
  }
  if ( QuerySmartData(whatToQueryEnum, deviceObject, outData)
    || QueryStorageProperty(whatToQueryEnum, deviceObject, outData) )
  {
    success = 1;
  }
  return success;
}

bool __fastcall QuerySmartData(int whatToQueryEnum, _DEVICE_OBJECT *deviceObject, UNICODE_STRING *outData)
{
  bool success; // bl
  _SENDCMDOUTPARAMS *outParams; // rsi
  int querySerial; // edi
  BYTE *data; // rbp
  size_t dataLength; // rdi
  unsigned __int64 v11; // rdx
  unsigned __int64 v12; // r11
  char v13; // cl
  char v14; // al
  unsigned __int8 c; // al
  ANSI_STRING ansiString; // [rsp+30h] [rbp-C8h]
  SENDCMDINPARAMS inParams; // [rsp+40h] [rbp-B8h]
  char v19; // [rsp+6Eh] [rbp-8Ah]
  char v20; // [rsp+6Fh] [rbp-89h]
  char copiedData[128]; // [rsp+70h] [rbp-88h]
                                                // https://www.winsim.com/diskid32/diskid32.cpp
  success = 0;
  if ( deviceObject && outData )
  {
    outParams = (_SENDCMDOUTPARAMS *)AllocatePool(529i64);
    if ( !outParams )
      return success;
    *(_QWORD *)&outParams->cBufferSize = 0i64;
    *(_QWORD *)outParams->DriverStatus.dwReserved = 0i64;
    outParams->bBuffer[0] = 0;
    memset(&inParams, 0, 33ui64);
    inParams.irDriveRegs.bCommandReg = -20;     // Returns ID sector for ATA
    if ( SendIoControl(
           (__int64)&dword_7C088,               // SMART_RCV_DRIVE_DATA
           deviceObject,
           (__int64)&inParams,
           33u,
           (__int64)outParams,
           529) >= 0 )
    {
      querySerial = whatToQueryEnum - 2;
      if ( !querySerial )
      {
        data = (BYTE *)outParams[3].DriverStatus.dwReserved + 2;// model number
        dataLength = 40i64;
        goto LABEL_9;
      }
      if ( querySerial == 1 )
      {
        data = outParams[1].bBuffer;            // serial number
        dataLength = 20i64;
LABEL_9:
        if ( data && dataLength > 0 )
        {
          memset(copiedData, 0, 128ui64);
          memmove(copiedData, data, dataLength);
          v11 = dataLength - 1;
          v12 = 0i64;
          if ( dataLength - 1 > 0 )
          {
            do
            {
              v13 = copiedData[v12];
              v14 = copiedData[v12 + 1];
              v12 += 2i64;
              *(&v19 + v12) = v14;
              *(&v20 + v12) = v13;
            }
            while ( v12 < v11 );
            if ( v11 > 0 )
            {
              do
              {
                c = copiedData[v11];
                if ( (c < '\t' || c > '\r') && c != 0x20 )
                {
                  if ( c )
                    break;
                }
                else
                {
                  copiedData[v11] = 0;
                }
                --v11;
              }
              while ( v11 );
            }
          }
          ansiString.Buffer = copiedData;
          SetAnsiStringLength(&ansiString, copiedData);
          success = (signed int)AnsiStringToUnicodeString(outData, &ansiString) >= 0;
        }
        goto LABEL_21;
      }
    }
LABEL_21:
    FreePool((__int64)outParams);
    return success;
  }
  return 0;
}

bool __fastcall QueryStorageProperty(int whatToQueryEnum, _DEVICE_OBJECT *driverObject, UNICODE_STRING *outData)
{
  bool status; // bl
  unsigned __int64 dataLength; // rdi
  _STORAGE_DEVICE_DESCRIPTOR *deviceDescriptor; // rsi MAPDST
  char *deviceDescriptorEnd; // rcx
  int querySerial; // ebp
  char *data; // rdx
  unsigned __int64 maxSize0; // rcx
  unsigned __int64 maxSize1; // rcx
  size_t length; // rbp
  signed __int64 v16; // rax
  unsigned __int8 c; // cl
  _STORAGE_PROPERTY_QUERY propertyQuery; // [rsp+30h] [rbp-B8h]
  ANSI_STRING ansiString; // [rsp+40h] [rbp-A8h]
  char copiedData[128]; // [rsp+50h] [rbp-98h]
  __int64 requiredSize; // [rsp+F8h] [rbp+10h]

  status = 0;
  dataLength = 0i64;
  if ( driverObject && outData )
  {
    requiredSize = 0i64;
    *(_DWORD *)propertyQuery.AdditionalParameters = 0;
    propertyQuery.QueryType = 0;
    propertyQuery.PropertyId = 0;
    if ( SendIoControl(2954240i64, driverObject, (__int64)&propertyQuery, 0xCu, (__int64)&requiredSize, 8) < 0 )
      return status;
    if ( HIDWORD(requiredSize) <= 0x28 )
      return status;
    deviceDescriptor = (_STORAGE_DEVICE_DESCRIPTOR *)AllocatePool(HIDWORD(requiredSize));
    if ( !deviceDescriptor )
      return status;
    memset(deviceDescriptor, 0, HIDWORD(requiredSize));
    *(_DWORD *)propertyQuery.AdditionalParameters = 0;
    propertyQuery.QueryType = 0;                // StorageDeviceProperty
    propertyQuery.PropertyId = 0;               // PropertyStandardQuery
    if ( SendIoControl(
           0x2D1400i64,                         // IOCTL_STORAGE_QUERY_PROPERTY
           driverObject,
           (__int64)&propertyQuery,
           0xCu,
           (__int64)deviceDescriptor,
           SHIDWORD(requiredSize)) >= 0 )
    {
      deviceDescriptorEnd = (char *)deviceDescriptor + HIDWORD(requiredSize);
      querySerial = whatToQueryEnum - 2;
      if ( querySerial )
      {
        if ( querySerial == 1 && deviceDescriptor->SerialNumberOffset )
        {
          data = (char *)deviceDescriptor + deviceDescriptor->SerialNumberOffset;
          if ( data < (char *)deviceDescriptor || data >= deviceDescriptorEnd )
            goto LABEL_24;
          maxSize0 = deviceDescriptorEnd - data;
          if ( data )
          {
            if ( maxSize0 > 0 )
            {
              do
              {
                if ( !data[dataLength] )
                  break;
                ++dataLength;
              }
              while ( dataLength < maxSize0 );
            }
            goto LABEL_24;
          }
        }
      }
      else if ( deviceDescriptor->ProductIdOffset )
      {
        data = (char *)deviceDescriptor + deviceDescriptor->ProductIdOffset;
        if ( data < (char *)deviceDescriptor || data >= deviceDescriptorEnd )
          goto LABEL_24;
        maxSize1 = deviceDescriptorEnd - data;
        if ( data )
        {
          if ( maxSize1 > 0 )
          {
            do
            {
              if ( !data[dataLength] )
                break;
              ++dataLength;
            }
            while ( dataLength < maxSize1 );
          }
LABEL_24:
          if ( data && dataLength > 0 )
          {
            length = 127i64;
            if ( dataLength < 127 )
              length = dataLength;
            memmove(copiedData, data, length);
            copiedData[length] = 0;
            if ( length )
            {
              v16 = length - 1;
              if ( length - 1 > 0 )
              {
                do
                {
                  c = copiedData[v16];
                  if ( (c < '\t' || c > '\r') && c != ' ' )
                  {
                    if ( c )
                      break;
                  }
                  else
                  {
                    copiedData[v16] = 0;
                  }
                  --v16;
                }
                while ( v16 );
              }
            }
            *(_QWORD *)&ansiString.Length = copiedData;// it's Buffer but hexrays is doing weird shit
            SetAnsiStringLength(&ansiString, copiedData);
            status = (signed int)AnsiStringToUnicodeString(outData, &ansiString) >= 0;
          }
          goto LABEL_37;
        }
      }
    }
LABEL_37:
    FreePool((__int64)deviceDescriptor);
    return status;
  }
  return 0;
}