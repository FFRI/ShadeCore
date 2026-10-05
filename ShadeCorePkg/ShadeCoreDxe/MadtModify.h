/*
 * (c) FFRI Security, Inc., 2026 / Author: FFRI Security, Inc.
 */

//
// Used in ModifyMADT function
//   - Check if the given APIC Structure is Processor Local APIC Structure (Type = 0) or
//     Local APIC NMI Structure (Type = 4) whose Processor ID corresponds to ShadeCore
//     and return TRUE if it is.
//
BOOLEAN
EFIAPI
ShouldRemoveEntry (
    IN  BYTE*   Struct,
    IN  UINT32  TargetCoreId
    )
{
  BYTE Type = Struct[0];
  BYTE Len  = Struct[1];

  if (Type == EFI_ACPI_3_0_PROCESSOR_LOCAL_APIC) {
    EFI_ACPI_3_0_PROCESSOR_LOCAL_APIC_STRUCTURE *LocalApicStruct =
        (EFI_ACPI_3_0_PROCESSOR_LOCAL_APIC_STRUCTURE*)Struct;

    if(LocalApicStruct->AcpiProcessorId == TargetCoreId)
      return TRUE;
    return FALSE;
  }

  if (Type == EFI_ACPI_3_0_LOCAL_APIC_NMI) {
    EFI_ACPI_3_0_LOCAL_APIC_NMI_STRUCTURE *NmiStruct =
        (EFI_ACPI_3_0_LOCAL_APIC_NMI_STRUCTURE*)Struct;

    if(NmiStruct->AcpiProcessorId == TargetCoreId)
      return TRUE;
    return FALSE;
  }

  return FALSE;
}



//
// Main function to modify MADT
//   - MADT is located by AcpiSdtProtocol
//   - MADT structure is defined by ACPI standard
//   - Normally, MADT consists of a header followed by multiple APIC Structures.
//     APIC Structures are classified by the Type indicated by their first byte.
//     This function excludes the structure of Processor Local APIC Structure (Type = 0) and
//     Local APIC NMI Structure (Type = 4) whose Processor ID corresponds to ShadeCore
//   - This will hide ShadeCore from the OS (OS Loader)
//
VOID
EFIAPI
ModifyMADT(
    UINT8 ProcessorID
    )
{
  EFI_STATUS Status; 
  EFI_ACPI_SDT_HEADER *Table = NULL;
  EFI_ACPI_TABLE_VERSION TableVer = 0;
  UINTN TableKey = 0;

  EFI_ACPI_SDT_PROTOCOL *AcpiSdtProtocol = NULL;
  gBS->LocateProtocol(
      &gEfiAcpiSdtProtocolGuid,
      NULL,
      (VOID**)&AcpiSdtProtocol
      );

  // 1: Find MADT
  for(int i=0; ; i++) {
    Status = AcpiSdtProtocol->GetAcpiTable(
        i,
        (EFI_ACPI_SDT_HEADER**)&Table,
        (EFI_ACPI_TABLE_VERSION*)&TableVer,
        &TableKey
        );

    if(Table->Signature == SIGNATURE_32('A','P','I','C')) { // MADT (APIC)
      Print(L"MADT found!\n");
      Print(L"ACPI Table version %x\n", TableVer);
      break;
    }
  }

  // 2: Remove ProcessorID (arg) core from MADT
  //   - [Check] Precisely, it is necessary to use different structures depending on the ACPI version
  EFI_ACPI_3_0_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER *OldMadt =
        (EFI_ACPI_3_0_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER *)Table;
  UINTN OldMadtLen = OldMadt->Header.Length;

  EFI_ACPI_3_0_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER *NewMadt = NULL;
  gBS->AllocatePool(
      EfiRuntimeServicesData,
      OldMadtLen,
      (VOID**)&NewMadt
      );
  CopyMem((VOID*)NewMadt, (VOID*)OldMadt, OldMadtLen);

  BYTE *Struct = (BYTE*)OldMadt + sizeof(*OldMadt);
  BYTE *StructEnd = (BYTE*)OldMadt + OldMadtLen;
  BYTE *Dst = (BYTE*)NewMadt + sizeof(*NewMadt);

  while(Struct < StructEnd) {
    UINT8 StructType = Struct[0];
    UINT8 StructLen  = Struct[1];
    if(!ShouldRemoveEntry(Struct, ProcessorID)) {
      CopyMem(Dst, Struct, StructLen);
      Dst += StructLen;
    }
    else {
      Print(L"Removed MADT struct (type %u) for ApicProcessorId=%u\n", StructType, ProcessorID);
    }
    Struct += StructLen;
  }

  UINT32 NewMadtLen = (UINT32)(Dst - (BYTE*)NewMadt);
  NewMadt->Header.Length = NewMadtLen;
  NewMadt->Header.Checksum = CalcChecksum8(NewMadt, NewMadtLen);


  // 3: Reinstall modified MADT
  EFI_ACPI_TABLE_PROTOCOL *AcpiTableProtocol = NULL;
  gBS->LocateProtocol(
      &gEfiAcpiTableProtocolGuid,
      NULL,
      (VOID**)&AcpiTableProtocol
      );
  Status = AcpiTableProtocol->UninstallAcpiTable(
      AcpiTableProtocol,
      TableKey
      );
  Print(L"UninstallAcpiTable %r\n", Status);

  UINTN NewTableKey = 0;
  Status = AcpiTableProtocol->InstallAcpiTable(
      AcpiTableProtocol,
      NewMadt,
      NewMadtLen,
      &NewTableKey
      );
  Print(L"InstallAcpiTable %r\n", Status);

  gBS->FreePool(NewMadt);
}
