/*
 * (c) FFRI Security, Inc., 2026 / Author: FFRI Security, Inc.
 */

UINT32 gAcpiPmTimerPort;
UINT32 gAcpiPmTimerMask;

// 
// ACPI PM Timer especially to use in Runtime
//   - Since gBS->Stall() cannot be used after OS boot
//
VOID
EFIAPI
AcpiTimerStall(
    IN UINT32 Microseconds
    )
{
  const UINT64 TICKS_PER_SEC = 3579545ULL;
  const UINT64 US_PER_SEC    = 1000000ULL;

  UINT64 targetTicks = (UINT64)Microseconds * TICKS_PER_SEC / US_PER_SEC;
  UINT32 prev = IoRead32(gAcpiPmTimerPort) & gAcpiPmTimerMask;
  UINT64 elapsed = 0;

  while (elapsed < targetTicks) {
    UINT32 cur = IoRead32(gAcpiPmTimerPort) & gAcpiPmTimerMask;
    UINT32 delta = (cur - prev) & gAcpiPmTimerMask;
    elapsed += (UINT64)delta;
    prev = cur;
    __asm__ __volatile__("pause");
  }
}



// 
// Call this during boot to use AcpiTimerStall function
//   - gAcpiPmTimerPort, gAcpiPmTimerMask are initialized by this
//   - Uses AcpiSdtProtocol to locate FADT and locate ACPI PM Timer I/O port
//
VOID
EFIAPI
InitAcpiPmTimer(
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

  // 1: Find FADT
  for(int i=0; ; i++) {
    Status = AcpiSdtProtocol->GetAcpiTable(
        i,
        (EFI_ACPI_SDT_HEADER**)&Table,
        (EFI_ACPI_TABLE_VERSION*)&TableVer,
        &TableKey
        );

    if(Table->Signature == SIGNATURE_32('F','A','C','P')) { // FADT
      Print(L"FADT found!\n");
      Print(L"ACPI Table version %x\n", TableVer);
      break;
    }
  }

  // 2: Locate ACPI PM Timer I/O port
  EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE *Fadt =
        (EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE *)Table;
  gAcpiPmTimerPort = Fadt->PmTmrBlk;

  BOOLEAN Is32Bit = (Fadt->Flags & EFI_ACPI_3_0_TMR_VAL_EXT);
  gAcpiPmTimerMask = Is32Bit ? 0xFFFFFFFF : 0x00FFFFFF;
}
