/*
 * (c) FFRI Security, Inc., 2026 / Author: FFRI Security, Inc.
 */

#define APIC_ID_REG 0x20
#define APIC_ICR_LOW_REG 0x300
#define APIC_ICR_HIGH_REG 0x310
#define APIC_EOI_REG 0xB0

#define MSR_IA32_APIC_BASE         0x0000001B


UINT32 gVector = 0x2000; // SIPI Vector will be located at this phy addr

//
// [Omitted] SIPI Vector (first code to run when SIPI is received)
//   - The actual assembly is written in `SIPI_Vector/sipi-vector.nasm`
//   - Compile sipi-vector.nasm in SIPI_Vector directory and paste that output binary to this C array 
//   - This SIPI Vector will switch CPU mode from real mode to long mode and eventually jumps to SipiEntry function
//   - There are several addresses (`header_***`) that needs to be resolved during boot, and those setup are done
//     inside the SetupISS function
//
BYTE SipiVector[] = {
};
UINTN gSipiVectorAddr = (UINTN)SipiVector;

IA32_DESCRIPTOR gIdtr;

//
// First C function to be executed after receiving SIPI
//   - SIPI Vector will eventually call this function after fundamental setup like
//     transitioning into long mode
//
VOID
SipiEntry(
    )
{
  AsmWriteIdtr(&gIdtr);

  // Poll signal buf 
  while(1) {
    __asm__ __volatile__("cli");

    volatile UINT32* BufPtr = &gShadeCoreStartupSignalBuffer;
    if (*BufPtr == WAKEUP_SHADE_CORE_SIGNAL) {
      *BufPtr = SIGNATURE_32 ('R', 'E', 'C', 'V');
      break;
    }
  }

  // Execute 120 seconds after SendISS in ExitBootServicesHook is called
  //AcpiTimerStall(120000000);

  EFI_STATUS Status = ShadeCoreMain();
  gShadeCoreComBuf.Status = Status;

  __asm__ __volatile__("hlt");
}



//
// Fill `header_***` value of sipi-vector.nasm(SipiVector) and locates SipiVector at gVector
//   - Also prepares stack and IDT for ShadeCore to use
//   - ISS: INIT-SIPI-SIPI
//
VOID
SetupISS(
    )
{
  EFI_STATUS Status;

  // Save current IDT to use it also in ShadeCore
  AsmReadIdtr(&gIdtr);

  EFI_PHYSICAL_ADDRESS ShadeCoreStack = 0;
  UINTN ShadeCoreStackPages = 16; // This is just random
  Status = gBS->AllocatePages(
      AllocateAnyPages,
      EfiRuntimeServicesData,
      ShadeCoreStackPages,   // ShadeCoreStackPages * EFI_PAGE_SIZE(4096)
      &ShadeCoreStack
      );
  Print(L"ShadeCore stack allocation %r\n", Status);

  UINTN ShadeCoreStackTop = (UINTN)ShadeCoreStack + ShadeCoreStackPages*EFI_PAGE_SIZE;
  ShadeCoreStackTop &= ~0xFULL;

  // Setup SipiVector and locates it at address gVector
  CopyMem((VOID*)&SipiVector[0x08], (VOID*)&ShadeCoreStackTop, sizeof(UINTN)); // header_stack
  CopyMem((VOID*)&SipiVector[0x10], (VOID*)&gIdentityCR3, sizeof(UINTN)); // header_cr3
  UINTN SipiEntryAddr = (UINTN)SipiEntry;
  CopyMem((VOID*)&SipiVector[0x18], (VOID*)&SipiEntryAddr, sizeof(UINTN)); // header_entry
  UINT32 GdtOffset = *(UINT32*)(SipiVector+0x22);
  UINT32 GdtAddr = gVector + GdtOffset;
  CopyMem((VOID*)&SipiVector[0x22], (VOID*)&GdtAddr, sizeof(UINT32)); // header_entry
  CopyMem((VOID*)((UINTN)gVector), (VOID*)SipiVector, sizeof(SipiVector));

  Print(L"SipiVector header:\n");
  for(UINTN i=0; i<0x40; i++) {
    if(i%8==0 && i!=0) Print(L"\n");
    Print(L"%02X ", *(BYTE*)(gVector+i));
  }
  Print(L"\n");
}



//
// Get current executing core's APIC ID
//
BYTE
EFIAPI
GetApicId(
    )
{
  UINTN ApicBase = (UINTN)(AsmReadMsr64(MSR_IA32_APIC_BASE) & 0xFFFFF000ULL);
  BYTE ThisApicId = (BYTE)((*(UINT32*)(ApicBase+APIC_ID_REG))>>24);
  return ThisApicId;
}



//
// Send INIT-SIPI-SIPI sequence to the core with specified APIC ID
//   - Starts executing 0xVV000 when Vector=0xVV is given by SIPI
//
VOID
EFIAPI
SendISS (
    IN  BYTE   Vector,
    IN  UINT32 TargetApicId
    )
{
  UINTN ApicBase = (UINTN)(AsmReadMsr64(MSR_IA32_APIC_BASE) & 0xFFFFF000ULL);

  UINT32 IcrHigh = TargetApicId << 24;
  *(UINT32*)(ApicBase + APIC_ICR_HIGH_REG) = IcrHigh;

  // INIT
  UINT32 IcrLow = (UINT32)(
              (0x00 & 0xFF) |      // Vector should be 0 when INIT
              (5 <<  8)     |      // DeliveryMode = 101b (INIT)
              (0 << 11)     |      // Destination Mode = 0 (Physical)
              (0 << 12)     |      // Delivery Status (Read-Only)
              (1 << 14)     |      // Level = 1 (Assert) (Only 0 when INIT Level De-assert Delivery Mode)
              (0 << 15)     |      // Trigger Mode (Ignored when not INIT Level De-assert)
              (0 << 18)            // Destination Shorthand = 0b00 (No Shorthand)
              );
  *(UINT32*)(ApicBase + APIC_ICR_LOW_REG) = IcrLow; // IPI sent when ICR_Low is written
  
  AcpiTimerStall(100);

  IcrLow = (UINT32)(
              (0x00 & 0xFF) |      // Vector should be 0 when INIT
              (5 <<  8)     |      // DeliveryMode = 101b (INIT)
              (0 << 11)     |      // Destination Mode = 0 (Physical)
              (0 << 12)     |      // Delivery Status (Read-Only)
              (0 << 14)     |      // Level = 0 (Deassert) (Only 0 when INIT Level De-assert Delivery Mode)
              (0 << 15)     |      // Trigger Mode (I think 0 is fine)
              (0 << 18)            // Destination Shorthand = 0b00 (No Shorthand)
              );
  *(UINT32*)(ApicBase + APIC_ICR_LOW_REG) = IcrLow; // IPI sent when ICR_Low is written

  AcpiTimerStall(10000);

  // SIPI (1/2)
  IcrLow = (UINT32)(
              (Vector & 0xFF) |      // Vector 0xVV => Start execution at 0xVV000 (CS = 0xVV00)
              (6 <<  8)     |      // DeliveryMode = 110b (Start-Up)
              (0 << 11)     |      // Destination Mode = 0 (Physical)
              (0 << 12)     |      // Delivery Status (Read-Only)
              (1 << 14)     |      // Level = 1 (Only 0 when INIT Level De-assert Delivery Mode)
              (0 << 15)     |      // Trigger Mode (Ignored when not INIT Level De-assert)
              (0 << 18)            // Destination Shorthand = 0b00 (No Shorthand)
              );
  *(UINT32*)(ApicBase + APIC_ICR_LOW_REG) = IcrLow; // IPI sent when ICR_Low is written
                                                    
  AcpiTimerStall(200);

  // SIPI (2/2)
  *(UINT32*)(ApicBase + APIC_ICR_LOW_REG) = IcrLow; // IPI sent when ICR_Low is written
}



//
// NOT USED
//  Use this when you want to send interrupts to the ShadeCore
//
#define SHADE_CORE_VECTOR 2  // NMI
VOID
EFIAPI
SendIPI (
    IN  UINT32  TargetApicId
    )
{
  Print(L"\nSendIPI start\n");
  Print(L"This APIC ID: %d\n", GetApicId());

  UINTN ApicBase = (UINTN)(AsmReadMsr64(MSR_IA32_APIC_BASE) & 0xFFFFF000ULL);

  UINT32 IcrHigh = TargetApicId << 24;
  *(UINT32*)(ApicBase + APIC_ICR_HIGH_REG) = IcrHigh;

  UINT32 IcrLow = (UINT32)(
              (SHADE_CORE_VECTOR & 0xFF) |
              (4 <<  8)     |          // Delivery Mode = 100b NMI (Change to 000b Fixed if not NMI)
              (0 << 11)     |          // Destination Mode = 0 (Physical)
              (0 << 12)     |          // Delivery Status (Read-Only)
              (1 << 14)     |          // Level = 1 (Assert) (Only 0 when INIT Level De-assert Delivery Mode)
              (0 << 15)     |          // Trigger Mode (Ignored when not INIT Level De-assert)
              (0 << 18)                // Destination Shorthand = 0b00 (No Shorthand)
              );
  *(UINT32*)(ApicBase + APIC_ICR_LOW_REG) = IcrLow; // IPI sent when ICR_Low is written
  Print(L"IPI sent ICR_High: 0x%X, ICR_Low: 0x%X\n", IcrHigh, IcrLow);
}



//
// Currently, ShadeCore doesn't support x2APIC mode
//
BOOLEAN
IsX2ApicEnabled(
    )
{
  UINTN ApicBaseRaw = AsmReadMsr64(MSR_IA32_APIC_BASE);
  BOOLEAN IsX2Apic = (ApicBaseRaw>>10)&1;
  return IsX2Apic;
}
