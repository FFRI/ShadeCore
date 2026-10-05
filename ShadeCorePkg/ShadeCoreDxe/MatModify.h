/*
 * (c) FFRI Security, Inc., 2026 / Author: FFRI Security, Inc.
 */

typedef struct {
  UINT32    Version;
  UINT32    NumberOfEntries;
  UINT32    DescriptorSize;
  UINT32    Flags;
  // EFI_MEMORY_DESCRIPTOR Entry[1];
} EFI_MEMORY_ATTRIBUTES_TABLE;



//
// [Omitted] Locate MAT from gST->ConfigurationTable
//
EFI_MEMORY_ATTRIBUTES_TABLE*
EFIAPI
GetMat(
    )
{
  // Locate MAT from gST->ConfigurationTable by gEfiMemoryAttributesTableGuid
  return NULL;
}



//
// [Omitted] Modify MAT (Memory Attributes Table) to bypass HVCI
//   - Runtime DXE driver loaded in BDS phase (via UEFI Shell, ESP, etc) are not
//     recognized by MAT because MAT is constructed at EndOfDxe/ReadyToBoot
//   - It is necessary to manually add the entry otherwise the runtime DXE driver's
//     UEFI runtime services hook will be rejected by HVCI during runtime
//     (EPT is constructed referring to the MAT)
//
VOID
EFIAPI
ModifyMAT(
    IN  EFI_HANDLE  ImageHandle
    )
{
  // 1: Calculate this PE image .text and .data section base and size
  // 2: Split the MAT descriptor covering this module and insert
  //    .text (RUNTIME|RO) and .data (RUNTIME|XP) entries to bypass HVCI :)
  // 3: Install the modified MAT
  return;
}
