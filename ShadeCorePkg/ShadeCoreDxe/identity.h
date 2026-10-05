/*
 * (c) FFRI Security, Inc., 2026 / Author: FFRI Security, Inc.
 */

UINT64 gIdentityCR3;




/**

  Prepare identity map page tables (call this during boot)

**/
VOID
MakeIdentityPageTable (
    )
{
  // PML4 size = 8 Bytes (PML4E size) * 512 PML4Es = 4096(1 page size)
  //  Use AllocatePages to 4KB align the address
  EFI_PHYSICAL_ADDRESS pml4;   // pml4[512]
  gBS->AllocatePages(
      AllocateAnyPages,
      EfiRuntimeServicesCode,
      1,
      &pml4
      );

  EFI_PHYSICAL_ADDRESS pdp;   // pdp[512]
  gBS->AllocatePages(
      AllocateAnyPages,
      EfiRuntimeServicesCode,
      2,
      &pdp
      );

  // 1 PD contains 512 2MB pages (= can describe 1GB of phyical address)
  // => we need 64 PD
  // * Looks like some BIOS uses virtual address(?) so prepare 512 PD
  EFI_PHYSICAL_ADDRESS pd;   // ~~pd[64][512]~~ => pd[512][512]
  gBS->AllocatePages(
      AllocateAnyPages,
      EfiRuntimeServicesCode,
      512,  // 64
      &pd
      );

  // link page tables
  *(UINT64*)pml4 = (UINT64)pdp | 0x003;
  //for(UINT64 i=0; i<64; i++) {
  for(UINT64 i=0; i<512; i++) {
    *(UINT64*)(pdp+i*8) = ((UINT64)pd + i*8*512) | 0x003;
    for(UINT64 j=0; j<512; j++)
      *(UINT64*)(pd + i*8*512 + j*8) = (i*(UINT64)SIZE_1GB + j*(UINT64)SIZE_2MB) | 0x083;
  }

  gIdentityCR3 = (UINT64)pml4;
}
