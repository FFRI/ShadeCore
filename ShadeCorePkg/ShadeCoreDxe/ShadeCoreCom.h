/*
 * (c) FFRI Security, Inc., 2026 / Author: FFRI Security, Inc.
 */

#define WAKEUP_SHADE_CORE_SIGNAL  SIGNATURE_32 ('S', 'H', 'A', 'D')

//
// ShadeCore interfaces
//   - Interfaces for communicating between non-ShadeCore<=>ShadeCore
//   - Remember ShadeCore sees physical memory, but non-ShadeCore sees virtual memory
//
__attribute__((aligned(64)))
UINT32 gShadeCoreStartupSignalBuffer = SIGNATURE_32('N','U','L','L');
UINT32* gShadeCoreStartupSignalBufferVirAddr = NULL;

typedef struct {
  UINT32 Signature;       // 'SCCB'
  UINTN HypercallPageGPA; // IN
  UINTN VmcsAddr;         // OUT
  EFI_STATUS Status;      // OUT
  UINT64 Buf;  // OUT
  UINT64 Buf2;  // OUT
  UINT64 Command;
  UINT64 CommandStatus;
  BYTE Buf3[0x100]; // OUT
} SHADE_CORE_COM_BUF;
SHADE_CORE_COM_BUF gShadeCoreComBuf = {0};
SHADE_CORE_COM_BUF* gShadeCoreComBufVirAddr = NULL;



VOID
EFIAPI
InitComBuf(
    )
{
  gShadeCoreStartupSignalBufferVirAddr = &gShadeCoreStartupSignalBuffer;
  gShadeCoreComBufVirAddr = &gShadeCoreComBuf;
  gShadeCoreComBuf.Signature = SIGNATURE_32 ('S', 'C', 'C', 'B');
}
