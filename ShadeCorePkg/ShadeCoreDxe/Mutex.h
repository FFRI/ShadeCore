/*
 * (c) FFRI Security, Inc., 2026 / Author: FFRI Security, Inc.
 */

CHAR16 MutexVarName[0x10] = L"MutexVarCore";
UINTN MutexVarSize = 0x1;
// 8919fd88-2175-416d-8d7c-343abc46e5c7
EFI_GUID MutexVarGuid = \
  { 0x8919fd88, 0x2175, 0x416d, { 0x8d, 0x7c, 0x34, 0x3a, 0xbc, 0x46, 0xe5, 0xc7 }};


/**

  Check if this driver is executed for the first time from power-on
   - return TRUE if this is the first time

**/
BOOLEAN
EFIAPI
CheckMutex (
    )
{
  BOOLEAN isFirstExecution = TRUE;
  EFI_STATUS Status = EFI_SUCCESS;
  BYTE mutex[1] = {0};
  Status = gRT->GetVariable(
      MutexVarName,
      &MutexVarGuid,
      NULL,
      &MutexVarSize,
      (VOID*)&mutex
      );

  if(Status==EFI_NOT_FOUND) {
    mutex[0] = 0x1;
    gRT->SetVariable(
        MutexVarName,
        &MutexVarGuid,
        EFI_VARIABLE_BOOTSERVICE_ACCESS,
        MutexVarSize,
        mutex
        );
  }
  else {
    isFirstExecution = FALSE;
    if(mutex[0] < 0xFF)
      mutex[0] += 1;
    gRT->SetVariable(
        MutexVarName,
        &MutexVarGuid,
        EFI_VARIABLE_BOOTSERVICE_ACCESS,
        MutexVarSize,
        mutex
        );
  }

  return isFirstExecution;
}
