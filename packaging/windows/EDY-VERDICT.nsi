Unicode true
RequestExecutionLevel user
SetCompressor /SOLID lzma
Name "EDY VERDICT"
OutFile "${OUTPUT_FILE}"
InstallDir "$LOCALAPPDATA\Programs\EDY VERDICT"
ShowInstDetails show
ShowUninstDetails show
!include "MUI2.nsh"
!include "LogicLib.nsh"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "PortugueseBR"
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" "CurrentBuildNumber"
  IntCmp $0 19045 supported unsupported supported
  unsupported:
    MessageBox MB_ICONSTOP "EDY VERDICT requer Windows 10 Pro 22H2 x64 build 19045 ou posterior."
    Abort
  supported:
FunctionEnd

Section "EDY VERDICT" SEC_MAIN
  SetOutPath "$INSTDIR"
  File "/oname=EDY VERDICT.exe" "${PRODUCT_EXE}"
  File "${PROJECT_ROOT}\README.md"
  File "${PROJECT_ROOT}\SECURITY.md"
  File "${PROJECT_ROOT}\PRIVACY.md"
  File "${PROJECT_ROOT}\THIRD_PARTY_NOTICES.md"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\EDY VERDICT"
  CreateShortcut "$SMPROGRAMS\EDY VERDICT\EDY VERDICT.lnk" "$INSTDIR\EDY VERDICT.exe"
  CreateShortcut "$SMPROGRAMS\EDY VERDICT\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\EDY VERDICT" "DisplayName" "EDY VERDICT"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\EDY VERDICT" "DisplayVersion" "1.0.0-rc.1"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\EDY VERDICT" "UninstallString" '"$INSTDIR\Uninstall.exe"'
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\EDY VERDICT.exe"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\SECURITY.md"
  Delete "$INSTDIR\PRIVACY.md"
  Delete "$INSTDIR\THIRD_PARTY_NOTICES.md"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\EDY VERDICT\EDY VERDICT.lnk"
  Delete "$SMPROGRAMS\EDY VERDICT\Uninstall.lnk"
  RMDir "$SMPROGRAMS\EDY VERDICT"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\EDY VERDICT"
SectionEnd
