; IBRA ANTIVIRUS - right-click "Scan with IBRA ANTIVIRUS" for files and folders (current user)
!macro customInstall
  WriteRegStr HKCU "Software\Classes\*\shell\IBRAAntivirus" "" "فحص بـ IBRA ANTIVIRUS"
  WriteRegStr HKCU "Software\Classes\*\shell\IBRAAntivirus" "Icon" "$INSTDIR\IBRA ANTIVIRUS.exe,0"
  WriteRegStr HKCU "Software\Classes\*\shell\IBRAAntivirus\command" "" '"$INSTDIR\IBRA ANTIVIRUS.exe" --scan "%1"'
  WriteRegStr HKCU "Software\Classes\Directory\shell\IBRAAntivirus" "" "فحص بـ IBRA ANTIVIRUS"
  WriteRegStr HKCU "Software\Classes\Directory\shell\IBRAAntivirus" "Icon" "$INSTDIR\IBRA ANTIVIRUS.exe,0"
  WriteRegStr HKCU "Software\Classes\Directory\shell\IBRAAntivirus\command" "" '"$INSTDIR\IBRA ANTIVIRUS.exe" --scan "%1"'
  WriteRegStr HKCU "Software\Classes\Drive\shell\IBRAAntivirus" "" "فحص بـ IBRA ANTIVIRUS"
  WriteRegStr HKCU "Software\Classes\Drive\shell\IBRAAntivirus" "Icon" "$INSTDIR\IBRA ANTIVIRUS.exe,0"
  WriteRegStr HKCU "Software\Classes\Drive\shell\IBRAAntivirus\command" "" '"$INSTDIR\IBRA ANTIVIRUS.exe" --scan "%1"'
!macroend

!macro customUnInstall
  DeleteRegKey HKCU "Software\Classes\*\shell\IBRAAntivirus"
  DeleteRegKey HKCU "Software\Classes\Directory\shell\IBRAAntivirus"
  DeleteRegKey HKCU "Software\Classes\Drive\shell\IBRAAntivirus"
!macroend
