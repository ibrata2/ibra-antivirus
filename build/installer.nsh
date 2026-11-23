; IBRA ANTIVIRUS - right-click "Scan with IBRA ANTIVIRUS" for files and folders (current user)
; stop the elevated behaviour guard so its file can be replaced (it restarts by itself within 5 minutes)
!macro customInit
  nsExec::Exec 'taskkill /f /im ibra-guard.exe'
  Pop $0
!macroend

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
  nsExec::Exec 'schtasks /delete /tn "IBRA ANTIVIRUS Guard" /f'
  Pop $0
  nsExec::Exec 'taskkill /f /im ibra-guard.exe'
  Pop $0
  DeleteRegKey HKCU "Software\Classes\*\shell\IBRAAntivirus"
  DeleteRegKey HKCU "Software\Classes\Directory\shell\IBRAAntivirus"
  DeleteRegKey HKCU "Software\Classes\Drive\shell\IBRAAntivirus"
!macroend
