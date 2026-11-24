; IBRA ANTIVIRUS installer additions
;  - installed for all users in Program Files (normal programs cannot change or delete its files)
;  - the behaviour guard runs as a SYSTEM task from boot (normal programs cannot stop it)
;  - right-click "Scan with IBRA ANTIVIRUS" for files, folders and drives
!macro customInit
  nsExec::Exec 'schtasks /end /tn "IBRA ANTIVIRUS Guard"'
  Pop $0
  nsExec::Exec 'taskkill /f /im ibra-guard.exe'
  Pop $0
!macroend

!macro customInstall
  ; 1.5.x and older were installed only for this user: remove that copy (settings and quarantine are kept)
  ReadEnvStr $0 LOCALAPPDATA
  StrCpy $1 "$0\Programs\IBRA ANTIVIRUS"
  ${If} $1 != $INSTDIR
    ${If} ${FileExists} "$1\*.*"
      nsExec::Exec 'taskkill /f /im "IBRA ANTIVIRUS.exe"'
      Pop $2
      ${If} ${FileExists} "$1\Uninstall IBRA ANTIVIRUS.exe"
        ExecWait '"$1\Uninstall IBRA ANTIVIRUS.exe" /S /currentuser _?=$1' $2
      ${EndIf}
      RMDir /r "$1"
      FileOpen $3 "$TEMP\ibra-install.log" w
      FileWrite $3 "old=$1 uninstall-exit=$2"
      FileClose $3
      DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}"
    ${EndIf}
  ${EndIf}

  ; behaviour guard as a SYSTEM task
  nsExec::Exec 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\scripts\guard-task.ps1" -Exe "$INSTDIR\resources\vendor\ibra-guard.exe"'
  Pop $0

  DeleteRegKey HKCU "Software\Classes\*\shell\IBRAAntivirus"
  DeleteRegKey HKCU "Software\Classes\Directory\shell\IBRAAntivirus"
  DeleteRegKey HKCU "Software\Classes\Drive\shell\IBRAAntivirus"
  WriteRegStr HKLM "Software\Classes\*\shell\IBRAAntivirus" "" "فحص بـ IBRA ANTIVIRUS"
  WriteRegStr HKLM "Software\Classes\*\shell\IBRAAntivirus" "Icon" "$INSTDIR\IBRA ANTIVIRUS.exe,0"
  WriteRegStr HKLM "Software\Classes\*\shell\IBRAAntivirus\command" "" '"$INSTDIR\IBRA ANTIVIRUS.exe" --scan "%1"'
  WriteRegStr HKLM "Software\Classes\Directory\shell\IBRAAntivirus" "" "فحص بـ IBRA ANTIVIRUS"
  WriteRegStr HKLM "Software\Classes\Directory\shell\IBRAAntivirus" "Icon" "$INSTDIR\IBRA ANTIVIRUS.exe,0"
  WriteRegStr HKLM "Software\Classes\Directory\shell\IBRAAntivirus\command" "" '"$INSTDIR\IBRA ANTIVIRUS.exe" --scan "%1"'
  WriteRegStr HKLM "Software\Classes\Drive\shell\IBRAAntivirus" "" "فحص بـ IBRA ANTIVIRUS"
  WriteRegStr HKLM "Software\Classes\Drive\shell\IBRAAntivirus" "Icon" "$INSTDIR\IBRA ANTIVIRUS.exe,0"
  WriteRegStr HKLM "Software\Classes\Drive\shell\IBRAAntivirus\command" "" '"$INSTDIR\IBRA ANTIVIRUS.exe" --scan "%1"'
!macroend

!macro customUnInstall
  nsExec::Exec 'schtasks /end /tn "IBRA ANTIVIRUS Guard"'
  Pop $0
  nsExec::Exec 'schtasks /delete /tn "IBRA ANTIVIRUS Guard" /f'
  Pop $0
  nsExec::Exec 'taskkill /f /im ibra-guard.exe'
  Pop $0
  DeleteRegKey HKLM "Software\Classes\*\shell\IBRAAntivirus"
  DeleteRegKey HKLM "Software\Classes\Directory\shell\IBRAAntivirus"
  DeleteRegKey HKLM "Software\Classes\Drive\shell\IBRAAntivirus"
  DeleteRegKey HKCU "Software\Classes\*\shell\IBRAAntivirus"
  DeleteRegKey HKCU "Software\Classes\Directory\shell\IBRAAntivirus"
  DeleteRegKey HKCU "Software\Classes\Drive\shell\IBRAAntivirus"
!macroend
