/*
  IBRA ANTIVIRUS - YARA rules
  برمجة وتطوير ابراهيم الخزرجي - IBRAPROGRAM
  Each rule has meta severity: high (threat) or medium (suspicious).
*/

rule Ransomware_Behavior_PE
{
  meta:
    severity = "high"
    description = "Executable that deletes shadow copies or disables recovery"
  strings:
    $a1 = "vssadmin delete shadows" nocase ascii wide
    $a2 = "vssadmin.exe delete shadows" nocase ascii wide
    $a3 = "shadowcopy delete" nocase ascii wide
    $b1 = "recoveryenabled no" nocase ascii wide
    $b2 = "bootstatuspolicy ignoreallfailures" nocase ascii wide
    $c1 = "wbadmin delete catalog" nocase ascii wide
    $d1 = "Your files are encrypted" nocase ascii wide
    $d2 = "All your files have been encrypted" nocase ascii wide
    $d3 = "HOW_TO_DECRYPT" nocase ascii wide
    $d4 = "DECRYPT_INSTRUCTIONS" nocase ascii wide
  condition:
    uint16(0) == 0x5A4D and filesize < 30MB and
    ( (1 of ($a*) and 1 of ($b*, $c1)) or (1 of ($a*, $b*, $c1) and 1 of ($d*)) )
}

rule HackTool_Mimikatz
{
  meta:
    severity = "high"
    description = "Mimikatz credential dumping tool"
  strings:
    $s1 = "sekurlsa::logonpasswords" nocase ascii wide
    $s2 = "gentilkiwi" ascii wide
    $s3 = "mimikatz" nocase ascii wide
    $s4 = "kiwi_passwords" ascii wide
    $s5 = "lsadump::sam" nocase ascii wide
  condition:
    filesize < 20MB and 2 of them
}

rule RAT_njRAT
{
  meta:
    severity = "high"
    description = "njRAT / Bladabindi remote access trojan"
  strings:
    $s1 = "|'|'|" wide
    $s2 = "netsh firewall add allowedprogram" wide
    $s3 = "netsh firewall delete allowedprogram" wide
    $s4 = "[ENTER]" wide
    $s5 = "Execute ERROR" wide
    $s6 = "SEE_MASK_NOZONECHECKS" wide
  condition:
    uint16(0) == 0x5A4D and filesize < 5MB and 3 of them
}

rule RAT_DarkComet
{
  meta:
    severity = "high"
    description = "DarkComet remote access trojan"
  strings:
    $s1 = "DC_MUTEX-" ascii wide
    $s2 = "#BOT#OpenUrl" ascii wide
    $s3 = "#BOT#Ping" ascii wide
    $s4 = "DCPERSFWBP" ascii wide
    $s5 = "BTRESULTHTTP Flood" ascii wide
  condition:
    uint16(0) == 0x5A4D and 2 of them
}

rule RAT_Remcos
{
  meta:
    severity = "high"
    description = "Remcos remote access trojan"
  strings:
    $s1 = "Remcos_Mutex_Inj" ascii wide
    $s2 = "Breaking-Security.Net" nocase ascii wide
    $s3 = "remcos" nocase ascii wide
    $s4 = "[Following text has been copied to clipboard:]" ascii wide
    $s5 = "Uploading file to C&C" ascii wide
  condition:
    uint16(0) == 0x5A4D and 2 of them
}

rule RAT_NanoCore
{
  meta:
    severity = "high"
    description = "NanoCore remote access trojan"
  strings:
    $s1 = "NanoCore Client" ascii wide
    $s2 = "NanoCore.ClientPluginHost" ascii wide
    $s3 = "IClientNetworkHost" ascii wide
    $s4 = "PluginCommand" ascii wide
    $s5 = "ClientLoaderForm" ascii wide
  condition:
    uint16(0) == 0x5A4D and 3 of them
}

rule RAT_Quasar
{
  meta:
    severity = "high"
    description = "QuasarRAT remote access trojan"
  strings:
    $s1 = "Quasar.Common" ascii wide
    $s2 = "QuasarRAT" nocase ascii wide
    $s3 = "Quasar.Client" ascii wide
    $s4 = "GetKeyloggerLogsDirectory" ascii wide
    $s5 = "DoShellExecute" ascii wide
  condition:
    uint16(0) == 0x5A4D and 2 of them
}

rule RAT_AsyncRAT
{
  meta:
    severity = "high"
    description = "AsyncRAT / DcRat family"
  strings:
    $s1 = "AsyncClient" ascii wide
    $s2 = "Anti_Analysis" ascii wide
    $s3 = "Pastebin" ascii wide
    $s4 = "DetectSandboxie" ascii wide
    $s5 = "masterKey can not be null or empty." wide
    $s6 = "Plugin.Plugin" wide
  condition:
    uint16(0) == 0x5A4D and filesize < 5MB and 3 of them
}

rule Stealer_Browser_Wallet_Grabber
{
  meta:
    severity = "high"
    description = "Steals saved passwords, cookies, crypto wallets and Telegram sessions"
  strings:
    $b1 = "\\Login Data" ascii wide
    $b2 = "\\Local State" ascii wide
    $b3 = "\\Cookies" ascii wide
    $b4 = "\\Web Data" ascii wide
    $w1 = "wallet.dat" ascii wide
    $w2 = "\\Exodus\\" nocase ascii wide
    $w3 = "Electrum" ascii wide
    $w4 = "MetaMask" nocase ascii wide
    $t1 = "Telegram Desktop\\tdata" nocase ascii wide
    $t2 = "\\discord\\Local Storage\\leveldb" nocase ascii wide
    $x1 = "encrypted_key" ascii wide
    $x2 = "CryptUnprotectData" ascii
  condition:
    uint16(0) == 0x5A4D and filesize < 20MB and
    3 of ($b*) and $x1 and 2 of ($w*, $t*) and $x2
}

rule Stealer_Discord_Token_Grabber
{
  meta:
    severity = "high"
    description = "Discord token grabber"
  strings:
    $p1 = "Local Storage\\leveldb" nocase ascii wide
    $p2 = "discord" nocase ascii wide
    $r1 = /[\w-]{24}\.[\w-]{6}\.[\w-]{27}/ ascii wide
    $r2 = "dQw4w9WgXcQ:" ascii wide
    $h1 = "discord.com/api/webhooks/" nocase ascii wide
    $h2 = "discordapp.com/api/webhooks/" nocase ascii wide
  condition:
    filesize < 25MB and $p1 and $p2 and (1 of ($r*)) and (1 of ($h*))
}

rule Miner_XMRig_Hidden
{
  meta:
    severity = "medium"
    description = "Cryptocurrency miner (uses your CPU/GPU without asking)"
  strings:
    $s1 = "stratum+tcp://" ascii wide
    $s2 = "stratum+ssl://" ascii wide
    $s3 = "--donate-level" ascii wide
    $s4 = "xmrig" nocase ascii wide
    $s5 = "cryptonight" nocase ascii wide
    $s6 = "randomx" nocase ascii wide
  condition:
    filesize < 30MB and 1 of ($s1, $s2) and 2 of ($s3, $s4, $s5, $s6)
}

rule CobaltStrike_Beacon
{
  meta:
    severity = "high"
    description = "Cobalt Strike beacon"
  strings:
    $s1 = "%s as %s\\%s: %d" ascii
    $s2 = "beacon.dll" ascii
    $s3 = "beacon.x64.dll" ascii
    $s4 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
    $s5 = "Started service %s on %s" ascii
    $s6 = "could not spawn %s: %d" ascii
  condition:
    filesize < 10MB and 3 of them
}

rule Webshell_PHP_Generic
{
  meta:
    severity = "high"
    description = "PHP web shell"
  strings:
    $php = "<?php" nocase
    $e1 = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(/ nocase
    $e2 = /(assert|eval|system|passthru|shell_exec|exec)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase
    $e3 = /preg_replace\s*\(\s*['"].{1,10}\/e['"]/ nocase
  condition:
    $php and filesize < 2MB and 1 of ($e*)
}

rule Script_Downloader_Obfuscated
{
  meta:
    severity = "high"
    description = "Script that downloads and runs code from the internet"
  strings:
    $d1 = "DownloadString(" nocase ascii wide
    $d2 = "DownloadFile(" nocase ascii wide
    $d3 = "Invoke-WebRequest" nocase ascii wide
    $d4 = "MSXML2.XMLHTTP" nocase ascii wide
    $x1 = "IEX" ascii wide
    $x2 = "Invoke-Expression" nocase ascii wide
    $x3 = "Start-Process" nocase ascii wide
    $x4 = "WScript.Shell" nocase ascii wide
    $o1 = "FromBase64String" nocase ascii wide
    $o2 = "-WindowStyle Hidden" nocase ascii wide
    $o3 = "-w hidden" nocase ascii wide
    $o4 = "Bypass" ascii wide
  condition:
    uint16(0) != 0x5A4D and filesize < 3MB and 1 of ($d*) and 1 of ($x*) and 2 of ($o*)
}

rule USB_Worm_Shortcut_VBS
{
  meta:
    severity = "high"
    description = "USB shortcut worm (hides your files and spreads by shortcuts)"
  strings:
    $s1 = "CreateShortcut" nocase ascii wide
    $s2 = "attrib +s +h" nocase ascii wide
    $s3 = "DriveType = 1" nocase ascii wide
    $s4 = ".TargetPath" nocase ascii wide
    $s5 = "Scripting.FileSystemObject" nocase ascii wide
    $s6 = "%~d0" ascii wide
  condition:
    filesize < 2MB and $s1 and $s4 and 2 of ($s2, $s3, $s5, $s6)
}

rule Stealer_Crypto_Wallet_Extensions
{
  meta:
    severity = "high"
    description = "Steals crypto wallets from browser extensions (MetaMask, Phantom, Trust, TronLink...)"
  strings:
    $w1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
    $w2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide
    $w3 = "ibnejdfjmmkpcnlpebklmnkoeoihofec" ascii wide
    $w4 = "egjidjbpglichdcondbcbdnbeeppgdph" ascii wide
    $w5 = "hnfanknocfeofbddgcijnmhnfnkdnaad" ascii wide
    $w6 = "fhbohimaelbohpjbbldcngcnapndodjp" ascii wide
    $w7 = "fnjhmkhhmkbjkkabndcnnogagogbneec" ascii wide
    $w8 = "aholpfdialjgjfhomihkjbmgjidlcdno" ascii wide
    $w9 = "mcohilncbfahbmgdjkbpemcciiolgcge" ascii wide
    $w10 = "dmkamcknogkgcdfhhbddcghachkejeap" ascii wide
  condition:
    uint16(0) == 0x5A4D and filesize < 60MB and 5 of them
}

rule Stealer_Telegram_Session
{
  meta:
    severity = "high"
    description = "Copies Telegram Desktop sessions (tdata) together with browser passwords"
  strings:
    $t1 = "Telegram Desktop\\tdata" nocase ascii wide
    $t2 = "key_datas" ascii wide
    $t3 = "D877F783D5D3EF8C" ascii wide
    $b1 = "\\Login Data" ascii wide
    $b2 = "\\Cookies" ascii wide
    $b3 = "\\Network\\Cookies" ascii wide
    $x1 = "encrypted_key" ascii wide
    $x2 = "app_bound_encrypted_key" ascii wide
  condition:
    uint16(0) == 0x5A4D and filesize < 60MB and 2 of ($t*) and 2 of ($b*) and 1 of ($x*)
}

rule Stealer_Chrome_AppBound_Bypass
{
  meta:
    severity = "high"
    description = "Bypasses Chrome's cookie protection (App-Bound Encryption) to steal sessions"
  strings:
    $a1 = "app_bound_encrypted_key" ascii wide
    $a2 = "IElevator" ascii wide
    $a3 = "DecryptData" ascii wide
    $a4 = "--remote-debugging-port" ascii wide
    $a5 = "Network.getAllCookies" ascii wide
    $a6 = "Storage.getCookies" ascii wide
    $b1 = "\\Google\\Chrome\\User Data" nocase ascii wide
  condition:
    uint16(0) == 0x5A4D and filesize < 60MB and $b1 and ($a1 and ($a2 or $a3) or ($a4 and 1 of ($a5, $a6)))
}

rule ClickFix_Payload_Script
{
  meta:
    severity = "high"
    description = "Script from a fake 'I am not a robot' page that downloads and runs malware"
  strings:
    $c1 = /powershell[^\n]{0,80}-w(indowstyle)?\s+h(idden)?[^\n]{0,200}(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|net\.webclient)/ nocase
    $c2 = /mshta(\.exe)?\s+["']?https?:\/\// nocase
    $c3 = /(iwr|irm|invoke-restmethod)\s+["']?https?:\/\/[^\s"']+["']?\s*\|\s*iex/ nocase
    $d1 = "robot" nocase
    $d2 = "captcha" nocase
    $d3 = "verification" nocase
  condition:
    uint16(0) != 0x5A4D and filesize < 2MB and (($c2) or (($c1 or $c3) and 1 of ($d*)))
}
