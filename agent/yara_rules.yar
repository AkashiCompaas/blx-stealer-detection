rule BLX_Stealer_rule {
    
    meta:
        description = "Detects BLX Stealer malware"
        author = "Wazuh"
        date = "2024-11-01"
        reference = "https://www.cyfirma.com/research/blx-stealer/"
        
    
    strings:
        $str0 = { 20 20 20 20 70 6f 6c 69 63 79 2e 6d 61 6e 69 66 65 73 74 2e 61 73 73 65 72 74 49 6e 74 65 67 72 69 74 79 28 6d 6f 64 75 6c 65 55 52 4c 2c 20 63 6f 6e 74 65 6e 74 29 3b }
        $str1 = { 20 20 41 72 72 61 79 50 72 6f 74 6f 74 79 70 65 53 68 69 66 74 2c }
        $str2 = { 20 20 69 66 20 28 21 73 74 61 74 65 2e 6b 65 65 70 41 6c 69 76 65 54 69 6d 65 6f 75 74 53 65 74 29 }
        $str3 = { 20 20 72 65 74 75 72 6e 20 72 65 71 75 69 72 65 28 27 74 6c 73 27 29 2e 44 45 46 41 55 4c 54 5f 43 49 50 48 45 52 53 3b }
        $str4 = { 21 47 7e 79 5f 3b }
        $str5 = { 3f 52 65 64 75 63 65 53 74 61 72 74 40 42 72 61 6e 63 68 45 6c 69 6d 69 6e 61 74 69 6f 6e 40 63 6f 6d 70 69 6c 65 72 40 69 6e 74 65 72 6e 61 6c 40 76 38 40 40 41 45 41 41 3f 41 56 52 65 64 75 63 74 69 6f 6e 40 32 33 34 40 50 45 41 56 4e 6f 64 65 40 32 33 34 40 40 5a }
        $str6 = { 40 55 56 57 48 }
        $str7 = { 41 49 5f 41 44 44 52 43 4f 4e 46 49 47 }
        $str8 = { 44 24 70 48 }
        $str9 = { 45 56 50 5f 4d 44 5f 43 54 58 5f 73 65 74 5f 75 70 64 61 74 65 5f 66 6e }
        $str10 = { 46 61 69 6c 65 64 20 74 6f 20 64 65 73 65 72 69 61 6c 69 7a 65 20 64 6f 6e 65 5f 73 74 72 69 6e 67 }
        $str11 = { 49 63 4f 70 }
        $str12 = { 54 24 48 48 }
        $str13 = { 5c 24 30 48 }
        $str14 = { 5c 24 58 48 }
        $str15 = { 64 24 40 48 }
        $str16 = { 67 65 74 73 6f 63 6b 6f 70 74 }
        $str17 = { 73 74 72 65 73 73 20 74 68 65 20 47 43 20 63 6f 6d 70 61 63 74 6f 72 20 74 6f 20 66 6c 75 73 68 20 6f 75 74 20 62 75 67 73 20 28 69 6d 70 6c 69 65 73 20 2d 2d 66 6f 72 63 65 5f 6d 61 72 6b 69 6e 67 5f 64 65 71 75 65 5f 6f 76 65 72 66 6c 6f 77 73 29 }
        $str18 = { 74 24 38 48 }
        $str19 = { 74 24 60 48 }
        
        $blx_stealer_network = "https://api.ipify.org" ascii wide nocase
        $blx_stealer_network1 = "https://geolocation-db.com" ascii wide nocase
        $blx_stealer_network2 = "https://discord.com/api/webhooks" ascii wide nocase
        
        $blx_stealer_hash1 = "8c4daf5e4ced10c3b7fd7c17c7c75a158f08867aeb6bccab6da116affa424a89"
        $blx_stealer_hash2 = "e74dac040ec85d4812b479647e11c3382ca22d6512541e8b42cf8f9fbc7b4af6"
        $blx_stealer_hash3 = "32abb4c0a362618d783c2e6ee2efb4ffe59a2a1000dadc1a6c6da95146c52881"
        $blx_stealer_hash4 = "5b46be0364d317ccd66df41bea068962d3aae032ec0c8547613ae2301efa75d6"

    condition:
        (all of ($str*) or any of ($blx_stealer_network*) or any of ($blx_stealer_hash*))

}
rule MintStealer
{
meta:
        Author = "Benjamin Nworah"
        Description = "Detect Mint Stealer malware"
        Date = "13-09-2024"
        Hash1 = "1064ab9e734628e74c580c5aba71e4660ee3ed68db71f6aa81e30f148a5080fa" // SHA-256 Hash
        Hash2 = "cc93a4627a459d505c46de6fac342f856fb8f95b6a4fdcbd5e48be59aa4cbb7b" // SHA-256 Hash

    strings:
        $a1 = "FindResource"
        $a2 = "GetSystemTimeAsFileTime"
        $a3 = /NUITKA.{1,15}/
     
    condition:
        all of ($a*)
}
rule Daolpu_infostealer 
{
    meta:
        Author = "Benjamin Nworah"
        Description = "Detect Daolpu malware"
        Date = "16-08-2024"
        Hash1 = "3a9323a939fbecbc6d0ceb5c1e1f3ebde91e9f186b46fdf3ba1aee03d1d41cd8"
        Hash2 = "4ad9845e691dd415420e0c253ba452772495c0b971f48294b54631e79a22644a"

    strings:
        $a1 = "D:\\c++\\Mal_Cookie_x64\\x64\\Release\\mscorsvc.pdb"
        $a2 = "C:\\Windows\\Temp\\result.txt"
     
    condition:
        all of ($a*)
}
rule njRAT {

    meta:
        author                      = "Adedamola Okelola"
        date                        = "2023-08-10"
        description                 = "njRAT executable detection"
        threat_name                 = "Windows.Trojan.njRAT"
        tlp                         = "TLP:WHITE"
        operating_system            = "windows"
        version                     = "v1.0"

    strings:
        $a1  = { 24 65 66 65 39 65 61 64 63 2D 64 34 61 65 2D 34 62 39 65 2D 62 38 61 62 2D 37 65 34 37 66 38 64 62 36 61 63 39 }
        $a2  = "get_Registry" ascii fullword
        $a3  = "SEE_MASK_NOZONECHECKS" wide fullword
        $a4  = "Execute ERROR" wide fullword
        $a5  = "Download ERROR" wide fullword
        $a6  = "[k1]" wide fullword
        $a7  = "cmd.exe /c ping 0 -n 2 & del \"" wide fullword
        $a8  = "netsh firewall add allowedprogram \"" wide fullword
        $a9  = "[+] System : " wide fullword
        $a10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide

    condition:
        5 of them
}
rule Wazuh_Meduza
{
    meta:
    malware_name = "Meduza"
    description = "Meduza is a trojan stealer that gathers sensitive data such as browser cookies, histories, crypto wallet information, and more from infected machines."
    author = "Iseoluwa Titiloye Oyeniyi"
    version = "1"
 
    strings:

    $x1 = "autofill-profiles.json"  ascii wide
    $x2 = "formhistory.sqlite"  ascii wide
    $x3 = "logins.json"  ascii wide
    $x4 = "cookies.sqlite"  ascii wide
    $x5 = "key4.db"  ascii wide
    $x6 = "Electrum\\config"  ascii wide
    $x7 = "Sparrow\\wallets"  ascii wide
    $x8 = "Coinomi\\wallets"  ascii wide
    $x9 = "Electrum-LTC\\wallets"  ascii wide
    $x10 = "Mozilla\\SeaMonkey"  ascii wide
    $x11 = "Yandex\\YandexBrowser"  ascii wide
    $x12 = "BrowserPass"  ascii wide
    $x13 = "`anonymous namespace'"  ascii wide
    $x14 = "api-ms-"  ascii wide
    $x15 = "FlsAlloc"  ascii wide
    $x16 = "mscoree.dll"  ascii wide
    $x17 = "AppPolicyGetProcessTerminationMethod"  ascii wide
 
    condition:
    3 of ( $x* )
}
rule  Remcos_RAT 
{
    meta:
        Author = "Benjamin Nworah"
        Description = "Detect Remcos RAT"
        Reference =  "Personal Research"
        Date = "27-09-2022"
        Hash1 = "bcca157ab3520b1104411e86ea78f6a2efbb58ef"
        Hash2 = "8d3c6c8e83275a60401a152797e7b158ea808413"
    strings:
        $a1 = "Olympianize3.exe"  wide nocase
        $a2 = "target_pid" ascii
        $a3 = "VS_VERSION_INFO" wide
        $a4 = {45 56 45 4E 54 5F 53 49 4E 4B 5F 41 64 64 52 65 66 00 15 00 45 56 45 4E 54 5F 53 
               49 4E 4B 5F 52 65 6C 65 61 73 65 00 00 14 00 45 56 45 4E 54 5F 53 49 4E 4B 5F 51 
               75 65 72 79 49 6E 74 65 72 66 61 63 65 00 8E 00 5F 5F 76 62 61 45 78 63 65 70 74 
               48 61 6E 64 6C 65 72}
        $a5 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB"
        $b1 = "Software\\Microsoft\\Windows\\CurrentVersion"
        $b2 = "SearchPath" 
        $b3 = "RegCreateKeyEx"
        $b4 = "WritePrivateProfileString"
        $b5 = "MoveFile"
        $b6 = "CreateFile"
        $b7 = "GetTempFileName"
        $b8 = "LookupPrivilegeValue"
        $b9 = {52 65 67 44 65 6C 65 74 65 4B 65 79 45 78}
    condition:
        all of ($a*) or all of ($b*)
}     
rule REMCOS_RAT_variants
{
    meta:
        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-07-18"
        Description = "Detects multiple variants of REMCOS seen in the wild."
    strings:
        $funcs1 = "autogetofflinelogs" ascii fullword
        $funcs2 = "clearlogins" ascii fullword
        $funcs3 = "getofflinelogs" ascii fullword
        $funcs4 = "execcom" ascii fullword
        $funcs5 = "deletekeylog" ascii fullword
        $funcs6 = "remscriptexecd" ascii fullword
        $funcs7 = "getwindows" ascii fullword
        $funcs8 = "fundlldata" ascii fullword
        $funcs9 = "getfunlib" ascii fullword
        $funcs10 = "autofflinelogs" ascii fullword
        $funcs11 = "getclipboard" ascii fullword
        $funcs12 = "getscrslist" ascii fullword
        $funcs13 = "offlinelogs" ascii fullword
        $funcs14 = "getcamsingleframe" ascii fullword
        $funcs15 = "listfiles" ascii fullword
        $funcs16 = "getproclist" ascii fullword
        $funcs17 = "onlinelogs" ascii fullword
        $funcs18 = "getdrives" ascii fullword
        $funcs19 = "remscriptsuccess" ascii fullword
        $funcs20 = "getcamframe" ascii fullword
        $str_a1 = "C:\\Windows\\System32\\cmd.exe" ascii fullword
        $str_a2 = "C:\\WINDOWS\\system32\\userinit.exe" ascii fullword
        $str_a3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
        $str_a4 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
        $str_a5 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii fullword
        $str_b1 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" wide fullword
        $str_b2 = "Executing file: " ascii fullword
        $str_b3 = "GetDirectListeningPort" ascii fullword
        $str_b4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" wide fullword
        $str_b5 = "licence_code.txt" ascii fullword
        $str_b6 = "\\restart.vbs" wide fullword
        $str_b7 = "\\update.vbs" wide fullword
        $str_b8 = "\\uninstall.vbs" wide fullword
        $str_b9 = "Downloaded file: " ascii fullword
        $str_b10 = "Downloading file: " ascii fullword
        $str_b11 = "KeepAlive Enabled! Timeout: %i seconds" ascii fullword
        $str_b12 = "Failed to upload file: " ascii fullword
        $str_b13 = "StartForward" ascii fullword
        $str_b14 = "StopForward" ascii fullword
        $str_b15 = "fso.DeleteFile \"" wide fullword
        $str_b16 = "On Error Resume Next" wide fullword
        $str_b17 = "fso.DeleteFolder \"" wide fullword
        $str_b18 = "Uploaded file: " ascii fullword
        $str_b19 = "Unable to delete: " ascii fullword
        $str_b20 = "while fso.FileExists(\"" wide fullword
        $str_c0 = "[Firefox StoredLogins not found]" ascii fullword
        $str_c1 = "Software\\Classes\\mscfile\\shell\\open\\command" ascii fullword
        $str_c2 = "[Chrome StoredLogins found, cleared!]" ascii fullword
        $str_c3 = "[Chrome StoredLogins not found]" ascii fullword
        $str_c4 = "[Firefox StoredLogins cleared!]" ascii fullword
        $str_c5 = "Remcos_Mutex_Inj" ascii fullword
        $str_c6 = "\\logins.json" ascii fullword
        $str_c7 = "[Chrome Cookies found, cleared!]" ascii fullword
        $str_c8 = "[Firefox Cookies not found]" ascii fullword
        $str_c9 = "[Chrome Cookies not found]" ascii fullword
        $str_c10 = "[Firefox cookies found, cleared!]" ascii fullword
        $str_c11 = "mscfile\\shell\\open\\command" ascii fullword
        $str_c12 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" ascii fullword
        $str_c13 = "eventvwr.exe" ascii fullword
    condition:
        uint16(0) == 0x5a4d and filesize < 600KB
        and
        (
            ((8 of ($funcs*)) or all of ($funcs*))
            or
            ((1 of ($str_a*) and 4 of them) or all of ($str_a*))
            or
            ((8 of ($str_b*)) or all of ($str_b*))
            or
            all of ($str_c*)
         )
}
import "console"

rule RANSOM_Lockbit_Black_Packer : Ransomware {

   meta:
      author = "SECUINFRA Falcon Team"
      description = "Detects the packer used by Lockbit Black (Version 3)"
      reference = "https://twitter.com/vxunderground/status/1543661557883740161"
      date = "2022-07-04"
      tlp = "WHITE"
      yarahub_uuid = "de99eca0-9502-4942-a30a-b3f9303953e3"
      yarahub_reference_md5 = "38745539b71cf201bb502437f891d799"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      yarahub_author_twitter = "@SI_FalconTeam"
      hash0 = "80e8defa5377018b093b5b90de0f2957f7062144c83a09a56bba1fe4eda932ce"
      hash1 = "506f3b12853375a1fbbf85c82ddf13341cf941c5acd4a39a51d6addf145a7a51"
      hash2 = "d61af007f6c792b8fb6c677143b7d0e2533394e28c50737588e40da475c040ee"

   strings:
      $sectionname0 = ".rdata$zzzdbg" ascii
      $sectionname1 = ".xyz" ascii fullword
      
      // hash checks
      $check0 = {3d 75 80 91 76 ?? ?? 3d 1b a4 04 00 ?? ?? 3d 9b b4 84 0b}
      $check1 = {3d 75 ba 0e 64}
      
      // hex/ascii calculations
      $asciiCalc = {66 83 f8 41 ?? ?? 66 83 f8 46 ?? ?? 66 83 e8 37}
      
   condition:
      uint16(0) == 0x5a4d
      and filesize > 111KB // Size on Disk/1.5
      and filesize < 270KB // Size of Image*1.5
      and all of ($sectionname*)
      and any of ($check*)
      and $asciiCalc
      and for any i in (0..pe.number_of_sections - 1): 
      (math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.9
      and (pe.sections[i].name == ".text" or pe.sections[i].name == ".data" or pe.sections[i].name == ".pdata")//)
      // console requires Yara 4.2.0. For older versions uncomment closing bracket above und comment out the line below
      and console.log("High Entropy section found:", pe.sections[i].name))
}

rule _Blackbit_ransomware {
   meta:
      description = "Blackbit executable detection"
      author = "Anthony Faruna"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-21"
      hash1 = "1d2db070008116a7a1992ed7dad7e7f26a0bfee3499338c3e603161e3f18db2f"
      hash2 = "2f22f39ec1b30fbe3d5e6184378ef686de2038d12d98229f5bb14cf10653ea21"
   strings:
      $s1 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s2 = "<assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s3 = "Type Descriptor'" fullword ascii
      $s4 = "constructor or from DllMain." fullword ascii
      $s5 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii
      $s6 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii
      $s7 = "Base Class Descriptor at (" fullword ascii
      $s8 = "Class Hierarchy Descriptor'" fullword ascii
      $s9 = "Complete Object Locator'" fullword ascii
      $s10 = "<requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s11 = "svchost" fullword wide /* Goodware String - occurred 17 times */
      $s12 = "Broken pipe" fullword ascii /* Goodware String - occurred 742 times */
      $s13 = "Permission denied" fullword ascii /* Goodware String - occurred 823 times */
      $s14 = "D$<RSP" fullword ascii /* Goodware String - occurred 1 times */
      $s15 = "delete[]" fullword ascii
      $s16 = "</trustInfo>" fullword ascii
      $s17 = "T$h9T$" fullword ascii /* Goodware String - occurred 1 times */
      $s18 = "L$PQSV" fullword ascii /* Goodware String - occurred 1 times */
      $s19 = "B|BxBtBpBlBhBdB`B\\BXBTBPBLBHBDB@B<B8B4B0B,B(B$B B" fullword wide
      $s20 = "ForceRemove" fullword ascii /* Goodware String - occurred 1167 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}
