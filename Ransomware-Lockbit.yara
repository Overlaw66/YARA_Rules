import "pe"

rule Lockbit_Unpacked
{

  meta:
         Author = "Andrew McCabe"
         Description = "Rule to identify semi unpacked Lockbit Malware Strains"
         Date_Created = "29-08-2022"    
         Mal_Type = "Ransomware"
         Detection = "Tight - very little variation, V2 will account for modifiers"
         Version = "1.0"
         Sample_md5 = "AFD5D656A42A746E95926EF07933F054"
                  
         
  
 strings: 

	  //Section for any sample references that can only be represented in HEX or better represented in this form.
	  
	  //Restore-My-Files.txt
	  $hex1 = {52 65 73 74 6F 72 65 2D 4D 79 2D 46 69 6C 65 73 2E 74 78 74}
	  
	  // /vssadmin delete shadows /all /quiet & wmic shadowcopy delete & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no & wbadmin delete catalog -quiet
	  $hex2 = {2F 63 20 76 73 73 61 64 6D 69 6E 20 64 65 6C 65 74 65 20 73 68 61 64 6F 77 73 20 2F 61 6C 6C 20 2F 71 75 69 65 74 20 26 20 77 6D 69 63 20 73 68 61 64 6F 77 63 6F 70 79 20 64 65 6C 65 74 65 20 26 20 62 63 64 65 64 69 74 20 2F 73 65 74 20 7B 64 65 66 61 75 6C 74 7D 20 62 6F 6F 74 73 74 61 74 75 73 70 6F 6C 69 63 79 20 69 67 6E 6F 72 65 61 6C 6C 66 61 69 6C 75 72 65 73 20 26 20 62 63 64 65 64 69 74 20 2F 73 65 74 20 7B 64 65 66 61 75 6C 74 7D 20 72 65 63 6F 76 65 72 79 65 6E 61 62 6C 65 64 20 6E 6F 20 26 20 77 62 61 64 6D 69 6E 20 64 65 6C 65 74 65 20 63 61 74 61 6C 6F 67 20 2D 71 75 69 65 74}
      
	  // /c vssadmin Delete Shadows /All /Quiet
	  $hex3 = {2F 63 20 76 73 73 61 64 6D 69 6E 20 44 65 6C 65 74 65 20 53 68 61 64 6F 77 73 20 2F 41 6C 6C 20 2F 51 75 69 65 74}
	  
	  // /c wbadmin DELETE SYSTEMSTATEBACKUP
	  $hex4 = {2F 63 20 77 62 61 64 6D 69 6E 20 44 45 4C 45 54 45 20 53 59 53 54 45 4D 53 54 41 54 45 42 41 43 4B 55 50}
	  
	  // /c wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest
	  $hex5 = {2F 63 20 77 62 61 64 6D 69 6E 20 44 45 4C 45 54 45 20 53 59 53 54 45 4D 53 54 41 54 45 42 41 43 4B 55 50 20 2D 64 65 6C 65 74 65 4F 6C 64 65 73 74}
	  
	  // Volume Shadow Copy & Event log clean
	  $hex6 = {56 6F 6C 75 6D 65 20 53 68 61 64 6F 77 20 43 6F 70 79 20 26 20 45 76 65 6E 74 20 6C 6F 67 20 63 6C 65 61 6E}
	  
	  // badmin DELETE SYSTEMSTATEBACKUP
	  $hex7 = {62 61 64 6D 69 6E 20 44 45 4C 45 54 45 20 53 59 53 54 45 4D 53 54 41 54 45 42 41 43 4B 55 50}
	  
	  // wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest
	  $hex8 = {77 62 61 64 6D 69 6E 20 44 45 4C 45 54 45 20 53 59 53 54 45 4D 53 54 41 54 45 42 41 43 4B 55 50 20 2D 64 65 6C 65 74 65 4F 6C 64 65 73 74}
	  
	  // http://lockbitks2tvnmwk.onion/
	  $hex9 = {68 74 74 70 3A 2F 2F 6C 6F 63 6B 62 69 74 6B 73 32 74 76 6E 6D 77 6B 2E 6F 6E 69 6F 6E}
	  
	  // tor browser
	  $hex10 = {54 6F 72 20 42 72 6F 77 73 65 72}
	  
	  // SOFTWARE\LockBit
	  $hex11 = {53 4F 46 54 57 41 52 45 5C 4C 6F 63 6B 42 69 74}
	  
	  
      
	  //Random String Section but unique to analysed samples.
	  
	  
	  	  
	  //Windows API References that can be used for malicious activity seen in analysed samples.
	  
	  $api1 = "NetShareEnum" wide ascii
	  $api2 = "CryptBinaryToStringA" wide ascii
	  $api3 = "PathFindExtensionW" wide ascii
	  $api4 = "FindFirstVolumeW" wide ascii
	  $api5 = "GetCurrentProcessId" wide ascii
	  $api6 = "WriteFile" wide ascii
	  $api7 = "FindNextVolumeW" wide ascii
	  $api8 = "GetVolumePathNamesForVolumeNameW" wide ascii
	  $api9 = "FindFirstFileExW" wide ascii
	  $api10 = "FindNextFileW" wide ascii
	  $api11 = "TerminateProcess" wide ascii
	  $api12 = "RegSetValueExA" wide ascii
	  $api13 = "GetSecurityInfo" wide ascii
	  $api14 = "RegSetValueExW" wide ascii
	  $api15 = "RegDeleteValueW" wide ascii
	  $api16 = "CryptAcquireContextW" wide ascii
	  $api17 = "CryptGenRandom" wide ascii
	  $api18 = "ShellExecuteExA" wide ascii
	  $api19 = "ShellExecuteExW" wide ascii
	        
  condition:
      uint16(0) == 0x5A4D
      and 2 of ($hex*)
      and 2 of ($api*)  
	  
	  

}
