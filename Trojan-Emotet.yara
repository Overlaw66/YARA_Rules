import "pe"

rule Emotet_V2
{

  meta:
         Author = "Andrew McCabe"
         Description = "Rule to catch strains of the Emotet Trojan"
         Date_Created = "07-11-2022"
		 Mal_Type = "Trojan"
         Detection = "Lose - performing well on new Emotet campaign"
	 Version = "2.0"
		 Control = "This rule is still in testing and should not be used in a live env as it could generate many FPs"
                  
         
  
 strings: 

	  //Section for any sample references that can only be represented in HEX or better represented in this form.
	  
	  //!"#$%&'()*+,-./0123456789:;<=>?@abcdefghijklmnopqrstuvwxyz[\]^_`abcdefghijklmnopqrstuvwxyz{|}~
	  $hex1 = {21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F 60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E}
	  
      //!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`ABCDEFGHIJKLMNOPQRSTUVWXYZ{|}~
      $hex2 = {21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F 60 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 7B 7C 7D 7E}
	  
      //!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`ABCDEFGHIJKLMNOPQRSTUVWXYZ{|}~
      $hex3 = {21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F 60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E}
	  
	
	  
      
	  //Random String Section but unique to analysed samples.
	  
	  $ran1 = "1#QNAN" wide ascii
	  $ran2 = "1#SNAN" wide ascii
	  $ran3 = "ForceRemove" wide ascii
	  $ran4 = "@SUVWATAUAVAWH" wide ascii
      $ran5 = "SUVWATAUAVAWH" wide ascii
      $ran6 = "@SVWATAUH" wide ascii
      $ran7 = "SVWATAUH" wide ascii
	  
	  	  
	  //Windows API References that can be used for malicious activity seen in analysed samples.
	  
	  $api1 = "ShellExecuteExA" wide ascii
	  $api2 = "VirtualAlloc" wide ascii
	  $api3 = "GetCurrentProcess" wide ascii
	  $api4 = "GetCurrentThread" wide ascii
	  $api5 = "GetLocalTime" wide ascii
	  $api6 = "LockResource" wide ascii
	  $api7 = "LoadResource" wide ascii
	  $api8 = "FindResourceA" wide ascii
	  $api9 = "MoveFileA" wide ascii
	  $api10 = "DeleteFileA" wide ascii
	  $api11 = "ReadFile" wide ascii
	  $api12 = "WriteFile" wide ascii
	  $api13 = "DeleteFileA" wide ascii
	  $api14 = "MoveFileA" wide ascii
	  $api15 = "CreateFileA" wide ascii
	  $api16 = "CreateDirectoryA" wide ascii
	  $api17 = "GetCommandLineA" wide ascii
	  $api18 = "TerminateProcess" wide ascii
	  $api19 = "IsDebuggerPresent" wide ascii
	  $api20 = "CryptStringToBinaryA" wide ascii
	  $api21 = "RegDeleteKeyA" wide ascii
	  $api22 = "RegEnumKeyA" wide ascii
	  $api23 = "RegCreateKeyExA" wide ascii
	  $api24 = "RegQueryValueA" wide ascii
	  $api25 = "RegSetValueExA" wide ascii
	  $api26 = "ForceRemove" wide ascii
	  $api27 = "GetCurrentProcessId" wide ascii
	  $api28 = "GlobalFindAtomA" wide ascii
	  $api29 = "GlobalGetAtomNameA" wide ascii
	  $api30 = "GlobalDeleteAtom" wide ascii
	  $api31 = "DeleteAtom" wide ascii
	  $api32 = "GlobalAddAtomA" wide ascii
	  $api33 = "CallNextHookEx" wide ascii
	  $api34 = "UnhookWindowsHookEx" wide ascii
	  $api35 = "GetKeyState" wide ascii
	  $api36 = "SystemParametersInfoA" wide ascii
	  $api37 = "GetDesktopWindow" wide ascii
	  $api38 = "GetCapture" wide ascii
	  $api39 = "SetWindowsHookExA" wide ascii
	 
	  
	        
  condition:
      uint16(0) == 0x5A4D
      and 1 of ($hex*)
      and 4 of ($ran*)
	  and 8 of ($api*)
	  and pe.exports("DllRegisterServer")  
	  

}
