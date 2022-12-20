import "pe"

rule Qbot_V1
{

  meta:
         Author = "Andrew McCabe"
         Description = "Rule to identify strains of Qbot malware"
         Date_Created = "2022-01-02"
         Detection = "Tight but performing well in current campaign"
	 Version = "1.0"
		     Mal_Type = "Trojan"
                  
         
  
 strings: 

	  //Section for any sample references that can only be represented in HEX or better represented in this form.
	  
	  //!"#$%&'()*+,-./0123456789:;<=>?@abcdefghijklmnopqrstuvwxyz[\]^_`abcdefghijklmnopqrstuvwxyz{|}~
	  $hex1 = {21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F 60 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 7B 7C 7D 7E}
	  
	        
	  //requestedExecutionLevel level='asInvoker' uiAccess='false'
	  $hex2 = {72 65 71 75 65 73 74 65 64 45 78 65 63 75 74 69 6F 6E 4C 65 76 65 6C 20 6C 65 76 65 6C 3D 27 61 73 49 6E 76 6F 6B 65 72 27 20 75 69 41 63 63 65 73 73 3D 27 66 61 6C 73 65 27}
	  
	  
	  
      
	  //Common debug strings malware uses for analyses detection.
	  
	  $dbg1 = "IsProcessorFeaturePresent" wide ascii
	  $dbg2 = "IsDebuggerPresent" wide ascii
	  
	  	  
	  //Windows API References that can be used for malicious activity seen in analysed samples.
	  
	  $api1 = "GetCurrentThreadId" wide ascii
	  $api2 = "GetCurrentProcessId" wide ascii
	  $api3 = "MapViewOfFile" wide ascii
	  $api4 = "TerminateProcess" wide ascii
	  $api5 = "WriteFile" wide ascii
	  $api6 = "FindFirstFile" wide ascii
	  $api7 = "FindNextFile" wide ascii
	  $api8 = "SetFileAttributes" wide ascii
	  $api9 = "DeleteFile" wide ascii
	  $api10 = "FindFirstFileEx" wide ascii
	  $api11 = "FindNextFile" wide ascii
	  $api12 = "GetEnvironmentStrings" wide ascii
	  $api13 = "LockFile" wide ascii
	  $api14 = "VirtualProtect" wide ascii
	  $api15 = "ReadProcessMemory" wide ascii
	  $api16 = "OpenClipboard" wide ascii
	  $api17 = "GetClipboardData" wide ascii
	  $api18 = "GetKeyState" wide ascii
	  $api19 = "GetKeyboardState" wide ascii
	  $api20 = "GetWindowThreadProcessId" wide ascii
	  $api21 = "CreateThread" wide ascii
	  $api22 = "VirtualAllocEx" wide ascii
	  $api23 = "GetCommandLineA" wide ascii
	  $api24 = "AreFileApisANSI" wide ascii
	  $api25 = "AppPolicyGetProcessTerminationMethod" wide ascii
	  $api26 = "GetStartupInfoW" wide ascii
	  $api27 = "WideCharToMultiByte" wide ascii 
	  
	  
	  
	        
  condition:
      uint16(0) == 0x5A4D and filesize < 200MB
	  and pe.exports("DrawThemeIcon")
	  and 2 of ($hex*)
      and 2 of ($dbg*)
	  and 5 of ($api*)  
	  
	  

}



