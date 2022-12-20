import "pe"

rule Royal_Ran_V1
{

  meta:
     Author = "Andrew McCabe"
     Description = "Rule to detect Royal Ransomware Strains"
     Date_Created = "2022-10-11"
		 Mal_Type = "Ransomware"
		 Detection = "Tight - very little variation, V2 will account for modifiers"
		 Sample_md5 = "AFD5D656A42A746E95926EF07933F054"
                  
         
  
 strings: 

	  //Section for any sample references that can only be represented in HEX or better represented in this form.
	  
	  // http://royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion/%s
	  $hex1 = {68 74 74 70 3A 2F 2F 72 6F 79 61 6C 32 78 74 68 69 67 33 6F 75 35 68 64 37 7A 73 6C 69 71 61 67 79 36 79 79 67 6B 32 63 64 65 6C 61 78 74 6E 69 32 66 79 61 64 36 64 70 6D 70 78 65 64 69 64 2E 6F 6E 69 6F 6E 2F 25 73}
	  
	  // If you are reading this, it means that your system were hit by Royal ransomware.
	  $hex2 = {49 66 20 79 6F 75 20 61 72 65 20 72 65 61 64 69 6E 67 20 74 68 69 73 2C 20 69 74 20 6D 65 61 6E 73 20 74 68 61 74 20 79 6F 75 72 20 73 79 73 74 65 6D 20 77 65 72 65 20 68 69 74 20 62 79 20 52 6F 79 61 6C 20 72 61 6E 73 6F 6D 77 61 72 65 2E}
      
	  // .royal
	  $hex3 = {2E 00 72 00 6F 00 79 00 61 00 6C}
	  
	  // README.TXT
	  $hex4 = {52 00 45 00 41 00 44 00 4D 00 45 00 2E 00 54 00 58 00 54}
	  
	  // $windows.~ws
	  $hex5 = {24 00 77 00 69 00 6E 00 64 00 6F 00 77 00 73 00 2E 00 7E 00 77 00 73}
	  
	  // $windows.~bt
	  $hex6 = {24 00 77 00 69 00 6E 00 64 00 6F 00 77 00 73 00 2E 00 7E 00 62 00 74}
	  
	  // delete shadows /all /quiet
	  $hex7 = {64 00 65 00 6C 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6F 00 77 00 73 00 20 00 2F 00 61 00 6C 00 6C 00 20 00 2F 00 71 00 75 00 69 00 65 00 74}
	  
	  // C:\Windows\System32\vssadmin.exe
	  $hex8 = {43 00 3A 00 5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 53 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 5C 00 76 00 73 00 73 00 61 00 64 00 6D 00 69 00 6E 00 2E 00 65 00 78 00 65}
	  
	  // gADMIN$
	  $hex9 = {67 00 41 00 44 00 4D 00 49 00 4E 00 24}
	  
	  // requestedExecutionLevel level='asInvoker'
	  $hex10 = {72 65 71 75 65 73 74 65 64 45 78 65 63 75 74 69 6F 6E 4C 65 76 65 6C 20 6C 65 76 65 6C 3D 27 61 73 49 6E 76 6F 6B 65 72 27}
	  
	 	  
      
	  //Random String Section but unique to analysed samples.
	  
	  $ran1 = ".lnkal" wide ascii
	  $ran2 = "tor browser" wide ascii
	  $ran3 = ".?AVlogic_error@std@@" wide ascii
	  $ran4 = ".?AVlength_error@std@@" wide ascii
	  $ran5 = ".?AVbad_exception@std@@" wide ascii
	  $ran6 = ".?AVbad_alloc@std@@" wide ascii
	  $ran7 = ".?AVexception@std@@" wide ascii
	  $ran8 = ".?AVbad_array_new_length@std@@" wide ascii
	  $ran9 = ".?AVtype_info@@" wide ascii
	  $ran10 = "%*sPolicy" wide ascii
	  $ran11 = "%*sCPS: %.*s" wide ascii
	  $ran12 = "%*sUser Notice" wide ascii
	  $ran13 = "%*sUnknown Qualifier" wide ascii
	  $ran14 = "%*sOrganization: %.*s" wide ascii
	  $ran15 = "%*sNumber%s" wide ascii
	  $ran16 = "secureShellServer" wide ascii
	  $ran17 = "SSH Server" wide ascii
	  $ran18 = "sendRouter" wide ascii
	  $ran19 = "Send Router" wide ascii
	  $ran20 = "sendProxiedRouter" wide ascii
	  $ran21 = "Send Proxied Router" wide ascii
	  $ran22 = "sendOwner" wide ascii
	  $ran23 = "Send Owner" wide ascii
	  $ran24 = "sendProxiedOwner" wide ascii
	  $ran25 = "Send Proxied Owner" wide ascii
	  
	  	  
	  //Windows API References that can be used for malicious activity seen in analysed samples.
	  
	  $api1 = "CryptAcquireContextW" wide ascii
	  $api2 = "CryptReleaseContext" wide ascii
	  $api3 = "CryptDestroyKey" wide ascii
	  $api4 = "CryptSetHashParam" wide ascii
	  $api5 = "CryptGetProvParam" wide ascii
	  $api6 = "CryptGetUserKey" wide ascii
	  $api7 = "CryptExportKey" wide ascii
	  $api8 = "CryptDecrypt" wide ascii
	  $api9 = "CryptCreateHash" wide ascii
	  $api10 = "CryptDestroyHash" wide ascii
	  $api11 = "CryptSignHashW" wide ascii
	  $api12 = "CryptEnumProvidersW" wide ascii
	  $api13 = "RmRegisterResources" wide ascii
	  $api14 = "RmGetList" wide ascii
	  $api15 = "RmStartSession" wide ascii
	  $api16 = "RmShutdown" wide ascii
	  $api17 = "RmEndSession" wide ascii
	  $api18 = "NetShareEnum" wide ascii
	  
	        
  condition:
      uint16(0) == 0x5A4D
	  and filesize < 6MB
      and 6 of ($hex*)
      and 4 of ($ran*)
	  and any of ($api*)  
	  
	  

}
