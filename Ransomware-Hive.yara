import "pe"

rule Hive_V1
{

  meta:
         Author = "Andrew McCabe"
         Description = "YARA Rule to catch Hive Ransomware Variants"
         Date_Created = "26-10-2022"
		 Mal_Type = "Ransomware"
         Detection = "Tight but performs well as is"
		 Version = "1.0"
		 Control_Type = "This rule is still in testing, do not use in a live env"                 
         
  
 strings:  
	  
      
	  //Random String Section but unique to analysed samples.
	  
	  $ran1 = "shadowcopy delet" wide ascii
	  $ran2 = "delete catalog-q" wide ascii
	  $ran3 = "ECRYPT.t" wide ascii
	  $ran4 = "HOW_TO_DECRYPT.txt" wide ascii
	  $ran5 = "+shares: found" wide ascii
	 	  	  
	  //Windows API References that can be used for malicious activity seen in analysed samples.
	  
	  $api1 = "NtCreateFile" wide ascii
	  $api2 = "NtReadFile" wide ascii
	  $api3 = "NtWriteFile" wide ascii
	  $api4 = "CreateFileMappingA" wide ascii
	  $api5 = "CreateFileW" wide ascii
	  $api6 = "CreateMutexA" wide ascii
	  $api7 = "CreateThread" wide ascii
	  $api8 = "DeviceIoControl" wide ascii
	  $api9 = "FindClose" wide ascii
	  $api10 = "FindNextFileW" wide ascii
	  $api11 = "FindNextVolumeW" wide ascii
	  $api12 = "FindVolumeClose" wide ascii
	  $api13 = "GetCurrentDirectoryW" wide ascii
	  $api14 = "GetCurrentProcess" wide ascii
	  $api15 = "GetCurrentThread" wide ascii
	  $api16 = "GetModuleHandleA" wide ascii
	  $api17 = "GetProcAddress" wide ascii
	  $api18 = "GetSystemInfo" wide ascii
	  $api19 = "GetSystemTimeAsFileTime" wide ascii
	  $api20 = "GetVolumePathNamesForVolumeNameW" wide ascii
	  $api21 = "SetFileAttributesW" wide ascii
	  $api22 = "SetVolumeMountPointW" wide ascii
	  $api23 = "TerminateProcess" wide ascii
	  $api24 = "UnmapViewOfFile" wide ascii
	  $api25 = "LeaveCriticalSection" wide ascii
	  $api26 = "EnumDependentServicesW" wide ascii
	  $api27 = "EnumServicesStatusW" wide ascii
	  $api28 = "ImpersonateLoggedOnUser" wide ascii
	  $api29 = "LogonUserW" wide ascii
	  $api30 = "LookupPrivilegeValueW" wide ascii
	  $api31 = "SetNamedSecurityInfoW" wide ascii
	  $api32 = "StartServiceW" wide ascii
	  $api33 = "AcquireSRWLockExclusive" wide ascii
	  $api34 = "AcquireSRWLockShared" wide ascii
	  
  condition:
      uint16(0) == 0x5A4D
      and 2 of ($ran*)
      and 10 of ($api*)
	        
      }
