import "pe"
rule Lab5_1_persistence
 {
	meta:
		author = "lunadial"
		description = "Practice in YARA-rules writing while deal with PMA course"
		md5="1a9fd80174aafecd9a52fd908cb82637"
		sha1="fbe285b8b7fe710724ea35d15948969a709ed33b"
		sha256="eb1079bdd96bc9cc19c38b76342113a09666aad47518ff1a7536eebff8aadb4a"
	strings:
		$svc1="smss.exe"
		$svc2="csrss.exe"
		$svc3="lsass.exe"
		$svc4="services.exe"
		$svc5="svchost.exe"
		$svc6="explorer.exe"
		$svc7="winlogon.exe"
		$svc8="run32dll.exe"        
		$svc9="run64dll.exe"
		$svc10="xinstall.dll"
		$svc11="sfc_os.dll"
		$svc12="conime.exe"
		$svc13="iexplorer.exe"

	condition:
	3 of(
	pe.imports("ADVAPI32.dll", "CreateService")
	pe.imports("ADVAPI32.dll","DeleteService")
	pe.imports("ADVAPI32.dll","OpenService")
	pe.imports("ADVAPI32.dll","SetServiceStatus")
	pe.imports("ADVAPI32.dll","OpenSCManager")
	any of ($svc*))
 }
 
 rule Lab5_1_network_based
 {
	meta:
		author = "lunadial"
		description = "Practice in YARA-rules writing while deal with PMA course"
		md5="1a9fd80174aafecd9a52fd908cb82637"
		sha1="fbe285b8b7fe710724ea35d15948969a709ed33b"
		sha256="eb1079bdd96bc9cc19c38b76342113a09666aad47518ff1a7536eebff8aadb4a"
	strings:
		$url = "pics.practicalmalwareanalysis.com"
		$useragent ="Mozilla/4.0 (compatible; MISE 6.00; Windows NT 5.1)" nocase
	condition:
		($url or $useragent) and pe.imports("WS2_32.dll", "connect")
		and any of(
		pe.imports("WS2_32.dll","send") 
		pe.imports("WS2_32.dll", "recv") 
		pe.imports("WS2_32.dll","socket") 
		pe.imports("WS2_32.dll", "connect"))
}

rule Lab5_1_registry_activity
{
	meta:
		author = "lunadial"
		description = "Practice in YARA-rules writing while deal with PMA course"
		md5="1a9fd80174aafecd9a52fd908cb82637"
		sha1="fbe285b8b7fe710724ea35d15948969a709ed33b"
		sha256="eb1079bdd96bc9cc19c38b76342113a09666aad47518ff1a7536eebff8aadb4a"
	strings:
		$reg1 = "SYSTEM\\CurrentControlSet"
		$reg2= "SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
		$reg3="HKEY_USERS"
		$reg4="HKEY_LOCAL_MACHINE"
		$reg5="HKEY_CURRENT_USER"
		$reg6="HKEY_CURRENT_CONFIG"
		$reg7="HKEY_CLASSES_ROOT"
		$reg8="SOFTWARE\\MICROSOFT\\Windows NT\\CurrentVersion\\Svchost"
	condition:
		pe.imports("ADVAPI32.dll","RegOpenKey") 
		and pe.imports("ADVAPI32.dll","RegCloseKey") 
		and pe.imports("ADVAPI32.dll","RegCreateKey") 
		and pe.imports("ADVAPI32.dll","RegDeleteKey") 
		and pe.imports("ADVAPI32.dll", "RegSetValue")
		and pe.imports("ADVAPI32.dll", "RegDeleteValue")
		and any of ($reg*)
}

rule Lab5_1_anti_vm
{
	meta:
		author = "lunadial"
		description = "Practice in YARA-rules writing while deal with PMA course"
		md5="1a9fd80174aafecd9a52fd908cb82637"
		sha1="fbe285b8b7fe710724ea35d15948969a709ed33b"
		sha256="eb1079bdd96bc9cc19c38b76342113a09666aad47518ff1a7536eebff8aadb4a"
	strings:
		$avm1={56 4D 58 68}
		$avm2="VMX" wide
	condition:
		any of ($avm*)
}