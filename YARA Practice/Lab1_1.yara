rule Lab1_1
{
	meta:
		author = "lunadial"
		description = "Practice on YARA rules writing while dealing with PMA course"
	strings:
		$ip_address = "127.26.152.13" ascii wide nocase
		$malicious_library = "kerne132.dll" ascii wide nocase
		$injection_path = "C:\\windows\\system32\\kerne132.dll" ascii wide nocase
		$incoming injection = "Lab01-01.dll" ascii wide nocase
	condition:
		uint16(0)=0x4D5A
		and 1 of them
}