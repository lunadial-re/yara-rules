import "pe"

rule Lab1_4_dropper
{
	meta:
		author = "lunadial"
		description = "Practice in YARA rules writing while dealing with PMA course"
		stage = "dropper"
	strings:
		$mz = {4d 5a}
		$fileDropOpt1 = "CreateFileA"
		$fileDropOpt2 = "MoveFileA"
		$stealthOpt1 = "winup.exe" ascii nocase
		$stealthOpt2 = "winlogon.exe" ascii nocase
		$stealthOpt3 = "wupdmgr.exe" ascii nocase
	condition:
		pe.is_pe
		and pe.sections[pe.section_index(".rsrc")].raw_data_size > 5000
		and 1 of ($fileDrop*)
		and 1 of ($stealth*)
		and $mz
}

rule Lab1_4_loader
{
	meta:
		author = "lunadial"
		description = "Practice in YARA rules writing while dealing with PMA course"
		stage = "loader"
	strings:
		$url = "practicalmalwareanalysis.com/updater.exe" ascii nocase
		$net = "URLDownloadToFile"
		$stealthOpt1 = "winup.exe"
		$stealthOpt2 = "winupdmgrd.exe"
		$stealthOpt3 = "updater.exe"
	condition:
		pe.is_pe
		and $url
		and $net
		and 1 of ($stealth*)
}