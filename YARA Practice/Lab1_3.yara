import "pe"
rule Lab1_3
{
	meta:
		author = "lunadial"
		description = "Practice on YARA rules writing while dealing with PMA course"
	strings:
		$_url_address = "http://www.malwareanalysisbook.com/ad.html"
	condition:
		pe.is_pe
		and
		( pe.rich_signature.clear_data matches /FSG/
		or
		(pe.number_of__sections == 3 and pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress")))
}