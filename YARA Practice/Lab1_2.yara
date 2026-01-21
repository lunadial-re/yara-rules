import "pe"
rule Lab1_2
{
	meta:
		author = "lunadial"
		description = "Practice on YARA rules writing while dealing with PMA course"
	strings:
		$service_name = "Malservice" ascii nocase
		$user_agent = "Internet Explorer 8.0"
		$mutex_name = "HGL345" nocase ascii
		$url_address = "https:\\malwareanalysisbook.com"
	condition:
	 uint16(0)=0x5a4d
	 and
	 (2 of them
	 or
	 (pe.number_of_sections ==3 and 1 of them))
}
	