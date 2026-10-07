rule NmapCommand {
	meta:
		author       = "SpoodoW"
		description  = "Scans for popular port scanning tool nmap"
		date         = "07-10-2026"
		version      = "1.0"
		severity     = "Medium"
		mitre_attack = "T1046"
		score        = 4.0
		reference    = ""
	strings:
		$nmap_raw    = /nmap\s+(?:-[a-zA-Z0-9-]+\s+){0,5}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii wide
		$base64_nmap = "nmap -p" base64 base64wide
		$xor_nmap    = "nmap -p" xor
	condition:
		any of ($nmap_*) or any of ($base64_*) or any of ($xor_*)

}

rule RustscanCommand {
	meta:
		author       = "SpoodoW"
		description  = "Scans for popular port scanning tool rustscan"
		date         = "07-10-2026"
		version      = "1.0"
		severity     = "Medium"
		mitre_attack = "T1046"
		score        = 4.0
		reference    = ""
	strings:
		$rustscan_raw    = /rustscan\s+(?:-[a-zA-Z0-9-]+\s+){0,5}(?:-a\s+)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii wide
		$base64_rustscan = "rustscan -a" base64 base64wide
		$xor_rustscan    = "rustscan -a" xor
	condition:
		any of ($rustscan_*) or any of ($base64_*) or any of ($xor_*)

}
