rule PHP_ReverseShell {
	meta:
		author       = "SpoodoW"
		description  = "Scans for popular reverse shells from PHP"
		date         = "06-10-2026"
		version      = "1.0"
		severity     = "Critical"
		mitre_attack = "T1059.004"
		score        = 9.0
		reference_1  = "https://www.revshells.com/"
		reference_2  = "https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/"
	strings:
		$php_raw_regex    = /php\s+-r\s+['"]\$\w+\s*=\s*fsockopen\(\s*['"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}['"]\s*,\s*\d{1,5}\s*\)/ ascii wide
		$base64_fsock_php = "fsockopen" base64 base64wide
		$base64_fd_php    = "2>&3" base64 base64wide  // 4 chars is safer for YARA performance
		$xor_fsock_php    = "fsockopen" xor
		$xor_fd_php       = "2>&3" xor
	condition:
		any of ($php_*) or all of ($base64_*) or all of ($xor_*)

}

rule Bash_ReverseShell {
	meta:
		author       = "SpoodoW"
		description  = "Scans for popular reverse shells from Bash"
		date         = "06-10-2026"
		version      = "1.0"
		severity     = "Critical"
		mitre_attack = "T1059.004"
		score        = 9.0
		reference_1  = "https://www.revshells.com/"
		reference_2  = "https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/"
	strings:
		$bash_classic_raw_regex = /bash\s+-i\s*>\&\s*\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5}/ ascii wide
		$bash_exec_raw_regex    = /0<&\d+\s*;\s*exec\s+\d+<>\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5}/ ascii wide
		$base64_tcp_bash        = "/dev/tcp/" base64 base64wide
		$base64_fd_bash         = "0>&1" base64 base64wide
		$xor_tcp_bash           = "/dev/tcp/" xor
		$xor_fd_bash            = "0>&1" xor
	condition:
		any of ($bash_*) or all of ($base64_*) or all of ($xor_*)

}

rule Python_ReverseShell {
	meta:
		author       = "SpoodoW"
		description  = "Scans for popular reverse shells from Python"
		date         = "06-10-2026"
		version      = "1.0"
		severity     = "Critical"
		mitre_attack = "T1059.006"
		score        = 9.0
		reference_1  = "https://www.revshells.com/"
		reference_2  = "https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/"
	strings:
		$python_raw_regex   = /python(?:3)?\s+-c\s+['"]import\s+socket,\s*subprocess,\s*os\s*;\s*\w+\s*=\s*socket\.socket\(socket\.AF_INET,\s*socket\.SOCK_STREAM\);\s*\w+\.connect\(\(['"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}['"],\s*\d{1,5}\)\)/ ascii wide
		$base64_sock_python = "socket.socket(socket.AF_INET" base64 base64wide
		$base64_dup_python  = "os.dup2(" base64 base64wide
		$xor_sock_python    = "socket.socket(socket.AF_INET" xor
		$xor_dup_python     = "os.dup2(" xor
	condition:
		any of ($python_*) or all of ($base64_*) or all of ($xor_*)
}
