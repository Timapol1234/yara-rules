rule PHP_Reverse_Shell
{
    meta:
        description = "Detects pentestmonkey-style PHP reverse shells"
        author      = "Poltarykhin Timofey"
        date        = "2026-09-27"
        reference   = "https://github.com/pentestmonkey/php-reverse-shell"
        mitre_attack = "T1505.003 - Web Shell"
    strings:
        $s1 = "fsockopen" ascii
        $s2 = "/bin/sh -i" ascii
        $s3 = "proc_open" ascii
        $s4 = "php-reverse-shell" ascii nocase
        $s5 = "uname -a" ascii
    condition:
        // не менее 3 признаков сразу -> меньше ложных срабатываний
        3 of ($s*)
}
