rule Suspicious_PowerShell
{
    meta:
        description = "Detects obfuscated or download-cradle PowerShell"
        author      = "Poltarykhin Timofey"
        date        = "2026-09-27"
        mitre_attack = "T1059.001 - PowerShell, T1027 - Obfuscation"
    strings:
        $a1 = "-enc" ascii nocase
        $a2 = "-EncodedCommand" ascii nocase
        $a3 = "IEX" ascii
        $a4 = "DownloadString" ascii nocase
        $a5 = "FromBase64String" ascii nocase
    condition:
        2 of them
}
