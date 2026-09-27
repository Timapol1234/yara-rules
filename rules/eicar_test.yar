rule EICAR_Test_File
{
    meta:
        description = "Detects the EICAR anti-malware test string (harmless)"
        author      = "Poltarykhin Timofey"
        date        = "2026-09-27"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
