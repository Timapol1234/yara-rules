rule Windows_Executable
{
    meta:
        description = "Detects Windows PE files (EXE/DLL) by MZ magic bytes"
        author      = "Poltarykhin Timofey"
        date        = "2026-09-27"
    strings:
        $mz = { 4D 5A }          // 'MZ' - сигнатура заголовка PE
    condition:
        $mz at 0                 // именно в начале файла (offset 0)
}
