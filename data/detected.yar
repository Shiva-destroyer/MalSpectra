rule test_packed
{
    meta:
        description = "Auto-generated YARA rule for test_packed.exe"
        author = "MalSpectra - Sai Srujan Murthy"
        date = "2026-01-03"
        hash = "Generated from test_packed.exe"

    strings:
        $opcode = { 4d 5a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $str1 = "TEST DATA FOR MALSPECTRA" ascii wide
        $str2 = "`.data" ascii wide
        $str3 = "mW1=h" ascii wide
        $str4 = ".text" ascii wide
        $str5 = "pJmh)" ascii wide
        $str6 = ".rsrc" ascii wide
        $str7 = "N\\w{}" ascii wide
        $str8 = "aqdRp" ascii wide
        $str9 = "\"]V8]" ascii wide
        $str10 = "Qa~%" ascii wide

    condition:
        $opcode or
        20 of ($str*)
}