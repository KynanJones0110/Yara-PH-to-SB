rule Yara_template {


  meta:
      date_of_creation = "20**-**-**"
      last_updated = "20**-**-**"
      author = ""
      description = ""
      
 strings:
    // String identification etc
      $string_1 = "malz"
      $magic_byte = "MZ"
      $hex_string = "FF 69 ?? 44"
      $hex_string2 = "F9 3D DF 9L"
      
 condition:
   //  Conditions to be met etc









}
