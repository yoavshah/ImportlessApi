
# ImportlessApi

  ## ImportlessApi is a project that allow you to easly use real time function resolving using a changing hash value.

  ## Usage
  
  * include "ImportlessApi.hpp"
  * Handle hFile = IMPORTLESS_API(CreateFile)(Parameters);

  ## Examples

  * Example of CPP syntax
<img align="center" src="https://raw.githubusercontent.com/yoavshah/ImportlessApi/master/images/CPP_Syntax.png" />

  * Example of CPP full example
<img align="center" src="https://raw.githubusercontent.com/yoavshah/ImportlessApi/master/images/CPP_Example.png" />

  * Example's output
<img align="center" src="https://raw.githubusercontent.com/yoavshah/ImportlessApi/master/images/OUTPUT_Example.png" />

  * IDA output (main function)
<img align="center" src="https://raw.githubusercontent.com/yoavshah/ImportlessApi/master/images/IDA_Example_1.png" />

  * IDA output (resolve function)
<img align="center" src="https://raw.githubusercontent.com/yoavshah/ImportlessApi/master/images/IDA_Example_2.png" />


  ## Examples
  * There probally should not be hash collisions, but in case 2 functions resolve into the same hash, try changing the hash function.

  ## Credits
  * Real thanks for JustasMasiulis for helping me understand and learn about advanced macro techniques with his [project](https://github.com/JustasMasiulis/lazy_importer/)





