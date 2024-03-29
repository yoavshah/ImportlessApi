
# ImportlessApi

  ## ImportlessApi is a project that allows you to easly use real time function resolving using a compile time hashing calculation.

  ## Usage
  
  * include "ImportlessApi.hpp"
  
  * Use it with any imported function (any DLL that is already loaded to the process linked list)
  
  * Handle hFile = IMPORTLESS_API(CreateFile)(Parameters);

  ## Advanced Usage
  
  * defining IMPORTLESSAPI_CONSISTENT_COMPILATION before including the library force that the hash calculation will be constant across compilations
  
  * defining IMPORTLESSAPI_REMOVE_INLINE will force the search function ot not be inlined.
  
  * You can use IMPORTLESS_API(func_name) for functions you have symbols for, like CreateFile, LoadLibrary, etc.
  
  * You can use IMPORTLESS_API("func_name", func_type) for function you do not have symbols for, like NtQuerySystemInformation and more.
  

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


  ## Remarks
  
  * The library can handle using macro functions, like LoadLibrary instead of LoadLibraryA, and it will resolve it automaticly based on the macro value.
  
  * There probally should not be hash collisions, but in case 2 functions resolve into the same hash, try changing the hash function.


  ## Credits
  * Real thanks for JustasMasiulis for helping me understand and learn about advanced macro techniques with his [project](https://github.com/JustasMasiulis/lazy_importer/)





