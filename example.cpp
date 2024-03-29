#include "ImportlessApi.hpp"
#include <stdio.h>


/* Example of a code using the API. */
int main()
{
	//HANDLE hFile = IMPORTLESS_API(CreateFile)(L"ys.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	//if (hFile == INVALID_HANDLE_VALUE)
	//{
	//	printf("Error\n");
	//	return 1;
	//}

	//DWORD dwWritten;
	//IMPORTLESS_API(WriteFile)(hFile, "yoavshah importless api", strlen("yoavshah importless api"), &dwWritten, NULL);
	

	//IMPORTLESS_API(CloseHandle)(hFile);


	HMODULE x = IMPORTLESS_API(LoadLibraryA)("user32.dll");
	printf("%x\n", x);



	IMPORTLESS_API_WITH_MODULE(MessageBoxA, x)(0, "", "", 0);

	// For NTDLL.dll exports
	//IMPORTLESS_API_STR("MessageBoxA", decltype(&MessageBoxA))(0, "YS", "YS", 0);

	//IMPORTLESS_API(MessageBoxA)(0, "YS", "YS", 0);


	

	return 0;
}