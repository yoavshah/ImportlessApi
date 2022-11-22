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

	printf("%x\n", IMPORTLESS_API(LoadLibraryA)("kernel32.dll"));

	printf("%x\n", IMPORTLESS_MODULE(L"kernel32.dll"));

	// For NTDLL.dll exports
	//IMPORTLESS_API_STR("MessageBoxA", decltype(&MessageBoxA))(0, "YS", "YS", 0);

	//IMPORTLESS_API(MessageBoxA)(0, "YS", "YS", 0);


	

	return 0;
}