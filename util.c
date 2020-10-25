#include "detect.h"

BOOL util_path_exists(IN LPCWSTR lpszPath, IN DWORD dwExtraFlags)
{
	DWORD dwFlags = FILE_SHARE_READ | FILE_SHARE_WRITE;
	if (dwExtraFlags)
		dwFlags |= dwExtraFlags;

	HANDLE hFile = CreateFile(lpszPath, GENERIC_READ, 0, NULL, OPEN_ALWAYS, dwFlags, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}
