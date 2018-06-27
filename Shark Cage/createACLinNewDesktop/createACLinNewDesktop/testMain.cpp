#include "stdafx.h"

#include <Windows.h>
#include <LMaccess.h>
#include <lmerr.h>
#include "util.h"

int main() {
	LPWSTR  group_name = L"Dummy_group_testing_token_mod";
	SID_NAME_USE accountType;
	HANDLE handle = 0;


	PSID sid = 0;

	util::createLocalGroup(group_name, sid);
	util::constructUserTokenWithGroup(sid, handle);


	//surface all the groups to the console - just to demonstrate that a token has selected group in it.
	DWORD bufferSize = 0, buffer2Size = 0;
	GetTokenInformation(handle, TokenGroups, NULL, 0, &bufferSize);
	SetLastError(0);
	PTOKEN_GROUPS groups = (PTOKEN_GROUPS) new BYTE[bufferSize];
	GetTokenInformation(handle, TokenGroups, (LPVOID)groups, bufferSize, &bufferSize);
	for (size_t i = 0; i < groups->GroupCount; i++)
	{
		bufferSize = 0;
		buffer2Size = 0;
		LookupAccountSid(NULL, groups->Groups[i].Sid, NULL, &bufferSize, NULL, &buffer2Size, &accountType);
		LPTSTR name = (LPTSTR) new BYTE[bufferSize*sizeof(TCHAR)];
		LPTSTR domain = (LPTSTR) new BYTE[buffer2Size* sizeof(TCHAR)];
		LookupAccountSid(NULL, groups->Groups[i].Sid, name, &bufferSize, domain, &buffer2Size, &accountType);

		wprintf(L"%s\n",name);
		free(name);
		free(domain);
	}

	util::deleteLocalGroup(group_name);
	getchar();
	return 0;
}