#include "stdafx.h"

#include <Windows.h>
#include <LMaccess.h>
#include <lmerr.h>
#include "util.h"

#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

int main() {
	LPWSTR  groupName = L"Dummy_group_testing_token_mod";
	SID_NAME_USE accountType;
	HANDLE modifiedTokenHandle = 0;


	PSID newGroupSid = 0;
	NetLocalGroupDel(NULL, groupName);
	if (!tokenLib::createLocalGroup(groupName, newGroupSid) ||
		!tokenLib::constructUserTokenWithGroup(newGroupSid, modifiedTokenHandle)) {
		tokenLib::destroySid(newGroupSid);
		return 22;
	}
	tokenLib::destroySid(newGroupSid);


	//surface all the groups to the console - just to demonstrate that a token has selected group in it.
	DWORD bufferSize = 0, buffer2Size = 0;
	GetTokenInformation(modifiedTokenHandle, TokenGroups, NULL, 0, &bufferSize);
	SetLastError(0);
	PTOKEN_GROUPS groups = (PTOKEN_GROUPS) new BYTE[bufferSize];
	GetTokenInformation(modifiedTokenHandle, TokenGroups, (LPVOID)groups, bufferSize, &bufferSize);
	for (size_t i = 0; i < groups->GroupCount; i++)
	{
		bufferSize = 0;
		buffer2Size = 0;
		LookupAccountSid(NULL, groups->Groups[i].Sid, NULL, &bufferSize, NULL, &buffer2Size, &accountType);
		LPTSTR name = (LPTSTR) new BYTE[bufferSize*sizeof(TCHAR)];
		LPTSTR domain = (LPTSTR) new BYTE[buffer2Size* sizeof(TCHAR)];
		LookupAccountSid(NULL, groups->Groups[i].Sid, name, &bufferSize, domain, &buffer2Size, &accountType);

		wprintf(L"%s\n",name);
		delete[](BYTE*) name;
		delete[](BYTE*) domain;
	}

	delete[](BYTE*) groups;

	tokenLib::deleteLocalGroup(groupName);
	getchar();

	_CrtDumpMemoryLeaks();
	return 0;
}