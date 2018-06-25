#include "stdafx.h"

#include <Windows.h>
#include <LMaccess.h>
#include <lmerr.h>
#include "util.h"

int main() {
	LPWSTR  group_name = L"Dummy_group_test_02";
	HANDLE handle = 0;


	PSID sid = 0;
	SID_NAME_USE accountType;

	//create a test group and find an appropriate sid
	LOCALGROUP_INFO_0 localgroup_info;
	localgroup_info.lgrpi0_name = group_name;
	NetLocalGroupDel(NULL, group_name);
	if (NetLocalGroupAdd(NULL, 0, (LPBYTE)&localgroup_info, NULL) != NERR_Success)
		return -10;

	DWORD bufferSize = 0, buffer2Size = 0;
	
	LookupAccountName(NULL, group_name, NULL, &bufferSize, NULL, &buffer2Size, &accountType);
	sid = (PSID) new BYTE[bufferSize];
	LPTSTR domain = (LPTSTR) new BYTE[buffer2Size];
	if (!LookupAccountName(NULL, group_name, sid, &bufferSize, domain, &buffer2Size, &accountType)) {
		NetLocalGroupDel(NULL, group_name);
		return -20;
	}

	//construct the token with the dummy group
	util::constructUserTokenWithGroup(sid, handle);

	bufferSize = 0;
	GetTokenInformation(handle, TokenGroups, NULL, 0, &bufferSize);
	SetLastError(0);
	PTOKEN_GROUPS groups = (PTOKEN_GROUPS) new BYTE[bufferSize];
	GetTokenInformation(handle, TokenGroups, (LPVOID)groups, bufferSize, &bufferSize);

	for (size_t i = 0; i < groups->GroupCount; i++)
	{
		bufferSize = 0;
		buffer2Size = 0;
		LookupAccountSid(NULL, groups->Groups[i].Sid, NULL, &bufferSize, NULL, &buffer2Size, &accountType);
		LPTSTR name = (LPTSTR) new BYTE[bufferSize];
		LPTSTR domain = (LPTSTR) new BYTE[buffer2Size];
		LookupAccountSid(NULL, groups->Groups[i].Sid, name, &bufferSize, domain, &buffer2Size, &accountType);

		wprintf(L"%s\n",name);
	}
	
	getchar();
	NetLocalGroupDel(NULL, group_name);
	return 0;
}