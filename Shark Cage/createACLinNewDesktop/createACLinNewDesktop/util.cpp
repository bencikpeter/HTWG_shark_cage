#include "stdafx.h"
#include "util.h"
#include <LMaccess.h>
#include <lmerr.h>
#include <stdexcept>
#include <Sddl.h>
#include <Wtsapi32.h>
#include <Winternl.h>
#include <ntstatus.h>
#include <iostream>
#include <stdio.h>
#pragma comment(lib, "netapi32.lib")

class tokenStructures {
public:
	ACCESS_MASK			accessMask;
	POBJECT_ATTRIBUTES	objectAttributes;
	TOKEN_TYPE			tokenType;
	PLUID				authenticationId;
	PLARGE_INTEGER		expirationTime;
	PTOKEN_USER         tokenUser;
	PTOKEN_GROUPS       tokenGroups;
	PTOKEN_PRIVILEGES   tokenPrivileges;
	PTOKEN_OWNER        tokenOwner;
	PTOKEN_PRIMARY_GROUP tokenPrimaryGroup;
	PTOKEN_DEFAULT_DACL tokenDefaultDacl;
	PTOKEN_SOURCE       tokenSource;
};

ULONG getCurrentSessionID();
void deconstructToken(tokenStructures &tokenDeconstructed, HANDLE &userToken);
void deallocateToken(tokenStructures &tokenDeconstructed);
bool changeTokenCreationPrivilege(bool privilegeStatus);
bool addGroupToTokenGroups(PSID sid, tokenStructures &tokenDeconstructed, PTOKEN_GROUPS &newGroups);


namespace tokenLib {

	bool createLocalGroup(LPWSTR groupName, PSID &sid){
		SID_NAME_USE accountType;
		LOCALGROUP_INFO_0 localGroupInfo;
		localGroupInfo.lgrpi0_name = groupName;


		NET_API_STATUS result = NetLocalGroupAdd(NULL, 0, (LPBYTE)&localGroupInfo, NULL);
		if (result != NERR_Success) {
			if (result == NERR_GroupExists) wprintf(L"Specified group name already exists");
			else wprintf(L"Could not create specified group");
			sid = NULL;
			return false;
		}

		DWORD bufferSize = 0, buffer2Size = 0;

		LookupAccountName(NULL, groupName, NULL, &bufferSize, NULL, &buffer2Size, &accountType);
		sid = (PSID) new BYTE[bufferSize];
		LPTSTR domain = (LPTSTR) new BYTE[buffer2Size * sizeof(TCHAR)];
		if (!LookupAccountName(NULL, groupName, sid, &bufferSize, domain, &buffer2Size, &accountType)) {
			wprintf(L"Could not retrieve SID of newly created group");
			NetLocalGroupDel(NULL, groupName);
			delete[](BYTE*) sid;
			delete[](BYTE*) domain;
			sid = NULL;
			return false;
		}
		delete[](BYTE*) domain;
		return true;
	}

	bool deleteLocalGroup(LPWSTR groupName) {
		if(NetLocalGroupDel(NULL, groupName) != NERR_Success)
			return false;
		return true;
	}

	bool constructUserTokenWithGroup(PSID sid, HANDLE &token) {

		//load internal NtCreateToken function
		typedef NTSTATUS(__stdcall *NT_CREATE_TOKEN)(
			OUT PHANDLE             TokenHandle,
			IN ACCESS_MASK          DesiredAccess,
			IN POBJECT_ATTRIBUTES   ObjectAttributes,
			IN TOKEN_TYPE           TokenType,
			IN PLUID                AuthenticationId,
			IN PLARGE_INTEGER       ExpirationTime,
			IN PTOKEN_USER          TokenUser,
			IN PTOKEN_GROUPS        TokenGroups,
			IN PTOKEN_PRIVILEGES    TokenPrivileges,
			IN PTOKEN_OWNER         TokenOwner,
			IN PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
			IN PTOKEN_DEFAULT_DACL  TokenDefaultDacl,
			IN PTOKEN_SOURCE        TokenSource
			);
		NT_CREATE_TOKEN NtCreateToken = NULL;
		HMODULE hModule = LoadLibrary(_T("ntdll.dll"));
		NtCreateToken = (NT_CREATE_TOKEN)GetProcAddress(hModule, "NtCreateToken");

		tokenStructures tokenDeconstructed;
		HANDLE userToken = 0;
		HANDLE newToken = 0;


		HANDLE currentProcessHandle = GetCurrentProcess();
		if (!OpenProcessToken(currentProcessHandle, TOKEN_DUPLICATE | TOKEN_ALL_ACCESS, &userToken)) {
			wprintf(L"  Cannot aquire template token\n");
			return false;
		}
			

		//sample the token into individual structures
		deconstructToken(tokenDeconstructed, userToken);

		//add desired group to the token
		PTOKEN_GROUPS modifiedGroups = NULL;
		if (!addGroupToTokenGroups(sid, tokenDeconstructed, modifiedGroups)){
			wprintf(L"  Cannot add group to a token\n");
			return false;
		}

		//enable needed privileges
		if (!changeTokenCreationPrivilege(true)) {
			wprintf(L"  Cannot aquire needed privileges\n");
			return false;
		}

		//construct token
		NTSTATUS status = NtCreateToken(
			&newToken,
			tokenDeconstructed.accessMask,
			tokenDeconstructed.objectAttributes,
			tokenDeconstructed.tokenType,
			tokenDeconstructed.authenticationId,
			tokenDeconstructed.expirationTime,
			tokenDeconstructed.tokenUser,
			modifiedGroups,
			tokenDeconstructed.tokenPrivileges,
			tokenDeconstructed.tokenOwner,
			tokenDeconstructed.tokenPrimaryGroup,
			tokenDeconstructed.tokenDefaultDacl,
			tokenDeconstructed.tokenSource
		);

		//cleanup
		changeTokenCreationPrivilege(false);
		deallocateToken(tokenDeconstructed);
		delete[](BYTE*) modifiedGroups;

		if(!NT_SUCCESS(status)) {
			if (NT_ERROR(status)) {
				wprintf(L"  Cannot construct a token\n");
				return false;
			}
		}

		token = newToken;
		return true;
	}

}

//private functions

ULONG getCurrentSessionID() {
	DWORD count = 0;
	PWTS_SESSION_INFO  info;
	WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0,1,&info, &count);
	for (size_t i = 0; i < count; i++)
	{
		if (lstrcmp(info[i].pWinStationName, L"Console") == 0)
		{
			return info[i].SessionId;
		}

	}
	return 0;
}

//deconstructs the template token
void deconstructToken(tokenStructures &tokenDeconstructed, HANDLE &userToken) {

	DWORD bufferSize = 0;
	GetTokenInformation(userToken, TokenType, NULL, 0, &bufferSize);
	SetLastError(0);
	GetTokenInformation(userToken, TokenType, (LPVOID) &tokenDeconstructed.tokenType, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenUser, NULL, 0, &bufferSize);
	SetLastError(0);
	tokenDeconstructed.tokenUser = (PTOKEN_USER) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenUser, (LPVOID) tokenDeconstructed.tokenUser, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenGroups, NULL, 0, &bufferSize);
	SetLastError(0);
	tokenDeconstructed.tokenGroups = (PTOKEN_GROUPS) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenGroups, (LPVOID)tokenDeconstructed.tokenGroups, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenPrivileges, NULL, 0, &bufferSize);
	SetLastError(0);
	tokenDeconstructed.tokenPrivileges = (PTOKEN_PRIVILEGES) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenPrivileges, (LPVOID)tokenDeconstructed.tokenPrivileges, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenOwner, NULL, 0, &bufferSize);
	SetLastError(0);
	tokenDeconstructed.tokenOwner = (PTOKEN_OWNER) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenOwner, (LPVOID)tokenDeconstructed.tokenOwner, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenPrimaryGroup, NULL, 0, &bufferSize);
	SetLastError(0);
	tokenDeconstructed.tokenPrimaryGroup = (PTOKEN_PRIMARY_GROUP) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenPrimaryGroup, (LPVOID)tokenDeconstructed.tokenPrimaryGroup, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenDefaultDacl, NULL, 0, &bufferSize);
	SetLastError(0);
	tokenDeconstructed.tokenDefaultDacl = (PTOKEN_DEFAULT_DACL) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenDefaultDacl, (LPVOID)tokenDeconstructed.tokenDefaultDacl, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenSource, NULL, 0, &bufferSize);
	SetLastError(0);
	tokenDeconstructed.tokenSource = (PTOKEN_SOURCE) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenSource, (LPVOID)tokenDeconstructed.tokenSource, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenStatistics, NULL, 0, &bufferSize);
	SetLastError(0);
	PTOKEN_STATISTICS stats = (PTOKEN_STATISTICS) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenStatistics, (LPVOID)stats, bufferSize, &bufferSize);

	tokenDeconstructed.expirationTime = new LARGE_INTEGER{ stats->ExpirationTime };
	tokenDeconstructed.authenticationId = new LUID{ stats->AuthenticationId };

	

	tokenDeconstructed.accessMask = TOKEN_ALL_ACCESS;

	PSECURITY_QUALITY_OF_SERVICE sqos =
		new SECURITY_QUALITY_OF_SERVICE{ sizeof(SECURITY_QUALITY_OF_SERVICE), stats->ImpersonationLevel, SECURITY_STATIC_TRACKING, FALSE };
	POBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES{ sizeof(OBJECT_ATTRIBUTES), 0, 0, 0, 0, sqos };
	tokenDeconstructed.objectAttributes = oa;

	delete[](BYTE*) stats;
}


//adopted from MSDN example
BOOL setPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

bool changeTokenCreationPrivilege(bool privilegeStatus) {

	//keeping this for future debug purposes
	//will be important when implementing token capture for a token having SE_CREATE_TOKEN_NAME included
	/*
	DWORD bufferSize = 0;
	GetUserName(NULL, &bufferSize);
	LPTSTR pUserName = (LPTSTR) new BYTE[bufferSize * sizeof(TCHAR)];
	GetUserName(pUserName, &bufferSize);
	wprintf(L"User account accessed: %s\n", pUserName);
	delete[](BYTE*) pUserName;
	*/

	HANDLE currentProcessHandle;
	HANDLE userTokenHandle;
	currentProcessHandle = GetCurrentProcess();
	if (!OpenProcessToken(currentProcessHandle, TOKEN_ALL_ACCESS, &userTokenHandle)) {
		wprintf(L"Error getting token for privilege escalation\n");
		return false;
	}
	return setPrivilege(userTokenHandle, SE_CREATE_TOKEN_NAME, privilegeStatus);
}

bool addGroupToTokenGroups(PSID sid, tokenStructures &tokenDeconstructed, PTOKEN_GROUPS &newGroups) {
	PTOKEN_GROUPS tokenGroups = tokenDeconstructed.tokenGroups;
	DWORD groupCount = tokenGroups->GroupCount;
	SID_AND_ATTRIBUTES newGroup{ sid, SE_GROUP_ENABLED };

	PTOKEN_GROUPS tokenGroupsMod = (PTOKEN_GROUPS) new BYTE[(FIELD_OFFSET(TOKEN_GROUPS, Groups[groupCount+1]))];
	for (size_t i = 0; i < groupCount; i++)
	{
		tokenGroupsMod->Groups[i] = tokenGroups->Groups[i];
	}
	tokenGroupsMod->Groups[groupCount] = newGroup;
	tokenGroupsMod->GroupCount = groupCount + 1;

	newGroups = tokenGroupsMod;

	return true;
}

void deallocateToken(tokenStructures &tokenDeconstructed) {
	delete tokenDeconstructed.objectAttributes->SecurityQualityOfService;
	delete tokenDeconstructed.objectAttributes;
	delete tokenDeconstructed.authenticationId;
	delete tokenDeconstructed.expirationTime;
	delete[](BYTE*) tokenDeconstructed.tokenUser;
	delete[](BYTE*) tokenDeconstructed.tokenGroups;
	delete[](BYTE*) tokenDeconstructed.tokenPrivileges;
	delete[](BYTE*) tokenDeconstructed.tokenOwner;
	delete[](BYTE*) tokenDeconstructed.tokenPrimaryGroup;
	delete[](BYTE*) tokenDeconstructed.tokenDefaultDacl;
	delete[](BYTE*) tokenDeconstructed.tokenSource;
}
