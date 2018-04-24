#include "stdafx.h"
#include "util.h"
#include <LMaccess.h>
#include <lmerr.h>
#include <stdexcept>
#include <Sddl.h>
#include <Wtsapi32.h>
#include <Winternl.h>


#include <iostream>
#include <stdio.h>
#pragma comment(lib, "netapi32.lib")

class tokenStructures {
public:
	ACCESS_MASK			AccessMask; //OK
	POBJECT_ATTRIBUTES	ObjectAttributes; //OK
	TOKEN_TYPE			TokenType; //OK
	PLUID				AuthenticationId; //OK
	PLARGE_INTEGER		ExpirationTime; //OK
	PTOKEN_USER         TokenUser; //OK
	PTOKEN_GROUPS       TokenGroups; //OK
	PTOKEN_PRIVILEGES   TokenPrivileges; //OK
	PTOKEN_OWNER        TokenOwner; //OK
	PTOKEN_PRIMARY_GROUP TokenPrimaryGroup; //OK
	PTOKEN_DEFAULT_DACL TokenDefaultDacl; //OK
	PTOKEN_SOURCE       TokenSource; //OK
};

bool emergencyExit(LPTSTR pUser_name); 
void enumerateSidsAndHashes(PTOKEN_ACCESS_INFORMATION pToken);
ULONG getCurrentSessionID();
void deconstructToken(tokenStructures &tokenDeconstructed, HANDLE &userToken);



namespace util {

	LPWSTR  group_name = L"Dummy_group"; //TODO: this should be constant, fix the conversions


	//this is all obsolete now  - keeping this only for grading purposes
	//reason: there is no way to arbitrarilly add a group to the token
	//we are going to create a new token from scratch using NtCreateToken
	bool getModifiedToken(PSID sid, HANDLE &token) {


		LOCALGROUP_INFO_0 localgroup_info;
		LPTSTR   pUser_name = NULL;
		HANDLE current_process_handle;
		HANDLE user_token_h;
		DWORD bufferSize = 0;


		//create a dummy group
		localgroup_info.lgrpi0_name = group_name;
		if (NetLocalGroupAdd(NULL, 0, (LPBYTE)&localgroup_info, NULL) != NERR_Success)
			return emergencyExit(pUser_name);


		//add user to that group
		GetUserName(NULL, &bufferSize);
		pUser_name = (LPTSTR) new BYTE[bufferSize];
		GetUserName(pUser_name, &bufferSize);
		LOCALGROUP_MEMBERS_INFO_3 localgroup_member_info;
		localgroup_member_info.lgrmi3_domainandname = pUser_name;
		if (NetLocalGroupAddMembers(NULL, group_name, 3, (LPBYTE)&localgroup_member_info, 1) != NERR_Success)
			return emergencyExit(pUser_name);

		//get user token (containig dummy group) - TODO: I need handle of a different process this one does not have the priviledge
		current_process_handle = GetCurrentProcess();
		if (!OpenProcessToken(current_process_handle, TOKEN_ALL_ACCESS, &user_token_h))
			return emergencyExit(pUser_name);

		bufferSize = 0;
		GetTokenInformation(user_token_h, TokenAccessInformation, NULL, 0, &bufferSize);
		PTOKEN_ACCESS_INFORMATION pTokenUser = (PTOKEN_ACCESS_INFORMATION) new BYTE[bufferSize];
		memset(pTokenUser, 0, bufferSize);
		GetTokenInformation(user_token_h, TokenAccessInformation, pTokenUser, bufferSize, &bufferSize);

		enumerateSidsAndHashes(pTokenUser);
		//replace the dummy group in token with actual group - requires to know the sid of the dummy_group
		//change the hashes - how - not possible  - one hash for all of the tokens - aborting this approach


		//delete dummy group
		NetLocalGroupDel(NULL, group_name);

		//assign token to handle


		//exit sequence
		free(pUser_name);
		return true;
	}

	bool constructUserTokenWithGroup(PSID sid, HANDLE &token) {

		//load internal NtCreateToken function
		typedef NTSTATUS (__stdcall *NT_CREATE_TOKEN)(
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

		ULONG sessionID = 0;
		tokenStructures tokenDeconstructed;
		HANDLE userToken = 0;
		HANDLE newToken = (HANDLE) 30;

		sessionID = getCurrentSessionID();
		WTSQueryUserToken(sessionID, &userToken); //local system permissions required

		//sample the token into individual structures
		deconstructToken(tokenDeconstructed, userToken);

		//TODO: modify the groups part
		PSID pSid = tokenDeconstructed.TokenUser->User.Sid;
		LPOLESTR stringSid = NULL;
		ConvertSidToStringSid(pSid, &stringSid);
		wprintf(L"  %s\r", stringSid);


		//construct token
		NtCreateToken(
			&newToken,
			tokenDeconstructed.AccessMask,
			tokenDeconstructed.ObjectAttributes,
			tokenDeconstructed.TokenType,
			tokenDeconstructed.AuthenticationId,
			tokenDeconstructed.ExpirationTime,
			tokenDeconstructed.TokenUser,
			tokenDeconstructed.TokenGroups,
			tokenDeconstructed.TokenPrivileges,
			tokenDeconstructed.TokenOwner,
			tokenDeconstructed.TokenPrimaryGroup,
			tokenDeconstructed.TokenDefaultDacl,
			tokenDeconstructed.TokenSource
		);

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

void deconstructToken(tokenStructures &tokenDeconstructed, HANDLE &userToken) {
	DWORD bufferSize = 0;

	GetTokenInformation(userToken, TokenType, NULL, 0, &bufferSize);
	GetTokenInformation(userToken, TokenType, (LPVOID) tokenDeconstructed.TokenType, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenUser, NULL, 0, &bufferSize);
	tokenDeconstructed.TokenUser = (PTOKEN_USER) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenUser, (LPVOID) tokenDeconstructed.TokenUser, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenGroups, NULL, 0, &bufferSize);
	tokenDeconstructed.TokenGroups = (PTOKEN_GROUPS) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenGroups, (LPVOID)tokenDeconstructed.TokenGroups, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenPrivileges, NULL, 0, &bufferSize);
	tokenDeconstructed.TokenPrivileges = (PTOKEN_PRIVILEGES) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenPrivileges, (LPVOID)tokenDeconstructed.TokenPrivileges, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenOwner, NULL, 0, &bufferSize);
	tokenDeconstructed.TokenOwner = (PTOKEN_OWNER) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenOwner, (LPVOID)tokenDeconstructed.TokenOwner, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenPrimaryGroup, NULL, 0, &bufferSize);
	tokenDeconstructed.TokenPrimaryGroup = (PTOKEN_PRIMARY_GROUP) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenPrimaryGroup, (LPVOID)tokenDeconstructed.TokenPrimaryGroup, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenDefaultDacl, NULL, 0, &bufferSize);
	tokenDeconstructed.TokenDefaultDacl = (PTOKEN_DEFAULT_DACL) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenDefaultDacl, (LPVOID)tokenDeconstructed.TokenDefaultDacl, bufferSize, &bufferSize);

	bufferSize = 0;
	GetTokenInformation(userToken, TokenSource, NULL, 0, &bufferSize);
	tokenDeconstructed.TokenSource = (PTOKEN_SOURCE) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenSource, (LPVOID)tokenDeconstructed.TokenSource, bufferSize, &bufferSize);

	//not sure about this section
	//among others, there is a memory leak here
	tokenDeconstructed.AccessMask = TOKEN_ALL_ACCESS;
	PSECURITY_QUALITY_OF_SERVICE sqos =
	new SECURITY_QUALITY_OF_SERVICE { sizeof sqos, SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE };
	POBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES{ sizeof oa, 0, 0, 0, 0, sqos };
	tokenDeconstructed.ObjectAttributes = oa;
	tokenDeconstructed.ExpirationTime = 0; //0=infinity - not supported yet

	//this is very ugly memory leak
	PLUID auth_luid_7 = new LUID(ANONYMOUS_LOGON_LUID); //this works for win 7 and below
	PLUID auth_luid_8 = new LUID(LOCALSERVICE_LUID); //this works for win 8 and further
	tokenDeconstructed.AuthenticationId  = auth_luid_8;

}

bool emergencyExit(LPTSTR pUser_name) {
	NetLocalGroupDel(NULL, util::group_name);
	free(pUser_name);
	return false;
}

void enumerateSidsAndHashes(PTOKEN_ACCESS_INFORMATION pToken) {
	PSID_AND_ATTRIBUTES_HASH hashes = pToken->SidHash;
	for (size_t i = 0; i < hashes->SidCount; ++i) {

		SID_AND_ATTRIBUTES &sidAndAttributes = hashes->SidAttr[i];
		PSID pSid = sidAndAttributes.Sid;
		LPOLESTR stringSid = NULL;
		ConvertSidToStringSid(pSid, &stringSid);
		wprintf(L"  %s\r", stringSid);
		SID_HASH_ENTRY &sidHashEntry = hashes->Hash[i];
		wprintf(L"  %u\r\n", sidHashEntry);
		LocalFree(stringSid);
		getchar();
	}
}