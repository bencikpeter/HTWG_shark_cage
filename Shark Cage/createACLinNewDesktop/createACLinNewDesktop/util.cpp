#include "stdafx.h"
#include "util.h"
#include <LMaccess.h>
#include <lmerr.h>
#include <stdexcept>

#include <iostream>
#pragma comment(lib, "netapi32.lib")


bool emergencyExit(LPTSTR pUser_name); 

namespace util {

	LPWSTR  group_name = L"Dummy_group"; //TODO: this should be constant, fix the conversions

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
		GetUserName(NULL,&bufferSize);
		pUser_name = (LPTSTR) new BYTE[bufferSize];
		GetUserName(pUser_name, &bufferSize);
		LOCALGROUP_MEMBERS_INFO_3 localgroup_member_info;
		localgroup_member_info.lgrmi3_domainandname = pUser_name;
		if (NetLocalGroupAddMembers(NULL, group_name, 3, (LPBYTE) &localgroup_member_info, 1) != NERR_Success)
			return emergencyExit(pUser_name);

		//get user token (containig dummy group)
		 current_process_handle = GetCurrentProcess();
		 if (!OpenProcessToken(current_process_handle, TOKEN_ALL_ACCESS, &user_token_h))
			 return emergencyExit(pUser_name);


		//replace the dummy group in token with actual group - requires to know the sid of the dummy_group
		//change the hashes - how??


		//delete dummy group
		NetLocalGroupDel(NULL, group_name);

		//assign token to handle


		//exit sequence
		free(pUser_name);
		return true;
	}
}

bool emergencyExit(LPTSTR pUser_name) {
	NetLocalGroupDel(NULL, util::group_name);
	free(pUser_name);
	return false;
}