#pragma once

#ifndef UNICODE
#define UNICODE
#endif 

#ifndef UTILFILE_H
#define UTILFILE_H

#include <Windows.h>


namespace tokenLib {
	/**
	* Function gets a SID of a group and creates a token with a group entry added in the token
	* Source of the token is the token of the process itself. Returned token is identical to the calling process token, just includes one more group
	* SE_CREATE_TOKEN_NAME must be held and enabled by a calling process, to successfully call this method
	* Mind that there are security implications to the current implementations - such that f.x.:
	* every process launched with token created by this function has SE_CREATE_TOKEN_NAME privilege, granting it basically any access to the system
	* This can be mitigated by calling CreateRestrictedToken() function on the output of this method
	* @param sid pointer to sid to be added to the token (IN)
	* @param token reference to handle to requested token (OUT)
	* @return true if success
	**/
	bool constructUserTokenWithGroup(PSID sid, HANDLE &token);

	//alternative token sourcing: 
	//another approach would be to use wtsQueryUserToken and determine session of current user
	//(this would require to run under a local system and have SE_CREATE_TOKEN_NAME at the same time  - which is suprisingly hard to achieve)
	//one more alternative is just to outsource the token aqusition and just take a handle to the template token as an input parameter

	/**
	* Creates a new local group with a name groupName and returns it�s SID. To deallocate returned sid, use destroySid() fucntion.
	* @param groupName string literal representing the name of the group (IN)
	* @param sid reference to the new group sid, NULL if function fails (OUT)
	* @return true if success
	**/
	bool createLocalGroup(LPWSTR groupName, PSID &sid);

	/**
	* Deletes a local group named groupName
	* @param groupName name of the group to be deleted
	* @return true if success
	**/
	bool deleteLocalGroup(LPWSTR groupName);

	/**
	* Deallocates an SID returned by createLocalGroup() function and sets the pointer to NULL;
	* @param sid pointer to sid alllocated by createLocalGroup()
	* @return true if success
	**/
	bool destroySid(PSID &sid);


}


#endif
