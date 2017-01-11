#pragma once

#ifndef UNICODE
#define UNICODE
#endif 

#ifndef UTILFILE_H
#define UTILFILE_H

#include <Windows.h>


namespace util {
	/**
	* This function is now obsolete, this approach is a dead end
	* Function gets a SID of a group and creates a token with a group entry added in the token
	* @param sid pointer to sid to be added to the token
	* @param token reference to handle to requested token
	* @return true if success
	**/
	bool getModifiedToken(PSID sid, HANDLE &token);

	/**
	* Function gets a SID of a group and creates a token with a group entry added in the token
	* @param sid pointer to sid to be added to the token
	* @param token reference to handle to requested token
	* @return true if success
	**/
	bool constructUserTokenWithGroup(PSID sid, HANDLE &token);


}


#endif
