#pragma once

#ifndef UTILFILE_H
#define UTILFILE_H

#include <Windows.h>


namespace util {
	/**
	* Function gets a SID of a group and creates a token with a group entry added in the token
	* @param sid pointer to sid to be added to the token
	* @param token reference to handle to requested token
	* @return true if success
	**/
	HAbool name(PSID sid, HANDLE &token)
}


#endif
