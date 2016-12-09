#pragma once

#ifndef UTILFILE_H
#define UTILFILE_H

#include <Windows.h>

namespace util {
	/**
	* Function gets a SID of a group and creates a token with a group entry added in the token
	* @param sid pointer to sid to be added to the token
	* @return handle to the token
	**/
	HANDLE name (PSID sid);
}


#endif
