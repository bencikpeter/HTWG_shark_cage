#include "stdafx.h"

#include <Windows.h>
#include "util.h"

int main() {
	HANDLE handle;
	PSID sid= 0;
	util::getModifiedToken(sid, handle);
	return 0;
}