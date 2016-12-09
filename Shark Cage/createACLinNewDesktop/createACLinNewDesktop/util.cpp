#include "util.h"

namespace util {
	HANDLE name(PSID sid) {
		//create a dummy group with no permissions
		//add user to that group
		//create token for that group
		//replace the dummy group in token with actual group
		//delete dummy group
		//return token
	}
}