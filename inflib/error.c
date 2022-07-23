#include "infect.h"
#include "finfect.h"
#include "error.h"

const char *err2str(int err)
{
	switch (err) {
	case INFLIB_ERR_NO_CR_METHOD:
		return "No suitable control redirection method found";
	case INFLIB_ERR_NO_INF_METHOD:
		return "No suitable infection method found";
	case INFLIB_ERR_INST_FAILURE:
		return "Installation of a stub failed";
	case INFLIB_ERR_ISNOT_X86_PE:
		return "File is not an x86 PE";
	case INFLIB_ERR_TOO_MANY_SECTIONS:
		return "The PE file has too many sections";
	case INFLIB_ERR_HAS_TLS:
		return "The PE file has a TLS callback(s)";
	case INFLIB_ERR_HAS_CERT:
		return "The PE file has an integrity certificate(s)";
	case INFLIB_ERR_IS_MANAGED_CODE:
		return "The PE file is a managed code (.Net PE file)";
	case INFLIB_ERR_DONT_INFECT:
		return "The custom infection callback doesn't want the PE to be infected";
	case INFLIB_ERR_FILE_IO:
		return "An error occured while mapping the file";
	default:
		return NULL;
	}
}