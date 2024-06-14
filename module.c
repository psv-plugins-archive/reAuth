/*
	Copyright (C) 2021 Reiko Asakura. All Rights Reserved.

	reAuth
*/

#include <libdbg.h>

#include "module.h"

#if defined(TAIHEN_KERNEL)
#define taiGetModuleInfo(...) taiGetModuleInfoForKernel(KERNEL_PID, ##__VA_ARGS__)
#endif

int get_module(const char *name, tai_module_info_t *info)
{
	info->size = sizeof(*info);
	int ret = taiGetModuleInfo(name, info);

	if (ret == 0) {
		SCE_DBG_LOG_INFO("Found module %s uid 0x%08X fingerprint 0x%08X", name, info->modid, info->module_nid);
	} else {
		SCE_DBG_LOG_ERROR("Failed to find module %s 0x%08X", name, ret);
	}

	return ret;
}
