/*
	Copyright (C) 2021 Reiko Asakura. All Rights Reserved.

	reAuth
*/

#include <libdbg.h>

#include "patch.h"

#if defined(TAIHEN_KERNEL)
#define taiHookFunctionImport(...) taiHookFunctionImportForKernel(KERNEL_PID, ##__VA_ARGS__)
#define taiHookFunctionExport(...) taiHookFunctionExportForKernel(KERNEL_PID, ##__VA_ARGS__)
#define taiHookFunctionOffset(...) taiHookFunctionOffsetForKernel(KERNEL_PID, ##__VA_ARGS__)
#define taiHookRelease taiHookReleaseForKernel
#endif

/* ARGSUSED */
static int hook_common(SceUID hook_id, const char *name)
{
	int ret = SCE_OK;
	if (hook_id < 0) {
		SCE_DBG_LOG_ERROR("Failed to hook %s 0x%08X", name, hook_id);
		ret = hook_id;
	} else {
		SCE_DBG_LOG_INFO("Hooked %s 0x%08X", name, hook_id);
	}
	return ret;
}

int hook_import(const char *module, uint32_t libnid, uint32_t funcnid, const void *func,
	SceUID *hook_id, tai_hook_ref_t *hook_ref, const char *name)
{
	*hook_id = taiHookFunctionImport(hook_ref, module, libnid, funcnid, func);
	return hook_common(*hook_id, name);
}

int hook_export(const char *module, uint32_t libnid, uint32_t funcnid, const void *func,
	SceUID *hook_id, tai_hook_ref_t *hook_ref, const char *name)
{
	*hook_id = taiHookFunctionExport(hook_ref, module, libnid, funcnid, func);
	return hook_common(*hook_id, name);
}

int hook_offset(SceUID modid, int segidx, uint32_t offset, int thumb, const void *func,
	SceUID *hook_id, tai_hook_ref_t *hook_ref, const char *name)
{
	*hook_id = taiHookFunctionOffset(hook_ref, modid, segidx, offset, thumb, func);
	return hook_common(*hook_id, name);
}

/* ARGSUSED */
int unhook(SceUID *hook_id, tai_hook_ref_t hook_ref, const char *name)
{
	int ret = SCE_OK;
	if (*hook_id < 0) {
		SCE_DBG_LOG_WARNING("Skipped unhooking %s %08X", name, *hook_id);
	} else {
		ret = taiHookRelease(*hook_id, hook_ref);
		if (ret == SCE_OK) {
			SCE_DBG_LOG_INFO("Unhooked %s %08X", name, *hook_id);
			*hook_id = -1;
		} else {
			SCE_DBG_LOG_ERROR("Failed to unhook %s %08X %08X", name, *hook_id, ret);
		}
	}
	return ret;
}
