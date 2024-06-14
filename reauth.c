/*
	Copyright (C) 2021 Reiko Asakura. All Rights Reserved.

	reAuth
*/

#include <string.h>

#include <kernel/iofilemgr.h>
#include <kernel/modulemgr.h>
#include <kernel/sysmem.h>
#include <libdbg.h>
#include <libsysmodule.h>

#include "module.h"
#include "patch.h"

#define LIBHTTP_OLD "vs0:sys/external/libhttp.suprx"
#define LIBSSL_OLD "vs0:sys/external/libssl.suprx"

#define LIBHTTP_FUTURE "ur0:data/reAuth/libhttp.suprx"
#define LIBSSL_FUTURE "ur0:data/reAuth/libssl.suprx"

#define REAUTH_USER "ur0:data/reAuth/reAuth.suprx"

static SceUID sceKernelLoadStartSharedModuleForPid_hook_id = -1;
static tai_hook_ref_t sceKernelLoadStartSharedModuleForPid_hook_ref;

static SceUID sceSysmoduleLoadModule_impl_hook_id = -1;
static tai_hook_ref_t sceSysmoduleLoadModule_impl_hook_ref;

static SceUID sceSysmoduleUnloadModule_impl_hook_id = -1;
static tai_hook_ref_t sceSysmoduleUnloadModule_impl_hook_ref;

static int is_file_exists(const char *path)
{
	SceIoStat stat;
	return sceIoGetstat(path, &stat) == SCE_OK;
}

static SceUID sceKernelLoadStartSharedModuleForPid_hook(
	SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLoadModuleOpt *option, int *status)
{
	if (strncmp(LIBHTTP_OLD, path, sizeof(LIBHTTP_OLD)) == 0) {
		path = LIBHTTP_FUTURE;
		SCE_DBG_LOG_INFO("Redirected libhttp");
	} else if (strncmp(LIBSSL_OLD, path, sizeof(LIBSSL_OLD)) == 0) {
		path = LIBSSL_FUTURE;
		SCE_DBG_LOG_INFO("Redirected libssl");
	}

	return HOOK_NEXT(sceKernelLoadStartSharedModuleForPid, pid, path, args, argp, flags, option, status);
}

static SceInt32 sceSysmoduleLoadModule_impl_hook(SceUInt32 id, void *args)
{
	int ret = HOOK_NEXT(sceSysmoduleLoadModule_impl, id, args);

	if (ret == SCE_OK) {
		int pid = sceKernelGetProcessId();
		int is_shell = pid == sceKernelSysrootGetShellPid();

		id &= ~0x40000000;

		if ((id == SCE_SYSMODULE_HTTPS && is_shell) || (id == SCE_SYSMODULE_NP_COMMERCE2 && !is_shell)) {
			int tpidruro = __builtin_mrc(15, 0, 13, 0, 3);
			__builtin_mcr(15, 0, 13, 0, 3, tpidruro & ~1);
			int ret2 = sceKernelLoadStartModuleForPid(pid, REAUTH_USER, 0, NULL, 0, NULL, NULL);
			__builtin_mcr(15, 0, 13, 0, 3, tpidruro);

			if (ret2 < 0) {
				SCE_DBG_LOG_ERROR("Failed to start reAuthUser 0x%08X", ret2);
			} else {
				SCE_DBG_LOG_INFO("Started reAuthUser 0x%08X", ret2);
			}
		}
	}

	return ret;
}

static SceInt32 sceSysmoduleUnloadModule_impl_hook(SceUInt32 id, void *args)
{
	int pid = sceKernelGetProcessId();
	int is_shell = pid == sceKernelSysrootGetShellPid();
	int id_ = id & ~0x40000000;

	if ((id_ == SCE_SYSMODULE_HTTPS && is_shell) || (id_ == SCE_SYSMODULE_NP_COMMERCE2 && !is_shell)) {
		tai_module_info_t minfo = {sizeof(minfo)};

		if (taiGetModuleInfoForKernel(pid, "reAuthUser", &minfo) == SCE_OK) {
			int uid = sceKernelKernelUidForUserUid(pid, minfo.modid);

			int tpidruro = __builtin_mrc(15, 0, 13, 0, 3);
			__builtin_mcr(15, 0, 13, 0, 3, tpidruro & ~1);
			int ret2 = sceKernelStopUnloadModuleForPid(pid, uid, 0, NULL, 0, NULL, NULL);
			__builtin_mcr(15, 0, 13, 0, 3, tpidruro);

			if (ret2 < 0) {
				SCE_DBG_LOG_ERROR("Failed to unload reAuthUser 0x%08X", ret2);
			} else {
				SCE_DBG_LOG_INFO("Unloaded reAuthUser");
			}
		}
	}

	return HOOK_NEXT(sceSysmoduleUnloadModule_impl, id, args);
}

static void cleanup(void)
{
	UNHOOK(sceKernelLoadStartSharedModuleForPid);
	UNHOOK(sceSysmoduleLoadModule_impl);
	UNHOOK(sceSysmoduleUnloadModule_impl);
}

int module_start()
{
	tai_module_info_t minfo;
	SceInt32 SceSysmodule_uid;

	if (sceKernelSysrootGetShellPid() >= 0) {
		SCE_DBG_LOG_ERROR("SceShell already started");
		return SCE_KERNEL_START_NO_RESIDENT;
	}

	if (!is_file_exists(LIBHTTP_FUTURE)) {
		SCE_DBG_LOG_ERROR("%s not found", LIBHTTP_FUTURE);
		goto fail;
	}

	if (!is_file_exists(LIBSSL_FUTURE)) {
		SCE_DBG_LOG_ERROR("%s not found", LIBSSL_FUTURE);
		goto fail;
	}

	if (!is_file_exists(REAUTH_USER)) {
		SCE_DBG_LOG_ERROR("%s not found", REAUTH_USER);
		goto fail;
	}

	if (HOOK_IMPORT("SceSysmodule", 0xD4A60A52, 0xE2ADEF8D, sceKernelLoadStartSharedModuleForPid) < 0) {
		goto fail;
	}

	if (GET_MODULE("SceSysmodule", &minfo) < 0) {
		goto fail;
	}
	SceSysmodule_uid = minfo.modid;

	if (HOOK_OFFSET(SceSysmodule_uid, 0, 0x230, 1, sceSysmoduleLoadModule_impl) < 0) {
		goto fail;
	}

	if (HOOK_OFFSET(SceSysmodule_uid, 0, 0x614, 1, sceSysmoduleUnloadModule_impl) < 0) {
		goto fail;
	}

	return SCE_KERNEL_START_SUCCESS;

fail:
	cleanup();
	return SCE_KERNEL_START_FAILED;
}

int module_stop()
{
	cleanup();
	return SCE_KERNEL_STOP_SUCCESS;
}
