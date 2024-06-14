/*
	Copyright (C) 2021 Reiko Asakura. All Rights Reserved.

	reAuth
*/

#include <kernel/libkernel.h>
#include <kernel/modulemgr.h>
#include <libdbg.h>

#include "patch.h"

#define HOSTNAME_OLD "native.np.ac.playstation.net"
#define HOSTNAME_NEW "native-vita.np.ac.playstation.net"

static SceUID sceHttpCreateConnection_hook_id = -1;
static tai_hook_ref_t sceHttpCreateConnection_hook_ref;

static SceInt32 sceHttpCreateConnection_hook(
	SceInt32 tmplId, const char *serverName, const char *scheme, SceUShort16 port, SceBool enableKeepalive)
{
	if (sceClibStrncmp(HOSTNAME_OLD, serverName, sizeof(HOSTNAME_OLD)) == 0) {
		serverName = HOSTNAME_NEW;
		SCE_DBG_LOG_INFO("Hostname redirected");
	}

	return HOOK_NEXT(sceHttpCreateConnection, tmplId, serverName, scheme, port, enableKeepalive);
}

static void cleanup(void) {
	UNHOOK(sceHttpCreateConnection);
}

int module_start()
{
	const char *module_name = NULL;
	tai_module_info_t minfo = {sizeof(minfo)};

	if (taiGetModuleInfo("SceShell", &minfo) == SCE_OK) {
		module_name = "SceShell";
	} else if (taiGetModuleInfo("SceNpCommerce2", &minfo) == SCE_OK) {
		module_name = "SceNpCommerce2";
	} else {
		return SCE_KERNEL_START_NO_RESIDENT;
	}

	SCE_DBG_LOG_INFO("Hooking module %s", module_name);

	if (HOOK_IMPORT(module_name, 0xE8F15CDE, 0xAEB3307E, sceHttpCreateConnection) < 0) {
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
