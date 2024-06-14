/*
	Copyright (C) 2021 Reiko Asakura. All Rights Reserved.

	reAuth
*/

#pragma once

#include <taihen.h>

#define HOOK_NEXT(func, ...) \
	TAI_NEXT(func##_hook, func##_hook_ref, ##__VA_ARGS__)

#if SCE_DBG_LOGGING_ENABLED

#define HOOK_IMPORT(module, libnid, funcnid, func) \
	hook_import(module, libnid, funcnid, func##_hook, &func##_hook_id, &func##_hook_ref, #func)

#define HOOK_EXPORT(module, libnid, funcnid, func) \
	hook_export(module, libnid, funcnid, func##_hook, &func##_hook_id, &func##_hook_ref, #func)

#define HOOK_OFFSET(modid, segidx, offset, thumb, func) \
	hook_offset(modid, segidx, offset, thumb, func##_hook, &func##_hook_id, &func##_hook_ref, #func)

#define UNHOOK(func) \
	unhook(&func##_hook_id, func##_hook_ref, #func)

#else /* SCE_DBG_LOGGING_ENABLED */

#define HOOK_IMPORT(module, libnid, funcnid, func) \
	hook_import(module, libnid, funcnid, func##_hook, &func##_hook_id, &func##_hook_ref, "")

#define HOOK_EXPORT(module, libnid, funcnid, func) \
	hook_export(module, libnid, funcnid, func##_hook, &func##_hook_id, &func##_hook_ref, "")

#define HOOK_OFFSET(modid, segidx, offset, thumb, func) \
	hook_offset(modid, segidx, offset, thumb, func##_hook, &func##_hook_id, &func##_hook_ref, "")

#define UNHOOK(func) \
	unhook(&func##_hook_id, func##_hook_ref, "")

#endif /* SCE_DBG_LOGGING_ENABLED */

int hook_import(const char *module, uint32_t libnid, uint32_t funcnid, const void *func,
	SceUID *hook_id, tai_hook_ref_t *hook_ref, const char *name);

int hook_export(const char *module, uint32_t libnid, uint32_t funcnid, const void *func,
	SceUID *hook_id, tai_hook_ref_t *hook_ref, const char *name);

int hook_offset(SceUID modid, int segidx, uint32_t offset, int thumb, const void *func,
	SceUID *hook_id, tai_hook_ref_t *hook_ref, const char *name);

int unhook(SceUID *hook_id, tai_hook_ref_t hook_ref, const char *name);
