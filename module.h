/*
	Copyright (C) 2021 Reiko Asakura. All Rights Reserved.

	reAuth
*/

#pragma once

#include <taihen.h>

#define GET_MODULE(name, info) \
	get_module(name, info)

int get_module(const char *name, tai_module_info_t *info);
