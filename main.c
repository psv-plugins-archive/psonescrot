/*
This file is part of PSOneScrot
Copyright 2020 浅倉麗子

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Author: 浅倉麗子

#include <stdarg.h>
#include <string.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/io/stat.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <taihen.h>

__attribute__ ((__format__ (__printf__, 1, 2)))
static void LOG(const char *fmt, ...) {
	#ifdef LOG_PRINTF
	ksceDebugPrintf("\033[0;35m[PSOneScrotKernel]\033[0m ");
	va_list args;
	va_start(args, fmt);
	ksceDebugVprintf(fmt, args);
	va_end(args);

	#else
	(void)fmt;

	#endif
}

#define GLZ(x) do {\
	if ((x) < 0) { goto fail; }\
} while (0)

static int (*sceKernelGetModuleInfo)(SceUID pid, SceUID mid, SceKernelModuleInfo *minfo);

#define N_HOOK 3
static SceUID hook_id[N_HOOK];
static tai_hook_ref_t hook_ref[N_HOOK];

static SceUID hook_export(int idx, char *mod, int libnid, int funcnid, void *func) {
	hook_id[idx] = taiHookFunctionExportForKernel(
		KERNEL_PID, hook_ref+idx, mod, libnid, funcnid, func);
	LOG("Hooked %d UID %08X\n", idx, hook_id[idx]);
	return hook_id[idx];
}

#define HOOK_EXPORT(idx, mod, libnid, funcnid, func)\
	hook_export(idx, mod, libnid, funcnid, func##_hook)

extern int module_get_by_name_nid(SceUID pid, const char *name, uint32_t nid, tai_module_info_t *info);
#define GET_MODULE(pid, name, info)\
	module_get_by_name_nid(pid, name, TAI_IGNORE_MODULE_NID, info)

extern int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);
#define GET_EXPORT(mod, lib, func, fptr)\
	module_get_export_func(KERNEL_PID, mod, lib, func, (uintptr_t*)fptr)

#define SYSCALL(x) do {\
	int state;\
	ENTER_SYSCALL(state);\
	(x);\
	EXIT_SYSCALL(state);\
} while (0)

#define GET_PID_TID\
	int pid = ksceKernelGetProcessId();\
	char tid[0x20] = {};\
	ksceKernelGetProcessTitleId(pid, tid, sizeof(tid));

#define GET_MINFO\
	SceKernelModuleInfo minfo;\
	memset(&minfo, 0x00, sizeof(minfo));\
	minfo.size = sizeof(minfo);\
	sceKernelGetModuleInfo(pid, ksceKernelKernelUidForUserUid(pid, mid), &minfo);

extern char scrot_compat_suprx[];
extern int scrot_compat_suprx_len;
#define BASE_DIR          "ux0:data/"
#define SCROT_DIR         BASE_DIR "PSOneScrot/"
#define SCROT_COMPAT_PATH SCROT_DIR "psonescrot.suprx"
static int scrot_id = -1;

static int sceKernelInhibitLoadingModule_hook(int r0) {
	int ret;
	GET_PID_TID

	tai_module_info_t minfo;
	minfo.size = sizeof(minfo);

	// Do not inhibit if call from a Pspemu process
	if (GET_MODULE(SCE_KERNEL_PROCESS_ID_SELF, "ScePspemu", &minfo) == 0) {
		ret = 0;
		LOG("Uninhibited PID %08X TID %s\n", pid, tid);
	} else {
		ret = TAI_CONTINUE(int, hook_ref[0], r0);
		LOG("Inhibited PID %08X TID %s\n", pid, tid);
	}
	return ret;
}

static int sceKernelStartModule_hook(int mid, int args, void *argp, void *params) {
	int ret;
	GET_PID_TID
	GET_MINFO

	ret = TAI_CONTINUE(int, hook_ref[1], mid, args, argp, params);
	LOG("Started PID %08X TID %s MID %08X RET %08X name %s\n", pid, tid, mid, ret, minfo.module_name);

	if (ret == 0 && strcmp(minfo.module_name, "SceCompatDialogPlugin") == 0) {
		SYSCALL(scrot_id = ksceKernelLoadStartModuleForPid(pid, SCROT_COMPAT_PATH, 0, NULL, 0, NULL, NULL));
		LOG("Loaded and started PSOneScrotCompat MID %08X\n", scrot_id);
	}

	return ret;
}

static int sceKernelStopModule_hook(int mid, int args, void *argp, void *params) {
	int ret;
	GET_PID_TID
	GET_MINFO

	if (scrot_id >= 0 && strcmp(minfo.module_name, "SceCompatDialogPlugin") == 0) {
		int ret;
		SYSCALL(ret = ksceKernelStopUnloadModuleForPid(pid, scrot_id, 0, NULL, 0, NULL, NULL));
		LOG("Stopped and unloaded PSOneScrotCompat RET %08X\n", ret);
		scrot_id = -1;
	}

	ret = TAI_CONTINUE(int, hook_ref[2], mid, args, argp, params);
	LOG("Stopped PID %08X TID %s MID %08X RET %08X name %s\n", pid, tid, mid, ret, minfo.module_name);

	return ret;
}

static int extract_scrot_user(void) {
	ksceIoMkdir(BASE_DIR, 0777);
	ksceIoMkdir(SCROT_DIR, 0777);
	SceUID fd = ksceIoOpen(SCROT_COMPAT_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
	if (fd < 0) {
		LOG("Failed to open %s\n", SCROT_COMPAT_PATH);
		return fd;
	}
	LOG("Opened file %s\n", SCROT_COMPAT_PATH);

	int ret = ksceIoWrite(fd, scrot_compat_suprx, scrot_compat_suprx_len);
	ksceIoClose(fd);
	if (ret == scrot_compat_suprx_len) {
		LOG("Extracted %d bytes\n", ret);
		return 0;
	} else {
		LOG("Extraction failed %08X\n", ret);
		return -1;
	}
}

static void startup(void) {
	memset(hook_id, 0xFF, sizeof(hook_id));
	memset(hook_ref, 0xFF, sizeof(hook_ref));
}

static void cleanup(void) {
	for (int i = 0; i < N_HOOK; i++) {
		if (hook_id[i] >= 0) {
			taiHookReleaseForKernel(hook_id[i], hook_ref[i]);
			LOG("Unhooked %d UID %08X\n", i, hook_id[i]);
		}
	}
}

int _start() __attribute__ ((weak, alias("module_start")));
int module_start(SceSize argc, const void *argv) { (void)argc; (void)argv;
	startup();

	GLZ(extract_scrot_user());

	if (GET_EXPORT("SceKernelModulemgr", 0xC445FA63, 0xD269F915, &sceKernelGetModuleInfo) < 0
			&& GET_EXPORT("SceKernelModulemgr", 0x92C9FFC2, 0xDAA90093, &sceKernelGetModuleInfo) < 0) {
		LOG("Failed to find sceKernelGetModuleInfo\n");
		goto fail;
	}
	LOG("Found sceKernelGetModuleInfo\n");

	GLZ(HOOK_EXPORT(0, "SceKernelModulemgr", 0xEAED1616, 0x6CED1F63, sceKernelInhibitLoadingModule));
	GLZ(HOOK_EXPORT(1, "SceKernelModulemgr", 0xEAED1616, 0x72CD301F, sceKernelStartModule));
	GLZ(HOOK_EXPORT(2, "SceKernelModulemgr", 0xEAED1616, 0x086867A8, sceKernelStopModule));
	return SCE_KERNEL_START_SUCCESS;

fail:
	cleanup();
	return SCE_KERNEL_START_FAILED;
}

int module_stop(SceSize argc, const void *argv) { (void)argc; (void)argv;
	cleanup();
	return SCE_KERNEL_STOP_SUCCESS;
}
