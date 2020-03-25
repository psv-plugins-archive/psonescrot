/*
PSOneScrot
Copyright (C) 2020 浅倉麗子

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

#include <string.h>
#include <psp2/kernel/clib.h>
#include <psp2/kernel/modulemgr.h>
#include <taihen.h>

__attribute__ ((__format__ (__printf__, 1, 2)))
static void LOG(const char *fmt, ...) {
	#ifdef LOG_PRINTF
	sceClibPrintf("\033[0;36m[PSOneScrotCompat]\033[0m ");
	va_list args;
	va_start(args, fmt);
	sceClibVprintf(fmt, args);
	va_end(args);

	#else
	(void)fmt;

	#endif
}

#define GLZ(x) do {\
	if ((x) < 0) { goto fail; }\
} while (0)

#define N_HOOK 2
static SceUID hook_id[N_HOOK];
static tai_hook_ref_t hook_ref[N_HOOK];

static SceUID hook_import(int idx, char *mod, int libnid, int funcnid, void *func) {
	hook_id[idx] = taiHookFunctionImport(hook_ref+idx, mod, libnid, funcnid, func);
	LOG("Hooked %d UID %08X\n", idx, hook_id[idx]);
	return hook_id[idx];
}

#define HOOK_IMPORT(idx, mod, libnid, funcnid, func)\
	hook_import(idx, mod, libnid, funcnid, func##_hook)

static char *cdlg_compat_8105EB34 = 0;

static int sceClibMemcpy_safe_hook(void *dest, void *src, uint32_t size) {
	int ret = TAI_CONTINUE(int, hook_ref[0], dest, src, size);

	if (dest == cdlg_compat_8105EB34) {
		LOG("cdlg_compat_8105EB34 vaddr %08X\n", (int)cdlg_compat_8105EB34);
		char *cdlg_compat_8105EB45 = cdlg_compat_8105EB34 + 0x11;
		LOG("cdlg_compat_8105EB45 value %02X\n", *cdlg_compat_8105EB45);
		*cdlg_compat_8105EB45 = 0;
	}

	return ret;
}

static int ScePafMisc_AF4FC3F4_hook(void) {
	int ret = TAI_CONTINUE(int, hook_ref[1]);
	LOG("ScePafMisc_AF4FC3F4 RET %08X\n", ret);
	return 0;
}

static void startup(void) {
	memset(hook_id, 0xFF, sizeof(hook_id));
	memset(hook_ref, 0xFF, sizeof(hook_ref));
}

static void cleanup(void) {
	for (int i = 0; i < N_HOOK; i++) {
		if (hook_id[i] >= 0) {
			taiHookRelease(hook_id[i], hook_ref[i]);
			LOG("Unhooked %d UID %08X\n", i, hook_id[i]);
		}
	}
}

int _start() __attribute__ ((weak, alias("module_start")));
int module_start(SceSize argc, const void *argv) { (void)argc; (void)argv;
	startup();

	tai_module_info_t minfo;
	minfo.size = sizeof(minfo);
	GLZ(taiGetModuleInfo("SceCompatDialogPlugin", &minfo));

	SceKernelModuleInfo sce_minfo;
	sce_minfo.size = sizeof(sce_minfo);
	GLZ(sceKernelGetModuleInfo(minfo.modid, &sce_minfo));
	cdlg_compat_8105EB34 = sce_minfo.segments[1].vaddr + 0x1B34;

	GLZ(HOOK_IMPORT(0, "SceCompatDialogPlugin", 0xCAE9ACE6, 0x2E3B02A1, sceClibMemcpy_safe));
	GLZ(HOOK_IMPORT(1, "SceCompatDialogPlugin", 0x3D643CE8, 0xAF4FC3F4, ScePafMisc_AF4FC3F4));
	return SCE_KERNEL_START_SUCCESS;

fail:
	cleanup();
	return SCE_KERNEL_START_FAILED;
}

int module_stop(SceSize argc, const void *argv) { (void)argc; (void)argv;
	cleanup();
	return SCE_KERNEL_STOP_SUCCESS;
}
