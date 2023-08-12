#include <Windows.h>
#include <iostream>
#include <string>
HANDLE hCSGO;

void OpenCSGO() {
	HWND hwGame = FindWindowW(0, L"Counter-Strike: Global Offensive - Direct3D 9");
	if (!hwGame) return;
	DWORD pid;
	GetWindowThreadProcessId(hwGame, &pid);
	hCSGO = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
}

std::wstring SelectDll() {
	OPENFILENAMEW ofn = { 0 };
	WCHAR szFile[MAX_PATH];
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = szFile;
	ofn.lpstrFile[0] = '\0';
	ofn.nFilterIndex = 1;
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = L"DLL File\0*.dll";
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	if (GetOpenFileNameW(&ofn)) {
		return ofn.lpstrFile;
	}
	else {
		return L"";
	}
}

bool InjectDll(std::wstring& path) {
	LPVOID allocatedMem = VirtualAllocEx(hCSGO, NULL, 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!allocatedMem)return false;
	WriteProcessMemory(hCSGO, allocatedMem, path.c_str(), path.length() * 2, NULL);
	HANDLE hThread = CreateRemoteThread(hCSGO, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, allocatedMem, 0, 0);
	if (!hThread)return false;
	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hCSGO, allocatedMem, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	return true;
}

namespace HookBypass {
	void LoadLib() {
		if (!GetModuleHandleW(L"kernel32")) LoadLibraryW(L"kernel32");
		if (!GetModuleHandleW(L"ntdll")) LoadLibraryW(L"ntdll");
		if (!GetModuleHandleW(L"KernelBase")) LoadLibraryW(L"KernelBase");
	}

	BOOL UnhookMethod(const char* methodName, const wchar_t* dllName, PBYTE save_origin_bytes) {
		LPVOID oriMethodAddr = GetProcAddress(GetModuleHandleW(dllName), methodName);
		if (!oriMethodAddr) return FALSE;
		PBYTE originalGameBytes[6];
		ReadProcessMemory(hCSGO, oriMethodAddr, originalGameBytes, sizeof(char) * 6, NULL);
		memcpy_s(save_origin_bytes, sizeof(char) * 6, originalGameBytes, sizeof(char) * 6);
		PBYTE originalDllBytes[6];
		memcpy_s(originalDllBytes, sizeof(char) * 6, oriMethodAddr, sizeof(char) * 6);
		return WriteProcessMemory(hCSGO, oriMethodAddr, originalDllBytes, sizeof(char) * 6, NULL);
	}

	BOOL RestoreOriginalHook(const char* methodName, const wchar_t* dllName, PBYTE save_origin_bytes) {
		LPVOID oriMethodAddr = GetProcAddress(GetModuleHandleW(dllName), methodName);
		if (!oriMethodAddr) return FALSE;
		return WriteProcessMemory(hCSGO, oriMethodAddr, save_origin_bytes, sizeof(char) * 6, NULL);
	}

	enum MethodNum {
		LOADLIBEXW = 1,
		VIRALLOC = 2,
		FREELIB = 3,
		LOADLIBEXA = 4,
		LOADLIBW = 5,
		LOADLIBA = 6,
		VIRALLOCEX = 7,
		LDRLOADDLL = 10,
		NTOPENFILE = 11,
		VIRPROT = 12,
		CREATPROW = 13,
		CREATPROA = 14,
		VIRPROTEX = 15,
		FREELIB_ = 16,
		LOADLIBEXA_ = 17,
		LOADLIBEXW_ = 18,
		RESUMETHREAD = 19,
	};
	BYTE originalGameBytess[30][6];
	BOOL BypassCSGO_hook() {
		BOOL res = TRUE;
		res &= UnhookMethod("LoadLibraryExW", L"kernel32", originalGameBytess[LOADLIBEXW]);
		res &= UnhookMethod("VirtualAlloc", L"kernel32", originalGameBytess[VIRALLOC]);
		res &= UnhookMethod("FreeLibrary", L"kernel32", originalGameBytess[FREELIB]);
		res &= UnhookMethod("LoadLibraryExA", L"kernel32", originalGameBytess[LOADLIBEXA]);
		res &= UnhookMethod("LoadLibraryW", L"kernel32", originalGameBytess[LOADLIBW]);
		res &= UnhookMethod("LoadLibraryA", L"kernel32", originalGameBytess[LOADLIBA]);
		res &= UnhookMethod("VirtualAllocEx", L"kernel32", originalGameBytess[VIRALLOCEX]);
		res &= UnhookMethod("LdrLoadDll", L"ntdll", originalGameBytess[LDRLOADDLL]);
		res &= UnhookMethod("NtOpenFile", L"ntdll", originalGameBytess[NTOPENFILE]);
		res &= UnhookMethod("VirtualProtect", L"kernel32", originalGameBytess[VIRPROT]);
		res &= UnhookMethod("CreateProcessW", L"kernel32", originalGameBytess[CREATPROW]);
		res &= UnhookMethod("CreateProcessA", L"kernel32", originalGameBytess[CREATPROA]);
		res &= UnhookMethod("VirtualProtectEx", L"kernel32", originalGameBytess[VIRPROTEX]);
		res &= UnhookMethod("FreeLibrary", L"KernelBase", originalGameBytess[FREELIB_]);
		res &= UnhookMethod("LoadLibraryExA", L"KernelBase", originalGameBytess[LOADLIBEXA_]);
		res &= UnhookMethod("LoadLibraryExW", L"KernelBase", originalGameBytess[LOADLIBEXW_]);
		res &= UnhookMethod("ResumeThread", L"KernelBase", originalGameBytess[RESUMETHREAD]);
		return res;
	}
	BOOL RestoreCSGO_hook() {
		BOOL res = TRUE;
		res &= RestoreOriginalHook("LoadLibraryExW", L"kernel32", originalGameBytess[LOADLIBEXW]);
		res &= RestoreOriginalHook("VirtualAlloc", L"kernel32", originalGameBytess[VIRALLOC]);
		res &= RestoreOriginalHook("FreeLibrary", L"kernel32", originalGameBytess[FREELIB]);
		res &= RestoreOriginalHook("LoadLibraryExA", L"kernel32", originalGameBytess[LOADLIBEXA]);
		res &= RestoreOriginalHook("LoadLibraryW", L"kernel32", originalGameBytess[LOADLIBW]);
		res &= RestoreOriginalHook("LoadLibraryA", L"kernel32", originalGameBytess[LOADLIBA]);
		res &= RestoreOriginalHook("VirtualAllocEx", L"kernel32", originalGameBytess[VIRALLOCEX]);
		res &= RestoreOriginalHook("LdrLoadDll", L"ntdll", originalGameBytess[LDRLOADDLL]);
		res &= RestoreOriginalHook("NtOpenFile", L"ntdll", originalGameBytess[NTOPENFILE]);
		res &= RestoreOriginalHook("VirtualProtect", L"kernel32", originalGameBytess[VIRPROT]);
		res &= RestoreOriginalHook("CreateProcessW", L"kernel32", originalGameBytess[CREATPROW]);
		res &= RestoreOriginalHook("CreateProcessA", L"kernel32", originalGameBytess[CREATPROA]);
		res &= RestoreOriginalHook("VirtualProtectEx", L"kernel32", originalGameBytess[VIRPROTEX]);
		res &= RestoreOriginalHook("FreeLibrary", L"KernelBase", originalGameBytess[FREELIB_]);
		res &= RestoreOriginalHook("LoadLibraryExA", L"KernelBase", originalGameBytess[LOADLIBEXA_]);
		res &= RestoreOriginalHook("LoadLibraryExW", L"KernelBase", originalGameBytess[LOADLIBEXW_]);
		res &= RestoreOriginalHook("ResumeThread", L"KernelBase", originalGameBytess[RESUMETHREAD]);
		return res;
	}
}

int main() {
	SetConsoleTitleW(L"CSGOInjector");

	OpenCSGO();
	if (!hCSGO) {
		MessageBoxW(0, L"Can not find game!", L"Please launch the game!", 0);
		return 0;
	}

	std::wstring dllpath = SelectDll();
	if (!dllpath.length()) {
		MessageBoxW(0, L"No dll file selected!", L"Please selected a dll file.", 0);
		return 0;
	}

	HookBypass::LoadLib();
	if (!HookBypass::BypassCSGO_hook()) {
		MessageBoxW(0, L"Filed to bypass VAC hook!", L"Filed to bypass VAC hook!", 0);
		return 0;
	}

	if (!InjectDll(dllpath)) {
		MessageBoxW(0, L"Failed to InjectDll", L"Failed to InjectDll", 0);
	}

	if (!HookBypass::RestoreCSGO_hook()) {
		MessageBoxW(0, L"Filed to Restore VAC hook!\nThis may result in VAC banning", L"WARN", 0);
	}

	return 0;
}
