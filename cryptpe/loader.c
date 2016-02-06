/*
 * PE binary loader. Modified from MemoryModule by Martin Wolters
 *
 * Memory loading code
 * Version 0.0.3
 *
 * Copyright (c) 2004-2012 by Joachim Bauch / mail@joachim-bauch.de
 * http://www.joachim-bauch.de
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is MemoryModule.c
 *
 * The Initial Developer of the Original Code is Joachim Bauch.
 *
 * Portions created by Joachim Bauch are Copyright (C) 2004-2012
 * Joachim Bauch. All Rights Reserved.
 *
 */

#include <Windows.h>
#include <WinNT.h>

#include <stdint.h>

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

typedef void *HMEMORYMODULE;

typedef struct {
	PIMAGE_NT_HEADERS headers;
	uint8_t *codeBase;
	HMODULE *modules;
	int numModules;
	int initialized;
} MEMORYMODULE, *PMEMORYMODULE;

typedef int (*EntryPoint)(int argc, char **argv);

#define GET_HEADER_DICTIONARY(module, idx)	&(module)->headers->OptionalHeader.DataDirectory[idx]

static void CopySections(const uint8_t *data, PIMAGE_NT_HEADERS old_headers, PMEMORYMODULE module) {
	int i, size;
	uint8_t *codeBase = module->codeBase;
	uint8_t *dest;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);

	for (i=0; i<module->headers->FileHeader.NumberOfSections; i++, section++) {
		if (!(section->SizeOfRawData)) {
			size = old_headers->OptionalHeader.SectionAlignment;
			if (size) {
				dest = (uint8_t*)VirtualAlloc(codeBase + section->VirtualAddress,
					size,
					MEM_COMMIT,
					PAGE_READWRITE);

				section->Misc.PhysicalAddress = (DWORD)dest;
				memset(dest, 0, size);
			}
			continue;
		}
		dest = (uint8_t*)VirtualAlloc(codeBase + section->VirtualAddress,
			section->SizeOfRawData,	MEM_COMMIT, PAGE_READWRITE);
		memcpy(dest, data + section->PointerToRawData, section->SizeOfRawData);
		section->Misc.PhysicalAddress = (DWORD)dest;
	}
}

static int ProtectionFlags[2][2][2] = {
	{
		{PAGE_NOACCESS, PAGE_WRITECOPY},
		{PAGE_READONLY, PAGE_READWRITE},
	}, {
		{PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
		{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
	},
};

static void
FinalizeSections(PMEMORYMODULE module) {
	int i;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
	DWORD protect, oldProtect, size;
	int exec, read, writ;

	for (i=0; i<module->headers->FileHeader.NumberOfSections; i++, section++) {
		exec = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		read = (section->Characteristics & IMAGE_SCN_MEM_READ) != 0;
		writ = (section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

		if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
			VirtualFree((LPVOID)((DWORD)section->Misc.PhysicalAddress), section->SizeOfRawData, MEM_DECOMMIT);
			continue;
		}

		protect = ProtectionFlags[exec][read][writ];
		if (section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
			protect |= PAGE_NOCACHE;

		size = section->SizeOfRawData;
		if (!size)
			if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
				size = module->headers->OptionalHeader.SizeOfInitializedData;
			else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
				size = module->headers->OptionalHeader.SizeOfUninitializedData;			
		

		if (size)
			VirtualProtect((LPVOID)((DWORD)section->Misc.PhysicalAddress), size, protect, &oldProtect);
	}
}

static void
PerformBaseRelocation(PMEMORYMODULE module, SIZE_T delta) {
	DWORD i;
	uint8_t *codeBase = module->codeBase;
	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION) (codeBase + directory->VirtualAddress);
	uint8_t *dest;
	uint16_t *relInfo;
	DWORD *patchAddrHL;
	
	if (directory->Size) {
		for (; relocation->VirtualAddress; ) {
			dest = codeBase + relocation->VirtualAddress;
			relInfo = (uint16_t*)((uint8_t*)relocation + IMAGE_SIZEOF_BASE_RELOCATION);
			for (i=0; i<((relocation->SizeOfBlock-IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, relInfo++) {
				if (((*relInfo) >> 12) == IMAGE_REL_BASED_HIGHLOW) {					
					patchAddrHL = (DWORD*) (dest + ((*relInfo) & 0xfff));
					*patchAddrHL += delta;									
				}
			}
			relocation = (PIMAGE_BASE_RELOCATION) (((char*) relocation) + relocation->SizeOfBlock);
		}
	}
}

static int BuildImportTable(PMEMORYMODULE module) {
	int result=1;
	uint8_t *codeBase = module->codeBase;
	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_IMPORT);
	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR) (codeBase + directory->VirtualAddress);
	DWORD *thunkRef;
	FARPROC *funcRef;
	
	if (directory->Size) {
		for (; !IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++) {
			HMODULE handle = LoadLibraryA((LPCSTR) (codeBase + importDesc->Name));
			if (handle == NULL) {
				result = 0;
				break;
			}

			module->modules = (HMODULE*)realloc(module->modules, (module->numModules+1)*(sizeof(HMODULE)));
			if (module->modules == NULL) {
				result = 0;
				break;
			}

			module->modules[module->numModules++] = handle;
			if (importDesc->OriginalFirstThunk) {
				thunkRef = (DWORD*) (codeBase + importDesc->OriginalFirstThunk);
				funcRef = (FARPROC*) (codeBase + importDesc->FirstThunk);
			} else {				
				thunkRef = (DWORD*) (codeBase + importDesc->FirstThunk);
				funcRef = (FARPROC*) (codeBase + importDesc->FirstThunk);
			}
			for (; *thunkRef; thunkRef++, funcRef++) {
				if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
					*funcRef = (FARPROC)GetProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
				else {
					PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME) (codeBase + (*thunkRef));
					*funcRef = (FARPROC)GetProcAddress(handle, (LPCSTR)&thunkData->Name);
				}
				if (!(*funcRef)) {
					result = 0;
					break;
				}
			}

			if (!result) {
				break;
			}
		}
	}

	return result;
}

void MemoryFreeBinary(HMEMORYMODULE mod) {
	int i;
	PMEMORYMODULE module = (PMEMORYMODULE)mod;

	if (module != NULL) {
		if (module->modules != NULL) {
			for (i=0; i<module->numModules; i++)
				if (module->modules[i] != INVALID_HANDLE_VALUE)
					FreeLibrary(module->modules[i]);
			free(module->modules);
		}
		if (module->codeBase != NULL)
			VirtualFree(module->codeBase, 0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0, module);
	}
}

int load(const uint8_t *data, int argc, char **argv) {
	PMEMORYMODULE result;
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS old_header;
	uint8_t *code, *headers;
	SIZE_T locationDelta;
	EntryPoint Entry;
	int entryretval = EXIT_FAILURE;

	dos_header = (PIMAGE_DOS_HEADER)data;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return EXIT_FAILURE;

	old_header = (PIMAGE_NT_HEADERS)&((const uint8_t*)(data))[dos_header->e_lfanew];
	if (old_header->Signature != IMAGE_NT_SIGNATURE)
		return EXIT_FAILURE;

	code = (uint8_t*)VirtualAlloc((LPVOID)(old_header->OptionalHeader.ImageBase),
		old_header->OptionalHeader.SizeOfImage,
		MEM_RESERVE,
		PAGE_READWRITE);

    if (code == NULL) {
        code = (uint8_t*)VirtualAlloc(NULL,
            old_header->OptionalHeader.SizeOfImage,
            MEM_RESERVE,
            PAGE_READWRITE);
		if (code == NULL)
			return EXIT_FAILURE;
	}
    
	if((result = (PMEMORYMODULE)HeapAlloc(GetProcessHeap(), 0, sizeof(MEMORYMODULE))) == NULL) {
		VirtualFree((LPVOID)((DWORD)code), old_header->OptionalHeader.SizeOfImage, MEM_DECOMMIT);
		return EXIT_FAILURE;
	}
	
	result->codeBase = code;
	result->numModules = 0;
	result->modules = NULL;
	result->initialized = 0;

	VirtualAlloc(code, old_header->OptionalHeader.SizeOfImage,
		MEM_COMMIT,	PAGE_READWRITE);

	headers = (uint8_t*)VirtualAlloc(code, old_header->OptionalHeader.SizeOfHeaders,
		MEM_COMMIT,	PAGE_READWRITE);
	
	memcpy(headers, dos_header, dos_header->e_lfanew + old_header->OptionalHeader.SizeOfHeaders);
	result->headers = (PIMAGE_NT_HEADERS)&((const uint8_t*)(headers))[dos_header->e_lfanew];

	result->headers->OptionalHeader.ImageBase = (DWORD)code;

	CopySections(data, old_header, result);

	locationDelta = (SIZE_T)(code - old_header->OptionalHeader.ImageBase);
	if (locationDelta)
		PerformBaseRelocation(result, locationDelta);

	if (!BuildImportTable(result))
		goto error;

	FinalizeSections(result);

	if (result->headers->OptionalHeader.AddressOfEntryPoint != 0) {
		Entry = (EntryPoint) (code + result->headers->OptionalHeader.AddressOfEntryPoint);
		if (!Entry)
			goto error;

		entryretval = (*Entry)(argc, argv);
	}

error:
	MemoryFreeBinary(result);

	return entryretval;
}