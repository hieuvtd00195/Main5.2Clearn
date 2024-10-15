#include "stdafx.h"
#include "Util.h"

BYTE NewAddressData1[240];
BYTE NewAddressData2[240];
BYTE NewAddressData3[6000];
DWORD gLevelExperience[1001];
DWORD CharacterMaxLevel;

void SetByte(DWORD offset, BYTE value) // OK
{
	DWORD OldProtect;

	VirtualProtect((void*)offset, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

	*(BYTE*)(offset) = value;

	VirtualProtect((void*)offset, 1, OldProtect, &OldProtect);
}

void SetWord(DWORD offset, WORD value) // OK
{
	DWORD OldProtect;

	VirtualProtect((void*)offset, 2, PAGE_EXECUTE_READWRITE, &OldProtect);

	*(WORD*)(offset) = value;

	VirtualProtect((void*)offset, 2, OldProtect, &OldProtect);
}

void SetDword(DWORD offset, DWORD value) // OK
{
	DWORD OldProtect;

	VirtualProtect((void*)offset, 4, PAGE_EXECUTE_READWRITE, &OldProtect);

	*(DWORD*)(offset) = value;

	VirtualProtect((void*)offset, 4, OldProtect, &OldProtect);
}

void SetFloat(DWORD offset, float value) // OK
{
	DWORD OldProtect;

	VirtualProtect((void*)offset, 4, PAGE_EXECUTE_READWRITE, &OldProtect);

	*(float*)(offset) = value;

	VirtualProtect((void*)offset, 4, OldProtect, &OldProtect);
}

void SetDouble(DWORD offset, double value) // OK
{
	DWORD OldProtect;

	VirtualProtect((void*)offset, 8, PAGE_EXECUTE_READWRITE, &OldProtect);

	*(double*)(offset) = value;

	VirtualProtect((void*)offset, 8, OldProtect, &OldProtect);
}

void SetCompleteHook(BYTE head, DWORD offset, ...) // OK
{
	DWORD OldProtect;

	VirtualProtect((void*)offset, 5, PAGE_EXECUTE_READWRITE, &OldProtect);

	if (head != 0xFF)
	{
		*(BYTE*)(offset) = head;
	}

	DWORD* function = &offset + 1;

	*(DWORD*)(offset + 1) = (*function) - (offset + 5);

	VirtualProtect((void*)offset, 5, OldProtect, &OldProtect);
}

void MemoryCpy(DWORD offset, void* value, DWORD size) // OK
{
	DWORD OldProtect;

	VirtualProtect((void*)offset, size, PAGE_EXECUTE_READWRITE, &OldProtect);

	memcpy((void*)offset, value, size);

	VirtualProtect((void*)offset, size, OldProtect, &OldProtect);
}

void MemorySet(DWORD offset, DWORD value, DWORD size) // OK
{
	DWORD OldProtect;

	VirtualProtect((void*)offset, size, PAGE_EXECUTE_READWRITE, &OldProtect);

	memset((void*)offset, value, size);

	VirtualProtect((void*)offset, size, OldProtect, &OldProtect);
}

void VirtualizeOffset(DWORD offset, DWORD size) // OK
{
	DWORD OldProtect;

	VirtualProtect((void*)offset, size, PAGE_EXECUTE_READWRITE, &OldProtect);

	DWORD HookAddr = (DWORD)malloc(size + 5);

	memcpy((void*)HookAddr, (void*)offset, size);

	*(BYTE*)(HookAddr + size) = 0xE9;

	*(DWORD*)(HookAddr + size + 1) = (offset + size) - ((HookAddr + size) + 5);

	*(BYTE*)(offset) = 0xE9;

	*(DWORD*)(offset + 1) = HookAddr - (offset + 5);

	memset((void*)(offset + 5), 0x90, (size - 5));

	VirtualProtect((void*)offset, size, OldProtect, &OldProtect);
}

void PacketArgumentEncrypt(char* out_buff, char* in_buff, int size) // OK
{
	BYTE XorTable[3] = { 0xFC,0xCF,0xAB };

	for (int n = 0; n < size; n++)
	{
		out_buff[n] = in_buff[n] ^ XorTable[n % 3];
	}
}

char* ConvertModuleFileName(char* name) // OK
{
	static char buff[MAX_PATH] = { 0 };

	for (int n = strlen(name); n > 0; n--)
	{
		if (name[n] == '\\')
		{
			strcpy_s(buff, sizeof(buff), &name[(n + 1)]);
			break;
		}
	}

	return buff;
}

void LoadReferenceAddressTable(HMODULE mod, char* name, DWORD address) // OK
{
	if (IS_INTRESOURCE(name) == 0)
	{
		return;
	}

	HRSRC resource = FindResource(mod, name, "BIN");

	if (resource == 0)
	{
		return;
	}

	if (SizeofResource(mod, resource) < sizeof(REFERENCE_INFO))
	{
		return;
	}

	HGLOBAL data = LoadResource(mod, resource);

	if (data == 0)
	{
		return;
	}

	REFERENCE_INFO* ReferenceInfo = (REFERENCE_INFO*)LockResource(data);

	if (ReferenceInfo == 0)
	{
		FreeResource(data);
		return;
	}

	if (ReferenceInfo->start == ReferenceInfo->end)
	{
		if (SizeofResource(mod, resource) < (sizeof(REFERENCE_INFO) + (ReferenceInfo->count * sizeof(REFERENCE_BASE))))
		{
			return;
		}

		REFERENCE_BASE* ReferenceBase = (REFERENCE_BASE*)((DWORD)ReferenceInfo + sizeof(REFERENCE_INFO));

		for (DWORD n = 0; n < ReferenceInfo->count; n++)
		{
			SetDword(ReferenceBase[n].address, address);
		}
	}
	else
	{
		if (SizeofResource(mod, resource) < (sizeof(REFERENCE_INFO) + (ReferenceInfo->count * sizeof(REFERENCE_DATA))))
		{
			return;
		}

		REFERENCE_DATA* ReferenceData = (REFERENCE_DATA*)((DWORD)ReferenceInfo + sizeof(REFERENCE_INFO));

		for (DWORD n = 0; n < ReferenceInfo->count; n++)
		{
			SetDword(ReferenceData[n].address, (address + ReferenceData[n].value));
		}
	}

	FreeResource(data);
}

void ErrorMessageBox(char* message, ...) // OK
{
	char buff[256];

	memset(buff, 0, sizeof(buff));

	va_list arg;
	va_start(arg, message);
	vsprintf_s(buff, message, arg);
	va_end(arg);

	MessageBox(0, buff, "Error", MB_OK | MB_ICONERROR);
}

char* GetHardwareId() //OK
{
	char WinDir[MAX_PATH];

	if (GetSystemDirectory(WinDir, sizeof(WinDir)) == 0)
	{
		return 0;
	}

	WinDir[3] = 0;

	DWORD VolumeSerialNumber;

	if (GetVolumeInformation(WinDir, 0, 0, &VolumeSerialNumber, 0, 0, 0, 0) == 0)
	{
		return 0;
	}

	SYSTEM_INFO SystemInfo;

	GetSystemInfo(&SystemInfo);

	DWORD ComputerHardwareId1 = (VolumeSerialNumber ^ VolumeSerialNumber) + 0x12BA1074;

	DWORD ComputerHardwareId2 = (VolumeSerialNumber * VolumeSerialNumber) - 0x13B06451;

	DWORD ComputerHardwareId3 = (VolumeSerialNumber | SystemInfo.dwNumberOfProcessors << 16) * 0x14CE1989;

	DWORD ComputerHardwareId4 = (VolumeSerialNumber | SystemInfo.wProcessorArchitecture << 16) / 4;

	DWORD ComputerHardwareId5 = ((SystemInfo.wProcessorLevel & 0xF5FB) | (SystemInfo.wProcessorRevision << 16)) ^ 0x15CA2020;

	static char HardwareId[45];

	wsprintf(HardwareId, "%08X-%08X-%08X-%08X-%08X", ComputerHardwareId1, ComputerHardwareId2, ComputerHardwareId3, ComputerHardwareId4, ComputerHardwareId5);

	return HardwareId;
}

void SetExperienceTable(int MaxLevel, int ConstA, int ConstB, int DeleteLevel) // OK
{
	SetWord(0x00405B7C, DeleteLevel); // Delete Level
	SetWord(0x0040CC40, DeleteLevel); // Delete Level Msg

	gLevelExperience[0] = 0;

	CharacterMaxLevel = MaxLevel;

	DWORD over = 1;

	for (int n = 1; n <= MaxLevel; n++)
	{
		gLevelExperience[n] = (((n + 9) * n) * n) * ConstA;

		if (n > 255)
		{
			gLevelExperience[n] += (((over + 9) * over) * over) * ConstB;
			over++;
		}
	}
}

void GetFormat(char* str, char oldval, char newval)
{
	std::string Buff;
	Buff = str;
	std::replace(Buff.begin(), Buff.end(), oldval, newval);
	memcpy(str, Buff.c_str(), Buff.size());
}

char* BNumberFormat(int Number)
{


	if (Number < 0) { return "0"; }

	char OutPut[15];

	if (Number < 1000) {
		sprintf(OutPut, "%d", Number);
		return strdup(OutPut);
	}
	else if (Number < 1000000) {
		int part1 = Number % 1000;
		int part2 = (Number - part1) / 1000;
		sprintf(OutPut, "%d,%03d", part2, part1);
		return strdup(OutPut);
	}
	else if (Number < 1000000000) {
		int part1 = Number % 1000;
		Number = (Number - part1) / 1000;
		int part2 = Number % 1000;
		Number = (Number - part2) / 1000;
		int part3 = Number % 1000;

		sprintf(OutPut, "%d,%03d,%03d", part3, part2, part1);
		return strdup(OutPut);
	}
	else {
		int part1 = Number % 1000;
		Number = (Number - part1) / 1000;
		int part2 = Number % 1000;
		Number = (Number - part2) / 1000;
		int part3 = Number % 1000;
		int part4 = (Number - part3) / 1000;

		sprintf(OutPut, "%d,%03d,%03d,%03d", part4, part3, part2, part1);
		return strdup(OutPut);
	}
	return "0";
}