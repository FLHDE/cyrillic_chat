#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define PROCESS_KEY_CALL_ADDR 0x5B0BCE
#define PROCESS_KEY_ADDR 0x577850

// Patches the memory
void Patch(LPVOID vOffset, LPVOID mem, UINT len)
{
    static DWORD _;

    VirtualProtect(vOffset, len, PAGE_EXECUTE_READWRITE, &_);
    memcpy(vOffset, mem, len);
}

// Replaces instructions with nop (0x90)
void Nop(LPVOID vOffset, UINT len)
{
    static DWORD _;

    VirtualProtect(vOffset, len, PAGE_EXECUTE_READWRITE, &_);
    memset(vOffset, 0x90, len);
}

// Adds a jmp or call instruction at a specified address which detours the instruction pointer to arbitrary code
void Hook(DWORD location, DWORD hookFunc, UINT instrLen, bool jmp = false)
{
    // Set the opcode for the call or jmp instruction
    static BYTE callOpcode = 0xE8, jmpOpcode = 0xE9;
    Patch((PVOID) location, &(jmp ? jmpOpcode : callOpcode), sizeof(BYTE));

    // Set and calculate the relative offset for the hook function
    DWORD relOffset = hookFunc - location - 5;
    Patch((PVOID) (location + 1), &relOffset, sizeof(DWORD));

    // Nop out excess bytes
    if (instrLen > 5)
        Nop((PVOID) (location + 5), instrLen - 5);
}

typedef bool ProcessKey(DWORD type, DWORD enteredKey, DWORD unk);

// edx = type
// ecx = enteredKey
// eax = unk
bool ProcessKey_Hook(DWORD type, DWORD enteredKey, DWORD unk)
{
	// Check if a key is typed and if the entered key is greater than the ASCII range
	// If so, convert the key to Cyrillic
	if (type == 0x102 && (enteredKey & 0x80) != NULL)
		enteredKey += 0x350;
	
	return ((ProcessKey*) PROCESS_KEY_ADDR)(type, enteredKey, unk);
}

void Init()
{
    Hook(PROCESS_KEY_CALL_ADDR, (DWORD) ProcessKey_Hook, 5);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpReserved);

    if (fdwReason == DLL_PROCESS_ATTACH)
        Init();

    return TRUE;
}
