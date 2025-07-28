#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define PROCESS_KEY_CALL_ADDR 0x5B0BCE
#define PROCESS_KEY_ADDR 0x577850

// Patches the memory
void Patch(LPVOID vOffset, LPVOID mem, UINT len)
{
    DWORD _;
    VirtualProtect(vOffset, len, PAGE_EXECUTE_READWRITE, &_);
    memcpy(vOffset, mem, len);
}

// Replaces instructions with nop (0x90)
void Nop(LPVOID vOffset, UINT len)
{
    DWORD _;
    VirtualProtect(vOffset, len, PAGE_EXECUTE_READWRITE, &_);
    memset(vOffset, 0x90, len);
}

// Adds a jmp or call instruction at a specified address which detours the instruction pointer to arbitrary code
void Hook(DWORD location, DWORD hookFunc, UINT instrLen, BOOLEAN jmp)
{
    BYTE callOpcode = 0xE8, jmpOpcode = 0xE9;
    DWORD relOffset = hookFunc - location - 5;

    // Set the opcode for the call or jmp instruction
    Patch((PVOID) location, jmp ? &jmpOpcode : &callOpcode, sizeof(BYTE));

    // Set and calculate the relative offset for the hook function
    Patch((PVOID) (location + 1), &relOffset, sizeof(DWORD));

    // Nop out excess bytes
    if (instrLen > 5)
        Nop((PVOID) (location + 5), instrLen - 5);
}

typedef BOOLEAN ProcessKey(DWORD type, DWORD enteredKey, DWORD unk);

#define YO_SRC_UNICODE 0xA8
#define YO_SRC_LOWER_BIT_NR 4
#define YO_DEST_UNICODE 0x401
#define YO_DEST_LOWER_BITS ((1 << YO_SRC_LOWER_BIT_NR) | (1 << (YO_SRC_LOWER_BIT_NR + 2)))

#define NUMERO_SRC_UNICODE 0xB9
#define NUMERO_DEST_UNICODE 0x2116

// Check if a key is typed and if the entered key is greater than the ASCII range
// If so, convert the key to Cyrillic
BOOLEAN ProcessKey_Hook(DWORD type, DWORD enteredKey, DWORD unk)
{
    BOOL isLower;

    // Key typed
    if (type == 0x102)
    {
        // ё and Ё
        if ((enteredKey & ~(1 << YO_SRC_LOWER_BIT_NR)) == YO_SRC_UNICODE)
        {
            isLower = (enteredKey >> YO_SRC_LOWER_BIT_NR) & 1;
            enteredKey = YO_DEST_UNICODE + isLower * YO_DEST_LOWER_BITS;
        }
        // №
        else if (enteredKey == NUMERO_SRC_UNICODE)
        {
            enteredKey = NUMERO_DEST_UNICODE;
        }
        // General Cyrillic key conversion
        else if (enteredKey & 0x80)
        {
            enteredKey += 0x350;
        }
    }

    // Call the original function
    return ((ProcessKey*) PROCESS_KEY_ADDR)(type, enteredKey, unk);
}

void Init()
{
    Hook(PROCESS_KEY_CALL_ADDR, (DWORD) ProcessKey_Hook, 5, FALSE);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpReserved);

    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        Init();
    }

    return TRUE;
}
