#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define CHECK_MESSAGE_CALL_ADDR 0x5B0BCE
#define CHECK_MESSAGE_ADDR 0x577850

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

typedef BOOLEAN CheckMessage(UINT message, WPARAM charCode, LPARAM flags);

#ifndef MAPVK_VSC_TO_VK
#define MAPVK_VSC_TO_VK (1)
#endif

#ifndef VK_OEM_3
#define VK_OEM_3 0xC0
#endif

#define YO_SRC_UNICODE 0xA8
#define YO_SRC_LOWER_BIT_NR 4
#define YO_DEST_UNICODE 0x401
#define YO_DEST_LOWER_BITS ((1 << YO_SRC_LOWER_BIT_NR) | (1 << (YO_SRC_LOWER_BIT_NR + 2)))

#define NUMERO_SRC_UNICODE 0xB9
#define NUMERO_DEST_UNICODE 0x2116

#define RUBLE_HRYVNIA_SRC_UNICODE 0x3F
#define RUBLE_DEST_UNICODE 0x20BD
#define HRYVNIA_DEST_UNICODE 0x20B4

#define GE_SRC_LOWER_UNICODE 0xB4
#define GE_DEST_LOWER_UNICODE 0x491

#define GE_SRC_UPPER_UNICODE 0xA5
#define GE_DEST_UPPER_UNICODE 0x490

// Check if the entered key is Cyrillic and convert it accordingly before processing
BOOLEAN CheckMessage_Hook(UINT message, WPARAM charCode, LPARAM flags)
{
    BOOL isLower;
    BYTE scanCode;
    UINT virtualCode;

    if (message == WM_CHAR)
    {
        scanCode = (flags >> 16) & 0xFF;

        // ё and Ё
        if ((charCode & ~(1 << YO_SRC_LOWER_BIT_NR)) == YO_SRC_UNICODE)
        {
            isLower = (charCode >> YO_SRC_LOWER_BIT_NR) & 1;
            charCode = YO_DEST_UNICODE + isLower * YO_DEST_LOWER_BITS;
        }
        // №
        else if (charCode == NUMERO_SRC_UNICODE)
        {
            charCode = NUMERO_DEST_UNICODE;
        }
        // ґ
        else if (charCode == GE_SRC_LOWER_UNICODE)
        {
            charCode = GE_DEST_LOWER_UNICODE;
        }
        // Ґ
        else if (charCode == GE_SRC_UPPER_UNICODE)
        {
            charCode = GE_DEST_UPPER_UNICODE;
        }
        // General Cyrillic key conversion
        else if (charCode & 0x80)
        {
            charCode += 0x350;
        }
        // Ruble and Hryvnia
        else if (charCode == RUBLE_HRYVNIA_SRC_UNICODE)
        {
            virtualCode = MapVirtualKey(scanCode, MAPVK_VSC_TO_VK);

            if (virtualCode == '8') // TODO: check for ALT? (bit 24 of flags)
            {
                charCode = RUBLE_DEST_UNICODE;
            }
            else if (virtualCode == VK_OEM_3)
            {
                charCode = HRYVNIA_DEST_UNICODE;
            }
        }
    }

    // Call the original function
    return ((CheckMessage*) CHECK_MESSAGE_ADDR)(message, charCode, flags);
}

void Init()
{
    Hook(CHECK_MESSAGE_CALL_ADDR, (DWORD) CheckMessage_Hook, 5, FALSE);
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
