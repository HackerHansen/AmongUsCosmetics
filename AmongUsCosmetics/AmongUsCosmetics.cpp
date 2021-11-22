#include <iostream>
#include <sstream>
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <string>
#include <TlHelp32.h>
#include <tchar.h> 
#include <vector>
#include <map>

using namespace std;

bool GALoaded = 0;
DWORD GameAssemblyNp;
DWORD GameAssemblySize;

DWORD pid;
HANDLE hprocess;

HANDLE  hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

map<char, char> byteDigits = { { '0', 0x0 }, { '1', 0x1 }, { '2', 0x2 }, { '3', 0x3 }, { '4', 0x4 }, { '5', 0x5 }, { '6', 0x6 }, { '7', 0x7 }, { '8', 0x8 }, { '9', 0x9 }, { 'A', 0xA }, { 'B', 0xB }, { 'C', 0xC }, { 'D', 0xD }, { 'E', 0xE }, { 'F', 0xF } };

bool isRunning(int procID) {
    HANDLE pss = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(pe);

    if (Process32First(pss, &pe))
    {
        do
        {
            // pe.szExeFile can also be useful  
            if (pe.th32ProcessID == procID)
                return true;
        } while (Process32Next(pss, &pe));
    }

    CloseHandle(pss);

    return false;
}

string ProcessIdToName(DWORD procID) {
    string ret;
    HANDLE handle = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        procID
    );
    if (handle) {
        DWORD buffSize = 1024;
        CHAR buffer[1024];
        if (QueryFullProcessImageNameA(handle, 0, buffer, &buffSize)) {
            ret = buffer;
        }
        else {
            printf("Error GetModuleBaseNameA : %lu", GetLastError());
        }
        CloseHandle(handle);
    }
    else {
        printf("Error OpenProcess : %lu", GetLastError());
    }
    return ret;
}

pair<char*, char*> GetModuleInfo(const wchar_t* ModuleName, DWORD procID) {
    MODULEENTRY32 ModuleEntry = { 0 };
    HANDLE SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procID);

    if (!SnapShot) return { NULL, NULL };

    ModuleEntry.dwSize = sizeof(ModuleEntry);

    if (!Module32First(SnapShot, &ModuleEntry)) return { NULL, NULL };

    while (Module32Next(SnapShot, &ModuleEntry)) {
        if (!wcscmp(ModuleEntry.szModule, ModuleName)) {
            CloseHandle(SnapShot);
            return { (char*)ModuleEntry.modBaseAddr, (char*)ModuleEntry.modBaseSize };
        }
    }

    CloseHandle(SnapShot);
    return { NULL, NULL };
}

bool attachProcess() {
    HWND hwnd = FindWindow(NULL, TEXT("Among Us"));
    if (hwnd != 0) {
        GetWindowThreadProcessId(hwnd, &pid);
        hprocess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if (hprocess != 0) {
            string gamepath = ProcessIdToName(pid);
            string gameprocessname = gamepath.substr(gamepath.find_last_of("\\")).substr(1);
            cout << "Attached to " + gameprocessname + " with PID " + to_string(pid) + "\n";
            if (gameprocessname == "Among Us.exe") {
                return 1;
            }
            else {
                cout << "Error: Attached to wrong process \n";
            }
        }
        else {
            cout << "An error occurred. Please try again. \n";
        }
    }
    return 0;
}

DWORD signatureScan(DWORD base, string sig, DWORD scanSize) {
    vector<char> search = {};
    for (int i = 0; i < sig.length(); i += 2) {
        if (sig[i] == ' ') i++;
        search.push_back(char((byteDigits[sig[i]] * 0x10) + (byteDigits[sig[i + 1]])));
    }
    DWORD searchAddress = 0x0;
    int progress = 0;
    for (long long a = 0x0; a < scanSize; a += 0x500) {
        size_t currScanSize = min(scanSize - a, 0x500);
        char epicScan[0x500];
        ReadProcessMemory(hprocess, (LPVOID)(base + a), &epicScan, currScanSize, 0);
        for (int b = 0; b < currScanSize; b++) {
            if (epicScan[b] == search[progress]) {
                progress++;
            }
            else {
                progress = 0;
            }
            if (progress >= search.size()) {
                searchAddress = base + (a + b - (search.size() - 1));
                return searchAddress;
            }
        }
    }
    return 0x0;
}

bool patchBytes(DWORD address, string bytes) {
    vector<char> patch = {};
    for (int i = 0; i < bytes.length(); i += 2) {
        if (bytes[i] == ' ') i++;
        patch.push_back(char((byteDigits[bytes[i]] * 0x10) + (byteDigits[bytes[i + 1]])));
    }
    DWORD protection = 0;
    VirtualProtectEx(hprocess, (LPVOID)(address), patch.size(), PAGE_EXECUTE_READWRITE, &protection);
    int patchSuccess = 0;
    for (int i = 0; i < patch.size(); i++) {
        if (WriteProcessMemory(hprocess, (LPVOID)(address + i), &patch.at(i), sizeof(patch.at(i)), 0)) {
            patchSuccess++;
        }
    }
    VirtualProtectEx(hprocess, (LPVOID)(address), patch.size(), protection, NULL);
    return patchSuccess == patch.size();
}

int main()
{
    SetConsoleTitleA("HackerHansen's Among Us Cosmetics Unlocker for v2021.11.9"); 
    cout << "Starting! \n";
    cout << "If you can afford to actually buy cosmetics, I would encourage doing so to support the devs who work hard on this game. \n";
start:
    bool appliedPatches = 0;
    if (!attachProcess()) {
        cout << "Waiting for the game to start... \n";
        while (true) {
            if (attachProcess()) break;
            Sleep(100);
        }
    }
    cout << "Waiting for GameAssembly.dll to load... \n";
    while (isRunning(pid)) {
        if (GALoaded == 0) {
            pair<char*, char*> modInfo = GetModuleInfo(L"GameAssembly.dll", pid);
            char* GABase = modInfo.first;
            GameAssemblyNp = (DWORD)GABase;
            char* GASize = modInfo.second;
            GameAssemblySize = (DWORD)GASize;
            if (GameAssemblyNp != 0 && GameAssemblySize != 0) {
                cout << "Found the address of GameAssembly.dll at 0x";
                cout << hex << GameAssemblyNp << dec << "\n";
                cout << "Found the size of GameAssembly.dll: 0x";
                cout << hex << GameAssemblySize << dec << "\n";
                GALoaded = 1;
                byte check = 0;
                ReadProcessMemory(hprocess, (LPVOID)(GameAssemblyNp + 0x20), &check, sizeof(check), 0);
                if (check == 0x69) {
                    cout << "This process was already injected into!\n";
                    appliedPatches = 1;
                }
            }
        }
        else if (appliedPatches == 0) {
            cout << "Scanning GameAssembly.dll for the injection points... \n";
            int workingFeatures = 0;
            DWORD unlockPetsAddress = signatureScan(GameAssemblyNp, "2C 00 74 04 B0 01 5D", GameAssemblySize) + 0x2;
            if (unlockPetsAddress > 0x100) {
                SetConsoleTextAttribute(hConsole, 0xA);
                cout << "Pets OK\n";
                workingFeatures++;
            }
            else {
                SetConsoleTextAttribute(hConsole, 0xC);
                cout << "Pets FAIL\n";
            }
            DWORD unlockHatsAddress = signatureScan(GameAssemblyNp, "50 00 74 04 B0 01 5D", GameAssemblySize) + 0x2;
            if (unlockHatsAddress > 0x100) {
                SetConsoleTextAttribute(hConsole, 0xA);
                cout << "Hats OK\n";
                workingFeatures++;
            }
            else {
                SetConsoleTextAttribute(hConsole, 0xC);
                cout << "Hats FAIL\n";
            }
            DWORD unlockSkinsAddress = signatureScan(GameAssemblyNp, "00 00 00 00 74 04 B0 01 5D", GameAssemblySize) + 0x4;
            if (unlockSkinsAddress > 0x100) {
                SetConsoleTextAttribute(hConsole, 0xA);
                cout << "Skins OK\n";
                workingFeatures++;
            }
            else {
                SetConsoleTextAttribute(hConsole, 0xC);
                cout << "Skins FAIL\n";
            }
            DWORD unlockVisorsAddress = signatureScan(GameAssemblyNp, "40 00 74 04 B0 01 5D C3 56", GameAssemblySize) + 0x2;
            if (unlockVisorsAddress > 0x100) {
                SetConsoleTextAttribute(hConsole, 0xA);
                cout << "Visors OK\n";
                workingFeatures++;
            }
            else {
                SetConsoleTextAttribute(hConsole, 0xC);
                cout << "Visors FAIL\n";
            }
            DWORD unlockNameplatesAddress = signatureScan(GameAssemblyNp, "30 00 74 04 B0 01 5D", GameAssemblySize) + 0x2;
            if (unlockNameplatesAddress > 0x100) {
                SetConsoleTextAttribute(hConsole, 0xA);
                cout << "Name Plates OK\n";
                workingFeatures++;
            }
            else {
                SetConsoleTextAttribute(hConsole, 0xC);
                cout << "Name Plates FAIL\n";
            }
            if (workingFeatures > 0) {
                if (workingFeatures == 5) {
                    SetConsoleTextAttribute(hConsole, 0xA);
                    cout << "All features OK!\n";
                    SetConsoleTextAttribute(hConsole, 0x7);
                    cout << "Applying patches...\n";
                    if (!patchBytes(unlockPetsAddress, "90 90") || !patchBytes(unlockHatsAddress, "90 90") || !patchBytes(unlockSkinsAddress, "90 90") || !patchBytes(unlockVisorsAddress, "90 90") || !patchBytes(unlockNameplatesAddress, "90 90")) {
                        SetConsoleTextAttribute(hConsole, 0xE);
                        cout << "WARNING: One or more patches failed, some features might not work properly!\n";
                    }
                    SetConsoleTextAttribute(hConsole, 0xA);
                    cout << "Ready to go!\n";
                }
                else {
                    SetConsoleTextAttribute(hConsole, 0xE);
                    cout << "WARNING: Some features won't work. \n";
                    SetConsoleTextAttribute(hConsole, 0x7);
                    cout << "Applying patches...\n";
                    bool patchFail = 0;
                    if (unlockPetsAddress > 0x100) if (patchBytes(unlockPetsAddress, "90 90") == 0) patchFail = 1;
                    if (unlockHatsAddress > 0x100) if (patchBytes(unlockHatsAddress, "90 90") == 0) patchFail = 1;
                    if (unlockSkinsAddress > 0x100) if (patchBytes(unlockSkinsAddress, "90 90") == 0) patchFail = 1;
                    if (unlockVisorsAddress > 0x100) if (patchBytes(unlockVisorsAddress, "90 90") == 0) patchFail = 1;
                    if (unlockNameplatesAddress > 0x100) if (patchBytes(unlockNameplatesAddress, "90 90") == 0) patchFail = 1;
                    if (patchFail == 1) {
                        SetConsoleTextAttribute(hConsole, 0xE);
                        cout << "WARNING: One or more patches failed, some features might not work properly!\n";
                    }
                    SetConsoleTextAttribute(hConsole, 0xA);
                    cout << "Ready to go!\n";
                }
                patchBytes(GameAssemblyNp + 0x20, "69");
                appliedPatches = 1;
            }
            else {
                SetConsoleTextAttribute(hConsole, 0xC);
                cout << "Nothing works. You may have an unsupported version of the game, or a different program already injected into the game. \n";
                SetConsoleTextAttribute(hConsole, 0x7);
                system("pause");
                return 0;
            }
            SetConsoleTextAttribute(hConsole, 0x7);
        }
        Sleep(200);
    }
    cout << "No longer attached to the game, it was probably closed!\n";
    GALoaded = 0;
    goto start;
}
