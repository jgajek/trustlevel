#include <iostream>
#include <string>
#include <windows.h>
#include <algorithm>
#include <AclAPI.h>
#include <sddl.h>
#include <map>

void printUsage() {
    std::wcout << L"Usage: trustlevel.exe [options]\n"
               << L"Options:\n"
               << L"  -f <filename>      Specify the filename\n"
               << L"  -r <registrykey>   Specify the registry key\n"
               << L"  -h, --help         Show this help message\n";
}

std::wstring getErrorMessage(DWORD errorCode) {
    LPVOID msgBuffer;
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&msgBuffer, 0, NULL);

    std::wstring message((LPWSTR)msgBuffer, size);
    LocalFree(msgBuffer);
    return std::wstring(message.begin(), message.end());
}

bool caseInsensitiveCompare(const std::wstring& str1, const std::wstring& str2) {
    return std::equal(str1.begin(), str1.end(), str2.begin(), str2.end(),
                      [](char a, char b) { return tolower(a) == tolower(b); });
}

bool enablePrivilege(const std::wstring& privilege) {
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        std::wcerr << L"OpenProcessToken error: " << getErrorMessage(GetLastError()) << std::endl;
        return false;
    }

    if (!LookupPrivilegeValueW(NULL, (LPCWSTR)privilege.c_str(), &luid)) {
        std::wcerr << L"LookupPrivilegeValue error: " << getErrorMessage(GetLastError()) << std::endl;
        CloseHandle(token);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::wcerr << L"AdjustTokenPrivileges error: " << getErrorMessage(GetLastError()) << std::endl;
        CloseHandle(token);
        return false;
    }

    CloseHandle(token);
    return true;
}

PACL getFileSACL(HANDLE fileHandle) {
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pSACL = NULL;
    BOOL bSaclPresent = FALSE;
    BOOL bSaclDefaulted = FALSE;

    DWORD result = GetSecurityInfo(fileHandle, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION | PROCESS_TRUST_LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, &pSACL, &pSD);
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"GetSecurityInfo error: " << getErrorMessage(result) << std::endl;
        return NULL;
    }

    if (!GetSecurityDescriptorSacl(pSD, &bSaclPresent, &pSACL, &bSaclDefaulted)) {
        std::wcerr << L"GetSecurityDescriptorSacl error: " << getErrorMessage(GetLastError()) << std::endl;
        LocalFree(pSD);
        return NULL;
    }

    if (!bSaclPresent) {
        std::wcerr << L"SACL not present." << std::endl;
        LocalFree(pSD);
        return NULL;
    }

    return pSACL;
}

PACL getRegKeySACL(HKEY hKey) {
    DWORD dwSize = 0;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pSACL = NULL;
    BOOL bSaclPresent = FALSE;
    BOOL bSaclDefaulted = FALSE;

    LONG result = RegGetKeySecurity(hKey, SACL_SECURITY_INFORMATION | PROCESS_TRUST_LABEL_SECURITY_INFORMATION, NULL, &dwSize);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        std::wcerr << L"RegGetKeySecurity error: " << getErrorMessage(result) << std::endl;
        return NULL;
    }

    pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSize);
    if (!pSD) {
        std::wcerr << L"LocalAlloc error: " << getErrorMessage(GetLastError()) << std::endl;
        return NULL;
    }

    result = RegGetKeySecurity(hKey, SACL_SECURITY_INFORMATION | PROCESS_TRUST_LABEL_SECURITY_INFORMATION, pSD, &dwSize);
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"RegGetKeySecurity error: " << getErrorMessage(result) << std::endl;
        LocalFree(pSD);
        return NULL;
    }

    if (!GetSecurityDescriptorSacl(pSD, &bSaclPresent, &pSACL, &bSaclDefaulted)) {
        std::wcerr << L"GetSecurityDescriptorSacl error: " << getErrorMessage(GetLastError()) << std::endl;
        LocalFree(pSD);
        return NULL;
    }

    if (!bSaclPresent) {
        std::wcerr << L"SACL not present." << std::endl;
        LocalFree(pSD);
        return NULL;
    }

    return pSACL;
}

HKEY openRegistryKey(const std::wstring& registryKey, REGSAM permissions) {
    HKEY hKey;
    size_t pos = registryKey.find('\\');
    if (pos == std::wstring::npos) {
        std::wcerr << L"Invalid registry key format." << std::endl;
        return NULL;
    }

    std::wstring rootKeyStr = registryKey.substr(0, pos);
    std::wstring subKey = registryKey.substr(pos + 1);

    HKEY rootKey;
    if (caseInsensitiveCompare(rootKeyStr, L"HKLM") || caseInsensitiveCompare(rootKeyStr, L"HKEY_LOCAL_MACHINE")) {
        rootKey = HKEY_LOCAL_MACHINE;
    } else if (caseInsensitiveCompare(rootKeyStr, L"HKCU") || caseInsensitiveCompare(rootKeyStr, L"HKEY_CURRENT_USER")) {
        rootKey = HKEY_CURRENT_USER;
    } else if (caseInsensitiveCompare(rootKeyStr, L"HKCR") || caseInsensitiveCompare(rootKeyStr, L"HKEY_CLASSES_ROOT")) {
        rootKey = HKEY_CLASSES_ROOT;
    } else if (caseInsensitiveCompare(rootKeyStr, L"HKU") || caseInsensitiveCompare(rootKeyStr, L"HKEY_USERS")) {
        rootKey = HKEY_USERS;
    } else if (caseInsensitiveCompare(rootKeyStr, L"HKCC") || caseInsensitiveCompare(rootKeyStr, L"HKEY_CURRENT_CONFIG")) {
        rootKey = HKEY_CURRENT_CONFIG;
    } else {
        std::wcerr << L"Invalid root key. Use HKLM, HKCU, HKCR, HKU, HKCC, or the full root key name." << std::endl;
        return NULL;
    }

    LONG result = RegOpenKeyExW(rootKey, (LPCWSTR)subKey.c_str(), 0, permissions, &hKey);
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"Error opening registry key: " << getErrorMessage(result) << std::endl;
        return NULL;
    }

    return hKey;
}

// Lookup table for process trust level SIDs
std::map<std::wstring, std::wstring> trustLevelLookup = {
    {L"S-1-19-512-1024", L"ProtectedLight-Authenticode"},
    {L"S-1-19-512-1536", L"ProtectedLight-AntiMalware"},
    {L"S-1-19-512-2048", L"ProtectedLight-App"},
    {L"S-1-19-512-4096", L"ProtectedLight-Windows"},
    {L"S-1-19-512-8192", L"ProtectedLight-WinTcb"},
    {L"S-1-19-1024-1024", L"Protected-Authenticode"},
    {L"S-1-19-1024-1536", L"Protected-AntiMalware"},
    {L"S-1-19-1024-2048", L"Protected-App"},
    {L"S-1-19-1024-4096", L"Protected-Windows"},
    {L"S-1-19-1024-8192", L"Protected-WinTcb"}
};

std::wstring convertAccessMaskToPermissions(DWORD accessMask) {
    std::wstring permissions;

    // Summary permissions
    bool hasSummaryPermission = false;
    if ((accessMask & KEY_ALL_ACCESS) == KEY_ALL_ACCESS) {
        permissions += L"KEY_ALL_ACCESS, ";
        hasSummaryPermission = true;
    }
    else if ((accessMask & KEY_READ) == KEY_READ) {
        permissions += L"KEY_READ, ";
        hasSummaryPermission = true;
    }
    else if ((accessMask & KEY_WRITE) == KEY_WRITE) {
        permissions += L"KEY_WRITE, ";
        hasSummaryPermission = true;
    }
    else if ((accessMask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS) {
        permissions += L"FILE_ALL_ACCESS, ";
        hasSummaryPermission = true;
    }
    else if ((accessMask & FILE_GENERIC_READ) == FILE_GENERIC_READ) {
        permissions += L"FILE_GENERIC_READ, ";
        hasSummaryPermission = true;
    }
    else if ((accessMask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE) {
        permissions += L"FILE_GENERIC_WRITE, ";
        hasSummaryPermission = true;
    }
    else if ((accessMask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE) {
        permissions += L"FILE_GENERIC_EXECUTE, ";
        hasSummaryPermission = true;
    }

    // Individual permissions
    if (!hasSummaryPermission || (accessMask & ~KEY_ALL_ACCESS & ~KEY_READ & ~KEY_WRITE & ~FILE_ALL_ACCESS & ~FILE_GENERIC_READ & ~FILE_GENERIC_WRITE & ~FILE_GENERIC_EXECUTE)) {
        if (accessMask & GENERIC_READ) permissions += L"GENERIC_READ, ";
        if (accessMask & GENERIC_WRITE) permissions += L"GENERIC_WRITE, ";
        if (accessMask & GENERIC_EXECUTE) permissions += L"GENERIC_EXECUTE, ";
        if (accessMask & GENERIC_ALL) permissions += L"GENERIC_ALL, ";
        if (accessMask & DELETE) permissions += L"DELETE, ";
        if (accessMask & READ_CONTROL) permissions += L"READ_CONTROL, ";
        if (accessMask & WRITE_DAC) permissions += L"WRITE_DAC, ";
        if (accessMask & WRITE_OWNER) permissions += L"WRITE_OWNER, ";
        if (accessMask & SYNCHRONIZE) permissions += L"SYNCHRONIZE, ";
        if (accessMask & ACCESS_SYSTEM_SECURITY) permissions += L"ACCESS_SYSTEM_SECURITY, ";
        if (accessMask & MAXIMUM_ALLOWED) permissions += L"MAXIMUM_ALLOWED, ";

        // Registry-specific permissions
        if (accessMask & KEY_QUERY_VALUE) permissions += L"KEY_QUERY_VALUE, ";
        if (accessMask & KEY_SET_VALUE) permissions += L"KEY_SET_VALUE, ";
        if (accessMask & KEY_CREATE_SUB_KEY) permissions += L"KEY_CREATE_SUB_KEY, ";
        if (accessMask & KEY_ENUMERATE_SUB_KEYS) permissions += L"KEY_ENUMERATE_SUB_KEYS, ";
        if (accessMask & KEY_NOTIFY) permissions += L"KEY_NOTIFY, ";
        if (accessMask & KEY_CREATE_LINK) permissions += L"KEY_CREATE_LINK, ";
        if (accessMask & KEY_WOW64_32KEY) permissions += L"KEY_WOW64_32KEY, ";
        if (accessMask & KEY_WOW64_64KEY) permissions += L"KEY_WOW64_64KEY, ";
        if (accessMask & KEY_WOW64_RES) permissions += L"KEY_WOW64_RES, ";

        // File and directory-specific permissions
        if (accessMask & FILE_READ_DATA) permissions += L"FILE_READ_DATA, ";
        if (accessMask & FILE_WRITE_DATA) permissions += L"FILE_WRITE_DATA, ";
        if (accessMask & FILE_APPEND_DATA) permissions += L"FILE_APPEND_DATA, ";
        if (accessMask & FILE_READ_EA) permissions += L"FILE_READ_EA, ";
        if (accessMask & FILE_WRITE_EA) permissions += L"FILE_WRITE_EA, ";
        if (accessMask & FILE_EXECUTE) permissions += L"FILE_EXECUTE, ";
        if (accessMask & FILE_DELETE_CHILD) permissions += L"FILE_DELETE_CHILD, ";
        if (accessMask & FILE_READ_ATTRIBUTES) permissions += L"FILE_READ_ATTRIBUTES, ";
        if (accessMask & FILE_WRITE_ATTRIBUTES) permissions += L"FILE_WRITE_ATTRIBUTES, ";
        if (accessMask & FILE_TRAVERSE) permissions += L"FILE_TRAVERSE, ";
    }

    // Remove trailing comma and space
    if (!permissions.empty()) {
        permissions.pop_back();
        permissions.pop_back();
    }

    return permissions;
}

void printTrustLevel(PACL pSACL) {
    if (pSACL == NULL) {
        std::wcerr << L"SACL is NULL." << std::endl;
        return;
    }

    for (DWORD i = 0; i < pSACL->AceCount; ++i) {
        PACE_HEADER pAceHeader;
        if (GetAce(pSACL, i, (LPVOID*)&pAceHeader)) {
            if (pAceHeader->AceType == SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE) {
                PSYSTEM_PROCESS_TRUST_LABEL_ACE pAce = (PSYSTEM_PROCESS_TRUST_LABEL_ACE)pAceHeader;
                DWORD accessMask = pAce->Mask;
                PSID trustLevelSID = (PSID)&(pAce->SidStart);

                // Convert SID to string
                LPWSTR sidString;
                if (ConvertSidToStringSidW(trustLevelSID, &sidString)) {
                    std::wstring sid(sidString);
                    LocalFree(sidString);

                    // Lookup high-level name
                    std::wstring trustLevelName = L"Unknown";
                    auto it = trustLevelLookup.find(sid);
                    if (it != trustLevelLookup.end()) {
                        trustLevelName = it->second;
                    }

                    // Convert access mask to permissions
                    std::wstring permissions = convertAccessMaskToPermissions(accessMask);

                    std::wcout << permissions << L" | " << trustLevelName << std::endl;
                } else {
                    std::wcerr << L"Failed to convert SID to string: " << getErrorMessage(GetLastError()) << std::endl;
                }
            }
        } else {
            std::wcerr << L"Failed to get ACE: " << getErrorMessage(GetLastError()) << std::endl;
        }
    }
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }

    std::wstring option = argv[1];
    if (option == L"-h" || option == L"--help") {
        printUsage();
        return 0;
    } else if (option == L"-f" && argc == 3) {
        std::wstring filename = argv[2];
        std::wcout << L"Filename: " << filename << std::endl;

        if (!enablePrivilege(L"SeSecurityPrivilege")) {
            std::wcerr << L"Failed to enable SeSecurityPrivilege. Continuing without it." << std::endl;
        }

        HANDLE fileHandle = CreateFileW((LPCWSTR)filename.c_str(), READ_CONTROL | ACCESS_SYSTEM_SECURITY, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fileHandle == INVALID_HANDLE_VALUE) {
            std::wcerr << L"Error opening file: " << getErrorMessage(GetLastError()) << std::endl;
            return 1;
        }

        PACL pSACL = getFileSACL(fileHandle);
        if (pSACL) {
            printTrustLevel(pSACL);
        }

        CloseHandle(fileHandle);
    } else if (option == L"-r" && argc == 3) {
        std::wstring registryKey = argv[2];
        std::wcout << L"Registry Key: " << registryKey << std::endl;

        if (!enablePrivilege(L"SeSecurityPrivilege")) {
            std::wcerr << L"Failed to enable SeSecurityPrivilege. Continuing without it." << std::endl;
        }

        HKEY hKey = openRegistryKey(registryKey, READ_CONTROL | ACCESS_SYSTEM_SECURITY);
        if (hKey) {
            PACL pSACL = getRegKeySACL(hKey);
            if (pSACL) {
                printTrustLevel(pSACL);
            }
            RegCloseKey(hKey);
        }
    } else {
        printUsage();
        return 1;
    }

    return 0;
}
