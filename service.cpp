#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <userenv.h>

#include <atomic>
#include <cstdio>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "antivirus_rpc.h"
#include "rpc_client.h"
#include "shared.h"

namespace {

struct SessionProcess {
    HANDLE processHandle = nullptr;
    DWORD processId = 0;
    DWORD mainThreadId = 0;
};

SERVICE_STATUS_HANDLE g_serviceStatusHandle = nullptr;
SERVICE_STATUS g_serviceStatus = {};
DWORD g_statusCheckpoint = 1;

std::wstring g_serviceDirectory;
std::wstring g_trayApplicationPath;

std::mutex g_processMutex;
std::map<DWORD, SessionProcess> g_sessionProcesses;
std::atomic<bool> g_stopRequested(false);

std::wstring GetModulePath() {
    wchar_t buffer[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buffer, static_cast<DWORD>(std::size(buffer)));
    return buffer;
}

std::wstring GetDirectoryName(const std::wstring& path) {
    const std::wstring::size_type separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) {
        return L".";
    }

    return path.substr(0, separator);
}

std::wstring QuoteForCommandLine(const std::wstring& path) {
    return L"\"" + path + L"\"";
}

bool FileExists(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

void CloseTrackedProcess(SessionProcess& sessionProcess) {
    if (sessionProcess.processHandle) {
        CloseHandle(sessionProcess.processHandle);
        sessionProcess.processHandle = nullptr;
    }
    sessionProcess.processId = 0;
    sessionProcess.mainThreadId = 0;
}

bool IsProcessRunning(HANDLE processHandle) {
    if (!processHandle) {
        return false;
    }

    return WaitForSingleObject(processHandle, 0) == WAIT_TIMEOUT;
}

void CleanupDeadProcessesLocked() {
    for (auto iterator = g_sessionProcesses.begin(); iterator != g_sessionProcesses.end();) {
        if (IsProcessRunning(iterator->second.processHandle)) {
            ++iterator;
            continue;
        }

        CloseTrackedProcess(iterator->second);
        iterator = g_sessionProcesses.erase(iterator);
    }
}

void UpdateServiceStatus(DWORD currentState, DWORD win32ExitCode = NO_ERROR, DWORD waitHint = 0) {
    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwCurrentState = currentState;
    g_serviceStatus.dwWin32ExitCode = win32ExitCode;
    g_serviceStatus.dwWaitHint = waitHint;
    g_serviceStatus.dwControlsAccepted = (currentState == SERVICE_RUNNING) ? SERVICE_ACCEPT_SESSIONCHANGE : 0;

    if (currentState == SERVICE_START_PENDING || currentState == SERVICE_STOP_PENDING) {
        g_serviceStatus.dwCheckPoint = g_statusCheckpoint++;
    } else {
        g_serviceStatus.dwCheckPoint = 0;
        g_statusCheckpoint = 1;
    }

    if (g_serviceStatusHandle) {
        SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
    }
}

bool LaunchTrayApplicationForSession(DWORD sessionId) {
    if (sessionId == 0 || !FileExists(g_trayApplicationPath)) {
        return false;
    }

    {
        std::lock_guard<std::mutex> guard(g_processMutex);
        CleanupDeadProcessesLocked();

        const auto existing = g_sessionProcesses.find(sessionId);
        if (existing != g_sessionProcesses.end() && IsProcessRunning(existing->second.processHandle)) {
            return true;
        }
    }

    HANDLE userToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &userToken)) {
        return false;
    }

    LPVOID environment = nullptr;
    CreateEnvironmentBlock(&environment, userToken, FALSE);

    STARTUPINFOW startupInfo = {};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION processInformation = {};
    std::wstring commandLine = QuoteForCommandLine(g_trayApplicationPath);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    const BOOL created = CreateProcessAsUserW(
        userToken,
        g_trayApplicationPath.c_str(),
        mutableCommandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT,
        environment,
        g_serviceDirectory.c_str(),
        &startupInfo,
        &processInformation
    );

    if (environment) {
        DestroyEnvironmentBlock(environment);
    }
    CloseHandle(userToken);

    if (!created) {
        return false;
    }

    CloseHandle(processInformation.hThread);

    std::lock_guard<std::mutex> guard(g_processMutex);
    auto& slot = g_sessionProcesses[sessionId];
    CloseTrackedProcess(slot);
    slot.processHandle = processInformation.hProcess;
    slot.processId = processInformation.dwProcessId;
    slot.mainThreadId = processInformation.dwThreadId;
    return true;
}

void LaunchTrayApplicationsForExistingSessions() {
    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD sessionCount = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &sessionCount)) {
        return;
    }

    for (DWORD index = 0; index < sessionCount; ++index) {
        const DWORD sessionId = sessions[index].SessionId;
        if (sessionId != 0) {
            LaunchTrayApplicationForSession(sessionId);
        }
    }

    WTSFreeMemory(sessions);
}

DWORD WINAPI StopRpcServerThread(LPVOID) {
    RpcMgmtStopServerListening(nullptr);
    return 0;
}

void StopAllTrayApplications() {
    std::vector<SessionProcess> processes;

    {
        std::lock_guard<std::mutex> guard(g_processMutex);
        for (auto& entry : g_sessionProcesses) {
            processes.push_back(entry.second);
            entry.second.processHandle = nullptr;
        }
        g_sessionProcesses.clear();
    }

    for (const SessionProcess& sessionProcess : processes) {
        if (sessionProcess.mainThreadId != 0) {
            PostThreadMessageW(sessionProcess.mainThreadId, WM_QUIT, 0, 0);
        }
    }

    for (SessionProcess& sessionProcess : processes) {
        if (sessionProcess.processHandle) {
            if (WaitForSingleObject(sessionProcess.processHandle, 5000) == WAIT_TIMEOUT) {
                TerminateProcess(sessionProcess.processHandle, 0);
                WaitForSingleObject(sessionProcess.processHandle, 1000);
            }
            CloseTrackedProcess(sessionProcess);
        }
    }
}

RPC_STATUS StartRpcServer() {
    RPC_STATUS status = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(antivirus::kRpcEndpoint)),
        nullptr
    );
    if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) {
        return status;
    }

    status = RpcServerRegisterIf2(
        AntivirusRpc_v1_0_s_ifspec,
        nullptr,
        nullptr,
        0,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        static_cast<unsigned int>(-1),
        nullptr
    );
    if (status != RPC_S_OK && status != RPC_S_TYPE_ALREADY_REGISTERED) {
        return status;
    }

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    if (status != RPC_S_OK && status != RPC_S_ALREADY_LISTENING) {
        return status;
    }

    return RPC_S_OK;
}

void StopRpcServer() {
    RpcServerUnregisterIf(AntivirusRpc_v1_0_s_ifspec, nullptr, FALSE);
}

DWORD WINAPI ServiceControlHandler(
    DWORD control,
    DWORD eventType,
    LPVOID eventData,
    LPVOID
) {
    switch (control) {
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    case SERVICE_CONTROL_SESSIONCHANGE:
        if (!g_stopRequested.load() &&
            (eventType == WTS_SESSION_LOGON || eventType == WTS_CONSOLE_CONNECT || eventType == WTS_REMOTE_CONNECT)) {
            const auto* notification = static_cast<WTSSESSION_NOTIFICATION*>(eventData);
            if (notification) {
                LaunchTrayApplicationForSession(notification->dwSessionId);
            }
        }
        return NO_ERROR;

    default:
        return NO_ERROR;
    }
}

bool InstallService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        return false;
    }

    const std::wstring binaryPath = QuoteForCommandLine(GetModulePath());
    SC_HANDLE service = CreateServiceW(
        scm,
        antivirus::kServiceName,
        antivirus::kServiceDisplayName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        binaryPath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );

    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_DESCRIPTIONW description = {};
    description.lpDescription = const_cast<LPWSTR>(antivirus::kServiceDescription);
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description);

    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
    PACL currentDacl = nullptr;
    PACL updatedDacl = nullptr;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    DWORD bytesNeeded = 0;
    DWORD installError = ERROR_ACCESS_DENIED;

    if (!QueryServiceObjectSecurity(
            service,
            DACL_SECURITY_INFORMATION,
            nullptr,
            0,
            &bytesNeeded) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        securityDescriptor = static_cast<PSECURITY_DESCRIPTOR>(LocalAlloc(LPTR, bytesNeeded));
    }
    else {
        installError = GetLastError();
    }

    bool accessUpdated = false;
    if (securityDescriptor &&
        QueryServiceObjectSecurity(
            service,
            DACL_SECURITY_INFORMATION,
            securityDescriptor,
            bytesNeeded,
            &bytesNeeded) &&
        GetSecurityDescriptorDacl(securityDescriptor, &daclPresent, &currentDacl, &daclDefaulted)) {
        PSID authenticatedUsersSid = nullptr;
        if (ConvertStringSidToSidW(L"S-1-5-11", &authenticatedUsersSid)) {
            EXPLICIT_ACCESSW access = {};
            access.grfAccessPermissions = SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE;
            access.grfAccessMode = GRANT_ACCESS;
            access.grfInheritance = NO_INHERITANCE;
            BuildTrusteeWithSidW(&access.Trustee, authenticatedUsersSid);

            const DWORD aclResult = SetEntriesInAclW(1, &access, currentDacl, &updatedDacl);
            if (aclResult == ERROR_SUCCESS) {
                SECURITY_DESCRIPTOR descriptor = {};
                if (InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) &&
                    SetSecurityDescriptorDacl(&descriptor, TRUE, updatedDacl, FALSE) &&
                    SetServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, &descriptor)) {
                    accessUpdated = true;
                } else {
                    installError = GetLastError();
                }
            } else {
                installError = aclResult;
            }

            LocalFree(authenticatedUsersSid);
        } else {
            installError = GetLastError();
        }
    } else if (securityDescriptor) {
        installError = GetLastError();
    }

    if (updatedDacl) {
        LocalFree(updatedDacl);
    }
    if (securityDescriptor) {
        LocalFree(securityDescriptor);
    }

    if (!accessUpdated) {
        SetLastError(installError);
        DeleteService(service);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

bool UninstallService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(
        scm,
        antivirus::kServiceName,
        DELETE | SERVICE_QUERY_STATUS
    );
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS statusProcess = {};
    DWORD bytesNeeded = 0;
    if (QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&statusProcess),
            sizeof(statusProcess),
            &bytesNeeded) &&
        statusProcess.dwCurrentState != SERVICE_STOPPED) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }

    const BOOL deleted = DeleteService(service);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return deleted == TRUE;
}

void PrintLastErrorMessage(const wchar_t* action, DWORD error) {
    wchar_t* buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD length = FormatMessageW(
        flags,
        nullptr,
        error,
        0,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr
    );

    if (length != 0 && buffer) {
        std::fwprintf(stderr, L"%ls failed: [%lu] %ls\n", action, error, buffer);
        LocalFree(buffer);
        return;
    }

    std::fwprintf(stderr, L"%ls failed: [%lu]\n", action, error);
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_serviceStatusHandle = RegisterServiceCtrlHandlerExW(
        antivirus::kServiceName,
        ServiceControlHandler,
        nullptr
    );
    if (!g_serviceStatusHandle) {
        return;
    }

    UpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 5000);

    g_serviceDirectory = GetDirectoryName(GetModulePath());
    g_trayApplicationPath = g_serviceDirectory + L"\\" + antivirus::kTrayExecutableName;
    if (!FileExists(g_trayApplicationPath)) {
        UpdateServiceStatus(SERVICE_STOPPED, ERROR_FILE_NOT_FOUND);
        return;
    }

    const RPC_STATUS rpcStatus = StartRpcServer();
    if (rpcStatus != RPC_S_OK) {
        UpdateServiceStatus(SERVICE_STOPPED, rpcStatus);
        return;
    }

    LaunchTrayApplicationsForExistingSessions();
    UpdateServiceStatus(SERVICE_RUNNING);

    RpcMgmtWaitServerListen();

    UpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
    StopAllTrayApplications();
    StopRpcServer();
    UpdateServiceStatus(SERVICE_STOPPED);
}

} // namespace

extern "C" void RequestServiceStop(void)
{
    if (g_stopRequested.exchange(true))
        return;

    
    UpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 10000);

  
    HANDLE stopThread = CreateThread(nullptr, 0, StopRpcServerThread, nullptr, 0, nullptr);
    if (stopThread) {
        CloseHandle(stopThread);
    }

   
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1) {
        const std::wstring command = argv[1];

        if (command == L"--install") {
            if (InstallService()) {
                std::wprintf(L"Service installed successfully.\n");
                return 0;
            }

            PrintLastErrorMessage(L"Service installation", GetLastError());
            return 1;
        }

        if (command == L"--uninstall") {
            if (UninstallService()) {
                std::wprintf(L"Service uninstalled successfully.\n");
                return 0;
            }

            PrintLastErrorMessage(L"Service uninstall", GetLastError());
            return 1;
        }

        if (command == L"--request-stop") {
            if (RequestServiceStopViaRpc()) {
                std::wprintf(L"Stop request sent successfully.\n");
                return 0;
            }

            std::fwprintf(stderr, L"RPC stop request failed.\n");
            return 1;
        }
    }

    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(antivirus::kServiceName), ServiceMain },
        { nullptr, nullptr }
    };

    return StartServiceCtrlDispatcherW(serviceTable) ? 0 : 1;
}
