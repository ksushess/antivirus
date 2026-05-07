#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <aclapi.h>
#include <iphlpapi.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <userenv.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "antivirus_rpc.h"
#include "rpc_client.h"
#include "shared.h"
#include "ziopvo_client.h"

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

std::mutex g_authMutex;
std::wstring g_authenticatedUsername;
std::wstring g_authenticatedEmail;
std::wstring g_authenticatedRole;
std::string g_accessToken;
std::string g_refreshToken;
std::chrono::system_clock::time_point g_accessTokenExpiry = {};
std::chrono::system_clock::time_point g_refreshTokenExpiry = {};
long g_lastAuthResult = antivirus::kRpcResultNotAuthenticated;
std::wstring g_lastAuthMessage = L"User is not authenticated.";

HANDLE g_authStopEvent = nullptr;
HANDLE g_authWakeEvent = nullptr;
HANDLE g_authWorkerThread = nullptr;

std::wstring g_deviceName;
std::wstring g_deviceMac;
antivirus::LicenseTicket g_licenseTicket;
bool g_hasLicenseTicket = false;
long g_licenseState = antivirus::kLicenseStateMissing;
std::wstring g_licenseMessage = L"No active license.";
std::chrono::system_clock::time_point g_licenseRefreshDeadline = {};

void StopAllTrayApplications();
void StopRpcServer();
bool StartAuthWorker();
void StopAuthWorker();
void ClearLicenseStateLocked(long state, const std::wstring& message);

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

std::wstring FormatMacAddress(const BYTE* address, ULONG length) {
    if (!address || length == 0) {
        return L"";
    }

    wchar_t segment[4] = {};
    std::wstring result;
    for (ULONG index = 0; index < length; ++index) {
        if (!result.empty()) {
            result += L":";
        }

        swprintf_s(segment, L"%02X", address[index]);
        result += segment;
    }

    return result;
}

std::wstring DetectPrimaryMacAddress() {
    ULONG bufferSize = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, nullptr, &bufferSize);
    if (bufferSize == 0) {
        return L"";
    }

    std::vector<BYTE> buffer(bufferSize);
    auto* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    if (GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr,
            addresses,
            &bufferSize) != NO_ERROR) {
        return L"";
    }

    for (IP_ADAPTER_ADDRESSES* adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
            adapter->OperStatus != IfOperStatusUp ||
            adapter->PhysicalAddressLength == 0) {
            continue;
        }

        return FormatMacAddress(adapter->PhysicalAddress, adapter->PhysicalAddressLength);
    }

    return L"";
}

std::wstring DetectDeviceName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = static_cast<DWORD>(std::size(buffer));
    if (GetComputerNameW(buffer, &size)) {
        return buffer;
    }

    return L"Windows Device";
}

void CopyRpcText(const std::wstring& source, long capacity, wchar_t* target) {
    if (!target || capacity <= 0) {
        return;
    }

    target[0] = L'\0';
    wcsncpy_s(target, static_cast<size_t>(capacity), source.c_str(), _TRUNCATE);
}

long MapBackendStatusToRpcResult(const antivirus::BackendCallStatus& status, bool authenticationRequest) {
    if (status.transportError != 0) {
        return antivirus::kRpcResultTransportError;
    }

    if (status.httpStatus == 0 || status.httpStatus >= 500) {
        return antivirus::kRpcResultBackendUnavailable;
    }

    if (status.httpStatus == 400) {
        return authenticationRequest ? antivirus::kRpcResultInvalidCredentials : antivirus::kRpcResultUnexpectedResponse;
    }

    if (status.httpStatus == 401 || status.httpStatus == 403) {
        return authenticationRequest ? antivirus::kRpcResultInvalidCredentials : antivirus::kRpcResultNotAuthenticated;
    }

    return antivirus::kRpcResultUnexpectedResponse;
}

void ClearAuthenticationStateLocked(const std::wstring& message, long resultCode) {
    g_authenticatedUsername.clear();
    g_authenticatedEmail.clear();
    g_authenticatedRole.clear();
    g_accessToken.clear();
    g_refreshToken.clear();
    g_accessTokenExpiry = {};
    g_refreshTokenExpiry = {};
    g_lastAuthResult = resultCode;
    g_lastAuthMessage = message;
    ClearLicenseStateLocked(antivirus::kLicenseStateMissing, L"No active license.");
}

void StoreAuthenticatedStateLocked(
    const antivirus::UserProfile& profile,
    const antivirus::TokenBundle& tokens
) {
    g_authenticatedUsername = profile.username;
    g_authenticatedEmail = profile.email;
    g_authenticatedRole = profile.role;
    g_accessToken = tokens.accessToken;
    g_refreshToken = tokens.refreshToken;
    g_accessTokenExpiry = tokens.accessExpiry;
    g_refreshTokenExpiry = tokens.refreshExpiry;
    g_lastAuthResult = antivirus::kRpcResultOk;
    g_lastAuthMessage.clear();
    ClearLicenseStateLocked(antivirus::kLicenseStateMissing, L"No active license.");
}

void WakeAuthWorker() {
    if (g_authWakeEvent) {
        SetEvent(g_authWakeEvent);
    }
}

bool IsRefreshFailureFinal(const antivirus::BackendCallStatus& status) {
    return status.httpStatus == 400 || status.httpStatus == 401 || status.httpStatus == 403 || status.httpStatus == 404;
}

bool IsAuthenticatedLocked() {
    return !g_accessToken.empty() && !g_refreshToken.empty() && !g_authenticatedUsername.empty();
}

void ClearLicenseStateLocked(long state, const std::wstring& message) {
    g_licenseTicket = {};
    g_hasLicenseTicket = false;
    g_licenseState = state;
    g_licenseMessage = message;
    g_licenseRefreshDeadline = {};
}

bool ParseBackendLicenseState(const std::wstring& message, long* state, std::wstring* normalizedMessage) {
    if (normalizedMessage) {
        *normalizedMessage = message;
    }

    if (message.find(L"License is blocked") != std::wstring::npos) {
        if (state) {
            *state = antivirus::kLicenseStateBlocked;
        }
        return true;
    }

    if (message.find(L"License has expired") != std::wstring::npos) {
        if (state) {
            *state = antivirus::kLicenseStateExpired;
        }
        return true;
    }

    if (message.find(L"No active license found") != std::wstring::npos ||
        message.find(L"Device not found") != std::wstring::npos ||
        message.find(L"License is not activated yet") != std::wstring::npos ||
        message.find(L"License not bound to this user") != std::wstring::npos) {
        if (state) {
            *state = antivirus::kLicenseStateMissing;
        }
        return true;
    }

    return false;
}

std::chrono::system_clock::time_point ComputeLicenseRefreshDeadline(const antivirus::LicenseTicket& ticket) {
    if (ticket.currentTime == std::chrono::system_clock::time_point() ||
        ticket.lifetime <= std::chrono::minutes::zero()) {
        return {};
    }

    std::chrono::system_clock::time_point deadline = ticket.currentTime + ticket.lifetime - std::chrono::minutes(5);
    if (ticket.expirationTime != std::chrono::system_clock::time_point()) {
        const auto expiryDeadline = ticket.expirationTime - std::chrono::minutes(1);
        if (deadline == std::chrono::system_clock::time_point() || expiryDeadline < deadline) {
            deadline = expiryDeadline;
        }
    }

    return deadline;
}

void StoreLicenseTicketLocked(const antivirus::LicenseTicket& ticket) {
    g_licenseTicket = ticket;
    g_hasLicenseTicket = true;
    g_licenseState = ticket.blocked ? antivirus::kLicenseStateBlocked : antivirus::kLicenseStateActive;
    g_licenseMessage.clear();
    g_licenseRefreshDeadline = ComputeLicenseRefreshDeadline(ticket);
}

bool IsLicenseRefreshDueLocked() {
    if (!g_hasLicenseTicket || g_licenseState != antivirus::kLicenseStateActive) {
        return false;
    }

    const auto now = std::chrono::system_clock::now();
    if (g_licenseTicket.expirationTime != std::chrono::system_clock::time_point() &&
        g_licenseTicket.expirationTime <= now) {
        return true;
    }

    return g_licenseRefreshDeadline == std::chrono::system_clock::time_point() ||
           g_licenseRefreshDeadline <= now;
}

void SnapshotLicenseOutputsLocked(long* licenseState, std::wstring* expirationDate, std::wstring* message) {
    if (licenseState) {
        *licenseState = g_licenseState;
    }
    if (expirationDate) {
        *expirationDate = g_hasLicenseTicket ? g_licenseTicket.expirationDate : L"";
    }
    if (message) {
        *message = g_licenseMessage;
    }
}

long RefreshLicenseStateFromBackend(bool forceRefresh) {
    std::string accessToken;
    std::wstring deviceMac;

    {
        std::lock_guard<std::mutex> guard(g_authMutex);
        if (!IsAuthenticatedLocked()) {
            return antivirus::kRpcResultNotAuthenticated;
        }

        if (!forceRefresh && g_hasLicenseTicket && !IsLicenseRefreshDueLocked()) {
            return antivirus::kRpcResultOk;
        }

        accessToken = g_accessToken;
        deviceMac = g_deviceMac;
    }

    const antivirus::LicenseTicketResponse licenseResponse = antivirus::BackendCheckLicense(accessToken, deviceMac);
    if (licenseResponse.status.success && licenseResponse.hasTicket) {
        std::lock_guard<std::mutex> guard(g_authMutex);
        if (g_accessToken == accessToken) {
            StoreLicenseTicketLocked(licenseResponse.ticket);
        }
        return antivirus::kRpcResultOk;
    }

    long parsedState = antivirus::kLicenseStateUnknown;
    std::wstring parsedMessage;
    if (ParseBackendLicenseState(licenseResponse.status.message, &parsedState, &parsedMessage)) {
        std::lock_guard<std::mutex> guard(g_authMutex);
        if (g_accessToken == accessToken) {
            ClearLicenseStateLocked(parsedState, parsedMessage);
        }
        return antivirus::kRpcResultOk;
    }

    const long resultCode = MapBackendStatusToRpcResult(licenseResponse.status, false);
    if (resultCode == antivirus::kRpcResultNotAuthenticated) {
        std::lock_guard<std::mutex> guard(g_authMutex);
        if (g_accessToken == accessToken) {
            const std::wstring message = licenseResponse.status.message.empty()
                ? L"Session expired. Please sign in again."
                : licenseResponse.status.message;
            ClearAuthenticationStateLocked(message, antivirus::kRpcResultNotAuthenticated);
        }
    }

    return resultCode;
}

long ActivateLicenseViaBackend(const std::wstring& activationCode) {
    std::string accessToken;
    std::wstring deviceMac;
    std::wstring deviceName;

    {
        std::lock_guard<std::mutex> guard(g_authMutex);
        if (!IsAuthenticatedLocked()) {
            return antivirus::kRpcResultNotAuthenticated;
        }

        accessToken = g_accessToken;
        deviceMac = g_deviceMac;
        deviceName = g_deviceName;
    }

    antivirus::LicenseTicketResponse activationResponse = antivirus::BackendActivateLicense(
        accessToken,
        activationCode,
        deviceName,
        deviceMac
    );

    if (activationResponse.status.success) {
        if (!activationResponse.hasTicket) {
            return RefreshLicenseStateFromBackend(true);
        }

        std::lock_guard<std::mutex> guard(g_authMutex);
        if (g_accessToken == accessToken) {
            StoreLicenseTicketLocked(activationResponse.ticket);
        }
        return antivirus::kRpcResultOk;
    }

    const long resultCode = MapBackendStatusToRpcResult(activationResponse.status, false);
    if (resultCode == antivirus::kRpcResultNotAuthenticated) {
        std::lock_guard<std::mutex> guard(g_authMutex);
        if (g_accessToken == accessToken) {
            const std::wstring message = activationResponse.status.message.empty()
                ? L"Session expired. Please sign in again."
                : activationResponse.status.message;
            ClearAuthenticationStateLocked(message, antivirus::kRpcResultNotAuthenticated);
        }
        return antivirus::kRpcResultNotAuthenticated;
    }

    std::lock_guard<std::mutex> guard(g_authMutex);
    if (g_accessToken == accessToken) {
        const std::wstring message = activationResponse.status.message.empty()
            ? L"Product activation failed."
            : activationResponse.status.message;
        if (g_licenseState == antivirus::kLicenseStateUnknown) {
            g_licenseState = antivirus::kLicenseStateMissing;
        }
        g_licenseMessage = message;
    }
    return antivirus::kRpcResultActivationFailed;
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

DWORD WINAPI StopRpcListeningThread(LPVOID) {
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
            if (WaitForSingleObject(sessionProcess.processHandle, 500) == WAIT_TIMEOUT) {
                TerminateProcess(sessionProcess.processHandle, 0);
                WaitForSingleObject(sessionProcess.processHandle, 2000);
            }
            CloseTrackedProcess(sessionProcess);
        }
    }
}

DWORD CalculateNextAuthWakeDelayMs() {
    constexpr DWORD kDefaultDelayMs = 30000;

    std::lock_guard<std::mutex> guard(g_authMutex);
    const auto now = std::chrono::system_clock::now();
    bool hasDelay = false;
    DWORD bestDelay = kDefaultDelayMs;

    if (!g_refreshToken.empty()) {
        if (g_refreshTokenExpiry <= now || g_accessTokenExpiry == std::chrono::system_clock::time_point()) {
            return 0;
        }

        const auto refreshLeadTime = std::chrono::minutes(1);
        const auto refreshMoment = g_accessTokenExpiry - refreshLeadTime;
        if (refreshMoment <= now) {
            return 0;
        }

        const auto waitDuration = std::chrono::duration_cast<std::chrono::milliseconds>(refreshMoment - now);
        const auto waitCount = waitDuration.count();
        if (waitCount <= 0) {
            return 0;
        }

        const long long maxDelay = 60LL * 60LL * 1000LL;
        bestDelay = static_cast<DWORD>(waitCount > maxDelay ? maxDelay : waitCount);
        hasDelay = true;
    }

    if (g_hasLicenseTicket && g_licenseState == antivirus::kLicenseStateActive) {
        if (g_licenseRefreshDeadline == std::chrono::system_clock::time_point() || g_licenseRefreshDeadline <= now) {
            return 0;
        }

        const auto waitDuration = std::chrono::duration_cast<std::chrono::milliseconds>(g_licenseRefreshDeadline - now);
        const auto waitCount = waitDuration.count();
        if (waitCount <= 0) {
            return 0;
        }

        const long long maxDelay = 60LL * 60LL * 1000LL;
        const DWORD licenseDelay = static_cast<DWORD>(waitCount > maxDelay ? maxDelay : waitCount);
        if (!hasDelay || licenseDelay < bestDelay) {
            bestDelay = licenseDelay;
            hasDelay = true;
        }
    }

    return hasDelay ? bestDelay : kDefaultDelayMs;
}

DWORD WINAPI AuthWorkerThread(LPVOID) {
    HANDLE waitHandles[] = { g_authStopEvent, g_authWakeEvent };

    while (true) {
        std::string refreshToken;
        bool transientRefreshFailure = false;
        bool refreshLicense = false;
        {
            std::lock_guard<std::mutex> guard(g_authMutex);

            if (!g_refreshToken.empty()) {
                const auto now = std::chrono::system_clock::now();
                if (g_refreshTokenExpiry <= now) {
                    ClearAuthenticationStateLocked(L"Session expired. Please sign in again.", antivirus::kRpcResultNotAuthenticated);
                } else if (g_accessTokenExpiry <= now + std::chrono::minutes(1)) {
                    refreshToken = g_refreshToken;
                }
            }

            if (IsAuthenticatedLocked() && IsLicenseRefreshDueLocked()) {
                refreshLicense = true;
            }
        }

        if (!refreshToken.empty()) {
            const antivirus::RefreshResponse refreshResponse = antivirus::BackendRefresh(refreshToken);

            std::lock_guard<std::mutex> guard(g_authMutex);
            if (g_refreshToken == refreshToken && !g_refreshToken.empty()) {
                if (refreshResponse.status.success) {
                    g_accessToken = refreshResponse.tokens.accessToken;
                    g_refreshToken = refreshResponse.tokens.refreshToken;
                    g_accessTokenExpiry = refreshResponse.tokens.accessExpiry;
                    g_refreshTokenExpiry = refreshResponse.tokens.refreshExpiry;
                    g_lastAuthResult = antivirus::kRpcResultOk;
                    g_lastAuthMessage.clear();
                } else if (IsRefreshFailureFinal(refreshResponse.status)) {
                    const std::wstring message = refreshResponse.status.message.empty()
                        ? L"Session expired. Please sign in again."
                        : refreshResponse.status.message;
                    ClearAuthenticationStateLocked(message, antivirus::kRpcResultNotAuthenticated);
                } else {
                    if (!refreshResponse.status.message.empty()) {
                        g_lastAuthMessage = refreshResponse.status.message;
                    }
                    transientRefreshFailure = true;
                }
            }
        }

        if (refreshLicense) {
            const long licenseRefreshResult = RefreshLicenseStateFromBackend(true);
            if (licenseRefreshResult == antivirus::kRpcResultBackendUnavailable ||
                licenseRefreshResult == antivirus::kRpcResultTransportError ||
                licenseRefreshResult == antivirus::kRpcResultUnexpectedResponse) {
                transientRefreshFailure = true;
            }
        }

        const DWORD waitTimeoutMs = transientRefreshFailure ? 30000 : CalculateNextAuthWakeDelayMs();
        const DWORD waitResult = WaitForMultipleObjects(
            static_cast<DWORD>(std::size(waitHandles)),
            waitHandles,
            FALSE,
            waitTimeoutMs
        );

        if (waitResult == WAIT_OBJECT_0) {
            return 0;
        }

        if (waitResult == WAIT_FAILED) {
            return 1;
        }
    }
}

bool StartAuthWorker() {
    g_authStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_authWakeEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!g_authStopEvent || !g_authWakeEvent) {
        StopAuthWorker();
        return false;
    }

    g_authWorkerThread = CreateThread(nullptr, 0, AuthWorkerThread, nullptr, 0, nullptr);
    if (!g_authWorkerThread) {
        StopAuthWorker();
        return false;
    }

    return true;
}

void StopAuthWorker() {
    if (g_authStopEvent) {
        SetEvent(g_authStopEvent);
    }

    if (g_authWorkerThread) {
        WaitForSingleObject(g_authWorkerThread, 5000);
        CloseHandle(g_authWorkerThread);
        g_authWorkerThread = nullptr;
    }

    if (g_authWakeEvent) {
        CloseHandle(g_authWakeEvent);
        g_authWakeEvent = nullptr;
    }

    if (g_authStopEvent) {
        CloseHandle(g_authStopEvent);
        g_authStopEvent = nullptr;
    }

    std::lock_guard<std::mutex> guard(g_authMutex);
    ClearAuthenticationStateLocked(L"User is not authenticated.", antivirus::kRpcResultNotAuthenticated);
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

    g_deviceName = DetectDeviceName();
    g_deviceMac = DetectPrimaryMacAddress();
    if (g_deviceMac.empty()) {
        UpdateServiceStatus(SERVICE_STOPPED, ERROR_NOT_SUPPORTED);
        return;
    }

    if (!StartAuthWorker()) {
        UpdateServiceStatus(SERVICE_STOPPED, GetLastError() != NO_ERROR ? GetLastError() : ERROR_SERVICE_SPECIFIC_ERROR);
        return;
    }

    const RPC_STATUS rpcStatus = StartRpcServer();
    if (rpcStatus != RPC_S_OK) {
        StopAuthWorker();
        UpdateServiceStatus(SERVICE_STOPPED, rpcStatus);
        return;
    }

    LaunchTrayApplicationsForExistingSessions();
    UpdateServiceStatus(SERVICE_RUNNING);

    const RPC_STATUS waitStatus = RpcMgmtWaitServerListen();
    const DWORD stopError = (waitStatus == RPC_S_OK || waitStatus == RPC_S_NOT_LISTENING) ? NO_ERROR : waitStatus;

    UpdateServiceStatus(SERVICE_STOP_PENDING, stopError, 5000);
    StopAuthWorker();
    StopAllTrayApplications();
    StopRpcServer();
    UpdateServiceStatus(SERVICE_STOPPED, stopError);
}

} 

extern "C" void ServiceRequestServiceStop(void)
{
    if (g_stopRequested.exchange(true)) {
        return;
    }

    HANDLE stopThread = CreateThread(
        nullptr,
        0,
        StopRpcListeningThread,
        nullptr,
        0,
        nullptr
    );

    if (stopThread) {
        CloseHandle(stopThread);
    } else {
        RpcMgmtStopServerListening(nullptr);
    }
}

extern "C" long ServiceGetAuthenticationState(
    long* isAuthenticated,
    long usernameCapacity,
    wchar_t* username,
    long messageCapacity,
    wchar_t* message
) {
    if (isAuthenticated) {
        *isAuthenticated = 0;
    }
    CopyRpcText(L"", usernameCapacity, username);
    CopyRpcText(L"", messageCapacity, message);

    std::lock_guard<std::mutex> guard(g_authMutex);
    if (!g_accessToken.empty() && !g_authenticatedUsername.empty()) {
        if (isAuthenticated) {
            *isAuthenticated = 1;
        }
        CopyRpcText(g_authenticatedUsername, usernameCapacity, username);
        return antivirus::kRpcResultOk;
    }

    CopyRpcText(g_lastAuthMessage, messageCapacity, message);
    return g_lastAuthResult;
}

extern "C" long ServiceLoginUser(
    wchar_t* username,
    wchar_t* password,
    long* isAuthenticated,
    long messageCapacity,
    wchar_t* message
) {
    if (isAuthenticated) {
        *isAuthenticated = 0;
    }
    CopyRpcText(L"", messageCapacity, message);

    if (!username || !password || username[0] == L'\0' || password[0] == L'\0') {
        CopyRpcText(L"Username and password are required.", messageCapacity, message);
        return antivirus::kRpcResultInvalidCredentials;
    }

    const antivirus::LoginResponse loginResponse = antivirus::BackendLogin(username, password);
    if (!loginResponse.status.success) {
        CopyRpcText(loginResponse.status.message, messageCapacity, message);
        return MapBackendStatusToRpcResult(loginResponse.status, true);
    }

    const antivirus::UserProfileResponse profileResponse = antivirus::BackendGetCurrentUser(loginResponse.tokens.accessToken);
    if (!profileResponse.status.success) {
        const std::wstring errorMessage = profileResponse.status.message.empty()
            ? L"Authentication succeeded, but the user profile could not be loaded."
            : profileResponse.status.message;
        CopyRpcText(errorMessage, messageCapacity, message);
        return MapBackendStatusToRpcResult(profileResponse.status, false);
    }

    {
        std::lock_guard<std::mutex> guard(g_authMutex);
        StoreAuthenticatedStateLocked(profileResponse.profile, loginResponse.tokens);
    }

    WakeAuthWorker();

    if (isAuthenticated) {
        *isAuthenticated = 1;
    }
    CopyRpcText(L"Authentication successful.", messageCapacity, message);
    return antivirus::kRpcResultOk;
}

extern "C" long ServiceLogoutUser(
    long messageCapacity,
    wchar_t* message
) {
    {
        std::lock_guard<std::mutex> guard(g_authMutex);
        ClearAuthenticationStateLocked(L"User is not authenticated.", antivirus::kRpcResultNotAuthenticated);
    }

    WakeAuthWorker();
    CopyRpcText(L"Signed out successfully.", messageCapacity, message);
    return antivirus::kRpcResultOk;
}

extern "C" long ServiceGetLicenseState(
    long* licenseState,
    long expirationCapacity,
    wchar_t* expirationDate,
    long messageCapacity,
    wchar_t* message
) {
    if (licenseState) {
        *licenseState = antivirus::kLicenseStateUnknown;
    }
    CopyRpcText(L"", expirationCapacity, expirationDate);
    CopyRpcText(L"", messageCapacity, message);

    const long refreshResult = RefreshLicenseStateFromBackend(false);

    std::wstring expiration;
    std::wstring currentMessage;
    long currentState = antivirus::kLicenseStateUnknown;
    {
        std::lock_guard<std::mutex> guard(g_authMutex);
        SnapshotLicenseOutputsLocked(&currentState, &expiration, &currentMessage);
    }

    if (licenseState) {
        *licenseState = currentState;
    }
    CopyRpcText(expiration, expirationCapacity, expirationDate);
    CopyRpcText(currentMessage, messageCapacity, message);

    if (refreshResult == antivirus::kRpcResultNotAuthenticated ||
        refreshResult == antivirus::kRpcResultBackendUnavailable ||
        refreshResult == antivirus::kRpcResultTransportError ||
        refreshResult == antivirus::kRpcResultUnexpectedResponse) {
        if (refreshResult == antivirus::kRpcResultNotAuthenticated && currentMessage.empty()) {
            CopyRpcText(L"User is not authenticated.", messageCapacity, message);
        }
        return refreshResult;
    }

    return currentState == antivirus::kLicenseStateActive
        ? antivirus::kRpcResultOk
        : antivirus::kRpcResultLicenseRequired;
}

extern "C" long ServiceActivateProduct(
    wchar_t* activationCode,
    long* licenseState,
    long expirationCapacity,
    wchar_t* expirationDate,
    long messageCapacity,
    wchar_t* message
) {
    if (licenseState) {
        *licenseState = antivirus::kLicenseStateUnknown;
    }
    CopyRpcText(L"", expirationCapacity, expirationDate);
    CopyRpcText(L"", messageCapacity, message);

    if (!activationCode || activationCode[0] == L'\0') {
        if (licenseState) {
            *licenseState = antivirus::kLicenseStateMissing;
        }
        CopyRpcText(L"Activation code is required.", messageCapacity, message);
        return antivirus::kRpcResultActivationFailed;
    }

    const long activationResult = ActivateLicenseViaBackend(activationCode);

    std::wstring expiration;
    std::wstring currentMessage;
    long currentState = antivirus::kLicenseStateUnknown;
    {
        std::lock_guard<std::mutex> guard(g_authMutex);
        SnapshotLicenseOutputsLocked(&currentState, &expiration, &currentMessage);
    }

    if (licenseState) {
        *licenseState = currentState;
    }
    CopyRpcText(expiration, expirationCapacity, expirationDate);

    if (activationResult == antivirus::kRpcResultOk) {
        CopyRpcText(L"Product activation successful.", messageCapacity, message);
        return antivirus::kRpcResultOk;
    }

    CopyRpcText(currentMessage, messageCapacity, message);
    return activationResult;
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

        if (command == L"--auth-state") {
            antivirus::RpcAuthenticationState state;
            if (!GetAuthenticationStateViaRpc(&state)) {
                std::fwprintf(stderr, L"Unable to query authentication state via RPC.\n");
                return 1;
            }

            std::wprintf(L"Authenticated: %ls\n", state.isAuthenticated ? L"yes" : L"no");
            if (!state.username.empty()) {
                std::wprintf(L"Username: %ls\n", state.username.c_str());
            }
            if (!state.message.empty()) {
                std::wprintf(L"Message: %ls\n", state.message.c_str());
            }
            std::wprintf(L"Result code: %ld\n", state.resultCode);
            return state.resultCode == antivirus::kRpcResultOk ? 0 : 1;
        }

        if (command == L"--login") {
            if (argc < 4) {
                std::fwprintf(stderr, L"Usage: antivirus_service.exe --login <username> <password>\n");
                return 1;
            }

            antivirus::RpcAuthenticationState state;
            if (!LoginUserViaRpc(argv[2], argv[3], &state)) {
                std::fwprintf(stderr, L"Unable to perform login via RPC.\n");
                return 1;
            }

            if (!state.message.empty()) {
                std::wprintf(L"%ls\n", state.message.c_str());
            }
            if (state.isAuthenticated && !state.username.empty()) {
                std::wprintf(L"Authenticated as: %ls\n", state.username.c_str());
            }
            std::wprintf(L"Result code: %ld\n", state.resultCode);
            return state.resultCode == antivirus::kRpcResultOk ? 0 : 1;
        }

        if (command == L"--logout") {
            std::wstring message;
            long resultCode = antivirus::kRpcResultUnexpectedResponse;
            if (!LogoutUserViaRpc(&message, &resultCode)) {
                std::fwprintf(stderr, L"Unable to perform logout via RPC.\n");
                return 1;
            }

            if (!message.empty()) {
                std::wprintf(L"%ls\n", message.c_str());
            }
            std::wprintf(L"Result code: %ld\n", resultCode);
            return resultCode == antivirus::kRpcResultOk ? 0 : 1;
        }

        if (command == L"--license-state") {
            antivirus::RpcLicenseState state;
            if (!GetLicenseStateViaRpc(&state)) {
                std::fwprintf(stderr, L"Unable to query license state via RPC.\n");
                return 1;
            }

            std::wprintf(L"License state: %ld\n", state.licenseState);
            if (!state.expirationDate.empty()) {
                std::wprintf(L"Expiration: %ls\n", state.expirationDate.c_str());
            }
            if (!state.message.empty()) {
                std::wprintf(L"Message: %ls\n", state.message.c_str());
            }
            std::wprintf(L"Result code: %ld\n", state.resultCode);
            return state.resultCode == antivirus::kRpcResultOk ? 0 : 1;
        }

        if (command == L"--activate") {
            if (argc < 3) {
                std::fwprintf(stderr, L"Usage: antivirus_service.exe --activate <code>\n");
                return 1;
            }

            antivirus::RpcLicenseState state;
            if (!ActivateProductViaRpc(argv[2], &state)) {
                std::fwprintf(stderr, L"Unable to activate product via RPC.\n");
                return 1;
            }

            if (!state.message.empty()) {
                std::wprintf(L"%ls\n", state.message.c_str());
            }
            if (!state.expirationDate.empty()) {
                std::wprintf(L"Expiration: %ls\n", state.expirationDate.c_str());
            }
            std::wprintf(L"License state: %ld\n", state.licenseState);
            std::wprintf(L"Result code: %ld\n", state.resultCode);
            return state.resultCode == antivirus::kRpcResultOk ? 0 : 1;
        }
    }

    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(antivirus::kServiceName), ServiceMain },
        { nullptr, nullptr }
    };

    return StartServiceCtrlDispatcherW(serviceTable) ? 0 : 1;
}

