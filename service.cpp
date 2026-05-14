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
#include <deque>
#include <filesystem>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "antivirus_rpc.h"
#include "rpc_client.h"
#include "scan_engine.h"
#include "shared.h"
#include "ziopvo_client.h"

namespace {


struct SessionProcess {
    HANDLE processHandle = nullptr;
    DWORD processId = 0;
    DWORD mainThreadId = 0;
};

struct ScheduledScanState {
    bool isEnabled = false;
    long intervalSeconds = 30;
    std::wstring targetPath;
    std::chrono::system_clock::time_point nextRun = {};
    std::chrono::system_clock::time_point lastRun = {};
    long lastResultCode = antivirus::kRpcResultUnexpectedResponse;
    std::wstring lastSummary;
};

struct MonitoredDirectory {
    std::wstring path;
    HANDLE stopEvent = nullptr;
    HANDLE thread = nullptr;
};

struct DirectoryScanOptions {
    bool includeCleanEntries = true;
    std::size_t maxReportedEntries = static_cast<std::size_t>(-1);
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
std::map<std::uint64_t, std::vector<antivirus::AvRecord>> g_avDatabase;
antivirus::AvDatabaseInfo g_avDatabaseInfo;
std::mutex g_backgroundMutex;
ScheduledScanState g_scheduledScanState;
HANDLE g_scheduleStopEvent = nullptr;
HANDLE g_scheduleWakeEvent = nullptr;
HANDLE g_scheduleWorkerThread = nullptr;
std::map<std::wstring, MonitoredDirectory> g_monitoredDirectories;
std::deque<std::wstring> g_monitorEventLog;
constexpr size_t kMaxMonitorEvents = 50;
constexpr std::size_t kMaxCompactScanDetails = 25;

void StopAllTrayApplications();
void StopRpcServer();
bool StartAuthWorker();
void StopAuthWorker();
bool StartScheduleWorker();
void StopScheduleWorker();
void ClearLicenseStateLocked(long state, const std::wstring& message);
bool EnsureAvDatabaseLoadedForActiveLicense(std::wstring* errorMessage);
void StopAllMonitoring();
long EnsureAntivirusReady(
    std::map<std::uint64_t, std::vector<antivirus::AvRecord>>* databaseSnapshot,
    antivirus::AvDatabaseInfo* infoSnapshot,
    std::wstring* message
);

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

bool HasActiveLicenseLocked() {
    return !g_accessToken.empty() &&
           !g_refreshToken.empty() &&
           !g_authenticatedUsername.empty() &&
           g_hasLicenseTicket &&
           g_licenseState == antivirus::kLicenseStateActive;
}

void ClearAvDatabaseLocked() {
    g_avDatabase.clear();
    g_avDatabaseInfo = {};
}

bool LoadAvDatabaseIntoMemory(std::wstring* errorMessage) {
    std::map<std::uint64_t, std::vector<antivirus::AvRecord>> database;
    antivirus::AvDatabaseInfo info;
    if (!antivirus::BuildDemoAvDatabase(&database, &info, errorMessage)) {
        return false;
    }

    std::lock_guard<std::mutex> guard(g_authMutex);
    if (!HasActiveLicenseLocked()) {
        if (errorMessage && errorMessage->empty()) {
            *errorMessage = L"Antivirus bases cannot be loaded without an active license.";
        }
        return false;
    }

    g_avDatabase = std::move(database);
    g_avDatabaseInfo = std::move(info);
    return true;
}

bool EnsureAvDatabaseLoadedForActiveLicense(std::wstring* errorMessage) {
    {
        std::lock_guard<std::mutex> guard(g_authMutex);
        if (!HasActiveLicenseLocked()) {
            if (errorMessage && errorMessage->empty()) {
                *errorMessage = L"An active license is required to load antivirus bases.";
            }
            return false;
        }

        if (g_avDatabaseInfo.isLoaded && !g_avDatabase.empty()) {
            return true;
        }
    }

    return LoadAvDatabaseIntoMemory(errorMessage);
}

void PreloadAvDatabaseBestEffort() {
    std::map<std::uint64_t, std::vector<antivirus::AvRecord>> database;
    antivirus::AvDatabaseInfo info;
    std::wstring ignoredError;
    if (!antivirus::BuildDemoAvDatabase(&database, &info, &ignoredError)) {
        return;
    }

    std::lock_guard<std::mutex> guard(g_authMutex);
    g_avDatabase = std::move(database);
    g_avDatabaseInfo = std::move(info);
}

std::wstring FormatTimePoint(const std::chrono::system_clock::time_point& value) {
    if (value == std::chrono::system_clock::time_point()) {
        return L"";
    }

    const std::time_t timeValue = std::chrono::system_clock::to_time_t(value);
    std::tm localTime = {};
    if (localtime_s(&localTime, &timeValue) != 0) {
        return L"";
    }

    wchar_t buffer[64] = {};
    if (wcsftime(buffer, static_cast<size_t>(std::size(buffer)), L"%Y-%m-%d %H:%M:%S", &localTime) == 0) {
        return L"";
    }

    return buffer;
}

void WakeScheduleWorker() {
    if (g_scheduleWakeEvent) {
        SetEvent(g_scheduleWakeEvent);
    }
}

void AppendMonitoringEventLocked(const std::wstring& text) {
    if (text.empty()) {
        return;
    }

    const std::wstring timestamped = L"[" + FormatTimePoint(std::chrono::system_clock::now()) + L"] " + text;
    g_monitorEventLog.push_back(timestamped);
    while (g_monitorEventLog.size() > kMaxMonitorEvents) {
        g_monitorEventLog.pop_front();
    }
}

void AppendMonitoringEvent(const std::wstring& text) {
    std::lock_guard<std::mutex> guard(g_backgroundMutex);
    AppendMonitoringEventLocked(text);
}

std::wstring NormalizeExistingDirectoryPath(const std::wstring& path) {
    std::error_code error;
    const std::filesystem::path normalized = std::filesystem::weakly_canonical(std::filesystem::path(path), error);
    if (error) {
        return L"";
    }
    return normalized.wstring();
}

long ScanDirectoryWithDatabaseSnapshot(
    const std::wstring& path,
    const std::map<std::uint64_t, std::vector<antivirus::AvRecord>>& databaseSnapshot,
    long* scannedCount,
    long* detectedCount,
    std::wstring* summary,
    const DirectoryScanOptions& options = {}
) {
    if (scannedCount) {
        *scannedCount = 0;
    }
    if (detectedCount) {
        *detectedCount = 0;
    }
    if (summary) {
        summary->clear();
    }

    std::error_code pathError;
    const std::filesystem::path directoryPath(path);
    if (!std::filesystem::exists(directoryPath, pathError) ||
        !std::filesystem::is_directory(directoryPath, pathError)) {
        if (summary) {
            *summary = L"The selected path is not a directory.";
        }
        return antivirus::kRpcResultInvalidPath;
    }

    long localScannedCount = 0;
    long localDetectedCount = 0;
    long localErrorCount = 0;
    std::size_t reportedEntries = 0;
    std::wostringstream stream;
    stream << L"Directory: " << path << L"\r\n";

    try {
        std::filesystem::recursive_directory_iterator iterator(
            directoryPath,
            std::filesystem::directory_options::skip_permission_denied,
            pathError
        );
        if (pathError) {
            if (summary) {
                *summary = L"Unable to enumerate the selected directory.";
            }
            return antivirus::kRpcResultScanFailed;
        }

        for (const auto& entry : iterator) {
            if (g_stopRequested.load()) {
                if (summary) {
                    *summary = L"Scan cancelled because the service stop was requested.";
                }
                return antivirus::kRpcResultScanFailed;
            }

            std::error_code symlinkError;
            if (entry.is_symlink(symlinkError) && !symlinkError) {
                continue;
            }

            std::error_code statusError;
            if (!entry.is_regular_file(statusError) || statusError) {
                continue;
            }

            const antivirus::ScanResult result = antivirus::ScanFileWithDatabase(entry.path().wstring(), databaseSnapshot);
            ++localScannedCount;

            bool shouldReport = false;
            if (result.success && result.malicious) {
                ++localDetectedCount;
                shouldReport = true;
                if (reportedEntries < options.maxReportedEntries) {
                    stream << L"[INFECTED] " << result.path;
                    if (!result.threatName.empty()) {
                        stream << L" | " << result.threatName;
                    }
                    stream << L"\r\n";
                }
            } else if (!result.success) {
                ++localErrorCount;
                shouldReport = true;
                if (reportedEntries < options.maxReportedEntries) {
                    stream << L"[ERROR] " << result.path;
                    if (!result.message.empty()) {
                        stream << L" | " << result.message;
                    }
                    stream << L"\r\n";
                }
            } else if (options.includeCleanEntries) {
                shouldReport = true;
                if (reportedEntries < options.maxReportedEntries) {
                    stream << L"[CLEAN] " << result.path << L"\r\n";
                }
            }

            if (shouldReport && reportedEntries < options.maxReportedEntries) {
                ++reportedEntries;
            }
        }
    } catch (const std::filesystem::filesystem_error&) {
        if (summary) {
            *summary = L"Unable to enumerate the selected directory.";
        }
        return antivirus::kRpcResultScanFailed;
    }

    if (localScannedCount == 0) {
        stream << L"No regular files were found in the selected directory.\r\n";
    }

    stream << L"\r\nScanned objects: " << localScannedCount << L"\r\n";
    stream << L"Detected threats: " << localDetectedCount << L"\r\n";
    stream << L"Scan errors: " << localErrorCount;

    if (summary) {
        *summary = stream.str();
    }
    if (scannedCount) {
        *scannedCount = localScannedCount;
    }
    if (detectedCount) {
        *detectedCount = localDetectedCount;
    }

    return antivirus::kRpcResultOk;
}

long ScanFixedDrivesInternal(
    long* hasDetections,
    long* scannedCount,
    long* detectedCount,
    std::wstring* summary
) {
    if (hasDetections) {
        *hasDetections = 0;
    }
    if (scannedCount) {
        *scannedCount = 0;
    }
    if (detectedCount) {
        *detectedCount = 0;
    }
    if (summary) {
        summary->clear();
    }

    std::map<std::uint64_t, std::vector<antivirus::AvRecord>> databaseSnapshot;
    std::wstring readinessMessage;
    const long readinessResult = EnsureAntivirusReady(&databaseSnapshot, nullptr, &readinessMessage);
    if (readinessResult != antivirus::kRpcResultOk) {
        if (summary) {
            *summary = readinessMessage;
        }
        return readinessResult;
    }

    const DWORD driveMask = GetLogicalDrives();
    if (driveMask == 0) {
        if (summary) {
            *summary = L"Unable to enumerate logical drives.";
        }
        return antivirus::kRpcResultScanFailed;
    }

    long totalScanned = 0;
    long totalDetected = 0;
    std::wostringstream stream;
    stream << L"Fixed drives scan\r\n";

    for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
        if (g_stopRequested.load()) {
            if (summary) {
                *summary = L"Fixed drives scan cancelled because the service stop was requested.";
            }
            return antivirus::kRpcResultScanFailed;
        }

        const DWORD bit = 1u << (letter - L'A');
        if ((driveMask & bit) == 0) {
            continue;
        }

        std::wstring rootPath;
        rootPath += letter;
        rootPath += L":\\";

        if (GetDriveTypeW(rootPath.c_str()) != DRIVE_FIXED) {
            continue;
        }

        long driveScanned = 0;
        long driveDetected = 0;
        std::wstring driveSummary;
        DirectoryScanOptions options;
        options.includeCleanEntries = false;
        options.maxReportedEntries = kMaxCompactScanDetails;
        const long driveResult = ScanDirectoryWithDatabaseSnapshot(
            rootPath,
            databaseSnapshot,
            &driveScanned,
            &driveDetected,
            &driveSummary,
            options
        );

        stream << L"\r\n=== " << rootPath << L" ===\r\n";
        stream << driveSummary << L"\r\n";

        if (driveResult != antivirus::kRpcResultOk) {
            stream << L"Drive scan failed with result code: " << driveResult << L"\r\n";
        }

        totalScanned += driveScanned;
        totalDetected += driveDetected;
    }

    stream << L"\r\nTotal scanned objects: " << totalScanned << L"\r\n";
    stream << L"Total detected threats: " << totalDetected;

    if (hasDetections) {
        *hasDetections = totalDetected > 0 ? 1 : 0;
    }
    if (scannedCount) {
        *scannedCount = totalScanned;
    }
    if (detectedCount) {
        *detectedCount = totalDetected;
    }
    if (summary) {
        *summary = stream.str();
    }

    return antivirus::kRpcResultOk;
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
        bool shouldLoadDatabase = false;
        {
            std::lock_guard<std::mutex> guard(g_authMutex);
            if (g_accessToken == accessToken) {
                StoreLicenseTicketLocked(licenseResponse.ticket);
                shouldLoadDatabase = !g_avDatabaseInfo.isLoaded || g_avDatabase.empty();
            }
        }
        if (shouldLoadDatabase) {
            std::wstring ignoredError;
            EnsureAvDatabaseLoadedForActiveLicense(&ignoredError);
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
        bool shouldLoadDatabase = false;
        if (!activationResponse.hasTicket) {
            const long refreshResult = RefreshLicenseStateFromBackend(true);
            if (refreshResult != antivirus::kRpcResultOk) {
                return refreshResult;
            }
            shouldLoadDatabase = true;
        } else {
            std::lock_guard<std::mutex> guard(g_authMutex);
            if (g_accessToken == accessToken) {
                StoreLicenseTicketLocked(activationResponse.ticket);
                shouldLoadDatabase = true;
            }
        }

        if (shouldLoadDatabase) {
            std::wstring databaseError;
            if (!EnsureAvDatabaseLoadedForActiveLicense(&databaseError)) {
                std::lock_guard<std::mutex> guard(g_authMutex);
                if (g_accessToken == accessToken && g_licenseState == antivirus::kLicenseStateActive) {
                    g_licenseMessage = databaseError.empty()
                        ? L"Product activated, but antivirus bases could not be loaded."
                        : databaseError;
                }
                return antivirus::kRpcResultDatabaseUnavailable;
            }
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

std::wstring FormatFileScanSummary(const antivirus::ScanResult& result) {
    std::wostringstream stream;
    stream << L"Path: " << result.path << L"\r\n";
    stream << L"Object type: " << antivirus::ObjectTypeToDisplayName(result.objectType) << L"\r\n";

    if (!result.success) {
        stream << L"Status: Error\r\n";
        if (!result.message.empty()) {
            stream << L"Message: " << result.message;
        }
        return stream.str();
    }

    if (result.malicious) {
        stream << L"Status: Infected\r\n";
        stream << L"Threat: " << result.threatName << L"\r\n";
        stream << L"Offset: " << result.matchedOffset;
        return stream.str();
    }

    stream << L"Status: Clean\r\n";
    if (!result.message.empty()) {
        stream << L"Message: " << result.message;
    }
    return stream.str();
}

long EnsureAntivirusReady(
    std::map<std::uint64_t, std::vector<antivirus::AvRecord>>* databaseSnapshot,
    antivirus::AvDatabaseInfo* infoSnapshot,
    std::wstring* message
) {
    if (message) {
        message->clear();
    }

    const long refreshResult = RefreshLicenseStateFromBackend(false);
    if (refreshResult == antivirus::kRpcResultNotAuthenticated ||
        refreshResult == antivirus::kRpcResultBackendUnavailable ||
        refreshResult == antivirus::kRpcResultTransportError ||
        refreshResult == antivirus::kRpcResultUnexpectedResponse) {
        std::lock_guard<std::mutex> guard(g_authMutex);
        if (message) {
            *message = g_lastAuthMessage.empty() ? L"Unable to contact the antivirus service state." : g_lastAuthMessage;
        }
        return refreshResult;
    }

    {
        std::lock_guard<std::mutex> guard(g_authMutex);
        if (!IsAuthenticatedLocked()) {
            if (message) {
                *message = g_lastAuthMessage.empty() ? L"User is not authenticated." : g_lastAuthMessage;
            }
            return antivirus::kRpcResultNotAuthenticated;
        }

        if (!g_hasLicenseTicket || g_licenseState != antivirus::kLicenseStateActive) {
            if (message) {
                *message = g_licenseMessage.empty() ? L"No active license." : g_licenseMessage;
            }
            return antivirus::kRpcResultLicenseRequired;
        }
    }

    std::wstring loadError;
    if (!EnsureAvDatabaseLoadedForActiveLicense(&loadError)) {
        if (message) {
            *message = loadError.empty() ? L"Antivirus bases are not loaded." : loadError;
        }
        return antivirus::kRpcResultDatabaseUnavailable;
    }

    std::lock_guard<std::mutex> guard(g_authMutex);
    if (!HasActiveLicenseLocked()) {
        if (message) {
            *message = g_licenseMessage.empty() ? L"No active license." : g_licenseMessage;
        }
        return antivirus::kRpcResultLicenseRequired;
    }

    if (!g_avDatabaseInfo.isLoaded || g_avDatabase.empty()) {
        if (message) {
            *message = L"Antivirus bases are not loaded.";
        }
        return antivirus::kRpcResultDatabaseUnavailable;
    }

    if (databaseSnapshot) {
        *databaseSnapshot = g_avDatabase;
    }
    if (infoSnapshot) {
        *infoSnapshot = g_avDatabaseInfo;
    }
    return antivirus::kRpcResultOk;
}

long ScanFileInternal(
    const std::wstring& path,
    long* isMalicious,
    long* scannedCount,
    long* detectedCount,
    std::wstring* summary
) {
    if (isMalicious) {
        *isMalicious = 0;
    }
    if (scannedCount) {
        *scannedCount = 0;
    }
    if (detectedCount) {
        *detectedCount = 0;
    }
    if (summary) {
        summary->clear();
    }

    if (path.empty()) {
        if (summary) {
            *summary = L"The selected file path is empty.";
        }
        return antivirus::kRpcResultInvalidPath;
    }

    std::error_code pathError;
    const std::filesystem::path scanPath(path);
    if (!std::filesystem::exists(scanPath, pathError) ||
        !std::filesystem::is_regular_file(scanPath, pathError)) {
        if (summary) {
            *summary = L"The selected path is not a regular file.";
        }
        return antivirus::kRpcResultInvalidPath;
    }

    std::map<std::uint64_t, std::vector<antivirus::AvRecord>> databaseSnapshot;
    std::wstring readinessMessage;
    const long readinessResult = EnsureAntivirusReady(&databaseSnapshot, nullptr, &readinessMessage);
    if (readinessResult != antivirus::kRpcResultOk) {
        if (summary) {
            *summary = readinessMessage;
        }
        return readinessResult;
    }

    const antivirus::ScanResult result = antivirus::ScanFileWithDatabase(path, databaseSnapshot);
    if (summary) {
        *summary = FormatFileScanSummary(result);
    }
    if (scannedCount) {
        *scannedCount = 1;
    }

    if (!result.success) {
        return antivirus::kRpcResultScanFailed;
    }

    if (result.malicious) {
        if (isMalicious) {
            *isMalicious = 1;
        }
        if (detectedCount) {
            *detectedCount = 1;
        }
    }

    return antivirus::kRpcResultOk;
}

long ScanDirectoryInternal(
    const std::wstring& path,
    long* hasDetections,
    long* scannedCount,
    long* detectedCount,
    std::wstring* summary
) {
    if (hasDetections) {
        *hasDetections = 0;
    }
    if (scannedCount) {
        *scannedCount = 0;
    }
    if (detectedCount) {
        *detectedCount = 0;
    }
    if (summary) {
        summary->clear();
    }

    if (path.empty()) {
        if (summary) {
            *summary = L"The selected directory path is empty.";
        }
        return antivirus::kRpcResultInvalidPath;
    }

    std::map<std::uint64_t, std::vector<antivirus::AvRecord>> databaseSnapshot;
    std::wstring readinessMessage;
    const long readinessResult = EnsureAntivirusReady(&databaseSnapshot, nullptr, &readinessMessage);
    if (readinessResult != antivirus::kRpcResultOk) {
        if (summary) {
            *summary = readinessMessage;
        }
        return readinessResult;
    }

    const long result = ScanDirectoryWithDatabaseSnapshot(path, databaseSnapshot, scannedCount, detectedCount, summary);
    if (result == antivirus::kRpcResultOk && hasDetections && detectedCount) {
        *hasDetections = *detectedCount > 0 ? 1 : 0;
    }
    return result;
}

DWORD CalculateNextScheduledScanWaitMs() {
    constexpr DWORD kDefaultDelayMs = 30000;

    std::lock_guard<std::mutex> guard(g_backgroundMutex);
    if (!g_scheduledScanState.isEnabled ||
        g_scheduledScanState.intervalSeconds <= 0 ||
        g_scheduledScanState.targetPath.empty()) {
        return kDefaultDelayMs;
    }

    const auto now = std::chrono::system_clock::now();
    if (g_scheduledScanState.nextRun == std::chrono::system_clock::time_point() ||
        g_scheduledScanState.nextRun <= now) {
        return 0;
    }

    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(g_scheduledScanState.nextRun - now);
    if (remaining.count() <= 0) {
        return 0;
    }

    return static_cast<DWORD>(std::min<long long>(remaining.count(), kDefaultDelayMs));
}

void UpdateScheduledScanResult(
    long resultCode,
    const std::wstring& summary,
    const std::chrono::system_clock::time_point& completedAt
) {
    std::lock_guard<std::mutex> guard(g_backgroundMutex);
    g_scheduledScanState.lastRun = completedAt;
    g_scheduledScanState.lastResultCode = resultCode;
    g_scheduledScanState.lastSummary = summary;
    if (g_scheduledScanState.isEnabled && g_scheduledScanState.intervalSeconds > 0) {
        g_scheduledScanState.nextRun = completedAt + std::chrono::seconds(g_scheduledScanState.intervalSeconds);
    }
}

DWORD WINAPI ScheduledScanWorker(LPVOID) {
    HANDLE waitHandles[] = { g_scheduleStopEvent, g_scheduleWakeEvent };

    while (true) {
        std::wstring targetPath;
        bool shouldRun = false;
        {
            std::lock_guard<std::mutex> guard(g_backgroundMutex);
            const auto now = std::chrono::system_clock::now();
            if (g_scheduledScanState.isEnabled &&
                g_scheduledScanState.intervalSeconds > 0 &&
                !g_scheduledScanState.targetPath.empty() &&
                (g_scheduledScanState.nextRun == std::chrono::system_clock::time_point() || g_scheduledScanState.nextRun <= now)) {
                targetPath = g_scheduledScanState.targetPath;
                shouldRun = true;
            }
        }

        if (shouldRun) {
            long hasDetections = 0;
            long scannedCount = 0;
            long detectedCount = 0;
            std::wstring summary;
            const long resultCode = ScanDirectoryInternal(targetPath, &hasDetections, &scannedCount, &detectedCount, &summary);
            const auto finishedAt = std::chrono::system_clock::now();
            UpdateScheduledScanResult(resultCode, summary, finishedAt);
            continue;
        }

        const DWORD waitResult = WaitForMultipleObjects(
            static_cast<DWORD>(std::size(waitHandles)),
            waitHandles,
            FALSE,
            CalculateNextScheduledScanWaitMs()
        );

        if (waitResult == WAIT_OBJECT_0) {
            return 0;
        }

        if (waitResult == WAIT_FAILED) {
            return 1;
        }
    }
}

bool StartScheduleWorker() {
    g_scheduleStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_scheduleWakeEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!g_scheduleStopEvent || !g_scheduleWakeEvent) {
        StopScheduleWorker();
        return false;
    }

    g_scheduleWorkerThread = CreateThread(nullptr, 0, ScheduledScanWorker, nullptr, 0, nullptr);
    if (!g_scheduleWorkerThread) {
        StopScheduleWorker();
        return false;
    }

    return true;
}

void StopScheduleWorker() {
    if (g_scheduleStopEvent) {
        SetEvent(g_scheduleStopEvent);
    }

    if (g_scheduleWorkerThread) {
        WaitForSingleObject(g_scheduleWorkerThread, 5000);
        CloseHandle(g_scheduleWorkerThread);
        g_scheduleWorkerThread = nullptr;
    }

    if (g_scheduleWakeEvent) {
        CloseHandle(g_scheduleWakeEvent);
        g_scheduleWakeEvent = nullptr;
    }

    if (g_scheduleStopEvent) {
        CloseHandle(g_scheduleStopEvent);
        g_scheduleStopEvent = nullptr;
    }
}

long ConfigureScheduledScanInternal(
    bool isEnabled,
    long intervalSeconds,
    const std::wstring& targetPath,
    std::wstring* message
) {
    if (message) {
        message->clear();
    }

    if (!isEnabled) {
        std::lock_guard<std::mutex> guard(g_backgroundMutex);
        g_scheduledScanState.isEnabled = false;
        g_scheduledScanState.nextRun = {};
        if (message) {
            *message = L"Scheduled scanning is disabled.";
        }
        WakeScheduleWorker();
        return antivirus::kRpcResultOk;
    }

    if (intervalSeconds < 5) {
        if (message) {
            *message = L"Schedule interval must be at least 5 seconds.";
        }
        return antivirus::kRpcResultInvalidConfiguration;
    }

    if (targetPath.empty()) {
        if (message) {
            *message = L"A schedule target directory is required.";
        }
        return antivirus::kRpcResultInvalidConfiguration;
    }

    std::wstring normalized = NormalizeExistingDirectoryPath(targetPath);
    if (normalized.empty()) {
        if (message) {
            *message = L"The selected schedule target is not a valid directory.";
        }
        return antivirus::kRpcResultInvalidPath;
    }

    {
        std::lock_guard<std::mutex> guard(g_backgroundMutex);
        g_scheduledScanState.isEnabled = true;
        g_scheduledScanState.intervalSeconds = intervalSeconds;
        g_scheduledScanState.targetPath = normalized;
        g_scheduledScanState.nextRun = std::chrono::system_clock::now() + std::chrono::seconds(intervalSeconds);
    }

    if (message) {
        *message = L"Scheduled scanning is enabled.";
    }
    WakeScheduleWorker();
    return antivirus::kRpcResultOk;
}

long GetScheduledScanStateInternal(
    long* isEnabled,
    long* intervalSeconds,
    std::wstring* targetPath,
    std::wstring* nextRunText,
    std::wstring* lastRunText,
    long* lastResultCode,
    std::wstring* lastSummary
) {
    std::lock_guard<std::mutex> guard(g_backgroundMutex);
    if (isEnabled) {
        *isEnabled = g_scheduledScanState.isEnabled ? 1 : 0;
    }
    if (intervalSeconds) {
        *intervalSeconds = g_scheduledScanState.intervalSeconds;
    }
    if (targetPath) {
        *targetPath = g_scheduledScanState.targetPath;
    }
    if (nextRunText) {
        *nextRunText = FormatTimePoint(g_scheduledScanState.nextRun);
    }
    if (lastRunText) {
        *lastRunText = FormatTimePoint(g_scheduledScanState.lastRun);
    }
    if (lastResultCode) {
        *lastResultCode = g_scheduledScanState.lastResultCode;
    }
    if (lastSummary) {
        *lastSummary = g_scheduledScanState.lastSummary;
    }
    return antivirus::kRpcResultOk;
}

DWORD WINAPI MonitorDirectoryThread(LPVOID parameter) {
    MonitoredDirectory* monitored = static_cast<MonitoredDirectory*>(parameter);
    if (!monitored) {
        return 1;
    }

    HANDLE directoryHandle = CreateFileW(
        monitored->path.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr
    );

    if (directoryHandle == INVALID_HANDLE_VALUE) {
        AppendMonitoringEvent(L"Failed to monitor directory: " + monitored->path);
        return 1;
    }

    HANDLE changeEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!changeEvent) {
        CloseHandle(directoryHandle);
        AppendMonitoringEvent(L"Failed to create monitoring event for: " + monitored->path);
        return 1;
    }

    std::vector<BYTE> buffer(4096);

    while (WaitForSingleObject(monitored->stopEvent, 0) != WAIT_OBJECT_0) {
        OVERLAPPED overlapped = {};
        overlapped.hEvent = changeEvent;
        ResetEvent(changeEvent);

        DWORD bytesReturned = 0;
        const BOOL watchStarted = ReadDirectoryChangesW(
            directoryHandle,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytesReturned,
            &overlapped,
            nullptr
        );

        if (!watchStarted) {
            break;
        }

        HANDLE waitHandles[] = { monitored->stopEvent, changeEvent };
        const DWORD waitResult = WaitForMultipleObjects(static_cast<DWORD>(std::size(waitHandles)), waitHandles, FALSE, INFINITE);
        if (waitResult == WAIT_OBJECT_0) {
            CancelIoEx(directoryHandle, &overlapped);
            break;
        }

        if (waitResult != WAIT_OBJECT_0 + 1) {
            CancelIoEx(directoryHandle, &overlapped);
            break;
        }

        if (!GetOverlappedResult(directoryHandle, &overlapped, &bytesReturned, FALSE)) {
            continue;
        }

        BYTE* current = buffer.data();
        while (true) {
            const auto* notification = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(current);
            std::wstring name(notification->FileName, notification->FileNameLength / sizeof(WCHAR));
            std::filesystem::path fullPath = std::filesystem::path(monitored->path) / name;

            if (notification->Action == FILE_ACTION_ADDED ||
                notification->Action == FILE_ACTION_MODIFIED ||
                notification->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                std::error_code statusError;
                if (std::filesystem::is_regular_file(fullPath, statusError) && !statusError) {
                    long isMalicious = 0;
                    long scannedCount = 0;
                    long detectedCount = 0;
                    std::wstring summary;
                    const long resultCode = ScanFileInternal(fullPath.wstring(), &isMalicious, &scannedCount, &detectedCount, &summary);

                    std::wstring message = L"Monitored change: " + fullPath.wstring();
                    if (resultCode == antivirus::kRpcResultOk) {
                        message += isMalicious != 0 ? L" | Infected" : L" | Clean";
                    } else {
                        message += L" | Scan failed";
                    }
                    AppendMonitoringEvent(message);
                }
            }

            if (notification->NextEntryOffset == 0) {
                break;
            }
            current += notification->NextEntryOffset;
        }
    }

    CloseHandle(changeEvent);
    CloseHandle(directoryHandle);
    return 0;
}

long AddMonitoredDirectoryInternal(const std::wstring& path, std::wstring* message) {
    if (message) {
        message->clear();
    }

    if (path.empty()) {
        if (message) {
            *message = L"A directory path is required.";
        }
        return antivirus::kRpcResultInvalidPath;
    }

    const std::wstring normalized = NormalizeExistingDirectoryPath(path);
    if (normalized.empty()) {
        if (message) {
            *message = L"The selected directory is not valid.";
        }
        return antivirus::kRpcResultInvalidPath;
    }

    MonitoredDirectory monitored;
    monitored.path = normalized;
    monitored.stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!monitored.stopEvent) {
        if (message) {
            *message = L"Unable to create a monitoring stop event.";
        }
        return antivirus::kRpcResultUnexpectedResponse;
    }

    {
        std::lock_guard<std::mutex> guard(g_backgroundMutex);
        if (g_monitoredDirectories.find(normalized) != g_monitoredDirectories.end()) {
            CloseHandle(monitored.stopEvent);
            if (message) {
                *message = L"The directory is already being monitored.";
            }
            return antivirus::kRpcResultOk;
        }

        auto [iterator, inserted] = g_monitoredDirectories.emplace(normalized, std::move(monitored));
        iterator->second.thread = CreateThread(nullptr, 0, MonitorDirectoryThread, &iterator->second, 0, nullptr);
        if (!iterator->second.thread) {
            CloseHandle(iterator->second.stopEvent);
            g_monitoredDirectories.erase(iterator);
            if (message) {
                *message = L"Unable to start the monitoring thread.";
            }
            return antivirus::kRpcResultUnexpectedResponse;
        }

        AppendMonitoringEventLocked(L"Started monitoring: " + normalized);
    }

    if (message) {
        *message = L"Directory monitoring enabled.";
    }
    return antivirus::kRpcResultOk;
}

long RemoveMonitoredDirectoryInternal(const std::wstring& path, std::wstring* message) {
    if (message) {
        message->clear();
    }

    if (path.empty()) {
        if (message) {
            *message = L"A directory path is required.";
        }
        return antivirus::kRpcResultInvalidPath;
    }

    const std::wstring normalized = NormalizeExistingDirectoryPath(path);
    if (normalized.empty()) {
        if (message) {
            *message = L"The selected directory is not valid.";
        }
        return antivirus::kRpcResultInvalidPath;
    }

    MonitoredDirectory monitored;
    {
        std::lock_guard<std::mutex> guard(g_backgroundMutex);
        const auto iterator = g_monitoredDirectories.find(normalized);
        if (iterator == g_monitoredDirectories.end()) {
            if (message) {
                *message = L"The directory is not in the monitoring list.";
            }
            return antivirus::kRpcResultInvalidPath;
        }

        monitored = iterator->second;
        g_monitoredDirectories.erase(iterator);
        AppendMonitoringEventLocked(L"Stopped monitoring: " + normalized);
    }

    if (monitored.stopEvent) {
        SetEvent(monitored.stopEvent);
    }
    if (monitored.thread) {
        WaitForSingleObject(monitored.thread, 5000);
        CloseHandle(monitored.thread);
    }
    if (monitored.stopEvent) {
        CloseHandle(monitored.stopEvent);
    }

    if (message) {
        *message = L"Directory monitoring disabled.";
    }
    return antivirus::kRpcResultOk;
}

void StopAllMonitoring() {
    std::vector<MonitoredDirectory> monitoredDirectories;
    {
        std::lock_guard<std::mutex> guard(g_backgroundMutex);
        for (const auto& [_, monitored] : g_monitoredDirectories) {
            monitoredDirectories.push_back(monitored);
        }
        g_monitoredDirectories.clear();
    }

    for (MonitoredDirectory& monitored : monitoredDirectories) {
        if (monitored.stopEvent) {
            SetEvent(monitored.stopEvent);
        }
    }
    for (MonitoredDirectory& monitored : monitoredDirectories) {
        if (monitored.thread) {
            WaitForSingleObject(monitored.thread, 5000);
            CloseHandle(monitored.thread);
        }
        if (monitored.stopEvent) {
            CloseHandle(monitored.stopEvent);
        }
    }
}

long GetMonitoringStateInternal(std::wstring* directories, std::wstring* events) {
    std::lock_guard<std::mutex> guard(g_backgroundMutex);
    if (directories) {
        std::wostringstream directoryStream;
        if (g_monitoredDirectories.empty()) {
            directoryStream << L"No directories are being monitored.";
        } else {
            for (const auto& [path, _] : g_monitoredDirectories) {
                directoryStream << path << L"\r\n";
            }
        }
        *directories = directoryStream.str();
    }

    if (events) {
        std::wostringstream eventStream;
        if (g_monitorEventLog.empty()) {
            eventStream << L"No monitoring events yet.";
        } else {
            for (const std::wstring& event : g_monitorEventLog) {
                eventStream << event << L"\r\n";
            }
        }
        *events = eventStream.str();
    }

    return antivirus::kRpcResultOk;
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
    g_stopRequested.store(false);
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

    PreloadAvDatabaseBestEffort();

    if (!StartAuthWorker()) {
        UpdateServiceStatus(SERVICE_STOPPED, GetLastError() != NO_ERROR ? GetLastError() : ERROR_SERVICE_SPECIFIC_ERROR);
        return;
    }

    if (!StartScheduleWorker()) {
        StopAuthWorker();
        UpdateServiceStatus(SERVICE_STOPPED, GetLastError() != NO_ERROR ? GetLastError() : ERROR_SERVICE_SPECIFIC_ERROR);
        return;
    }

    const RPC_STATUS rpcStatus = StartRpcServer();
    if (rpcStatus != RPC_S_OK) {
        StopScheduleWorker();
        StopAuthWorker();
        UpdateServiceStatus(SERVICE_STOPPED, rpcStatus);
        return;
    }

    LaunchTrayApplicationsForExistingSessions();
    UpdateServiceStatus(SERVICE_RUNNING);

    const RPC_STATUS waitStatus = RpcMgmtWaitServerListen();
    const DWORD stopError = (waitStatus == RPC_S_OK || waitStatus == RPC_S_NOT_LISTENING) ? NO_ERROR : waitStatus;

    UpdateServiceStatus(SERVICE_STOP_PENDING, stopError, 5000);
    StopAllMonitoring();
    StopScheduleWorker();
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

    const long refreshResult = RefreshLicenseStateFromBackend(true);

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

extern "C" long ServiceGetAvDatabaseInfo(
    long* isLoaded,
    long* recordCount,
    long releaseDateCapacity,
    wchar_t* releaseDate,
    long messageCapacity,
    wchar_t* message
) {
    if (isLoaded) {
        *isLoaded = 0;
    }
    if (recordCount) {
        *recordCount = 0;
    }
    CopyRpcText(L"", releaseDateCapacity, releaseDate);
    CopyRpcText(L"", messageCapacity, message);

    antivirus::AvDatabaseInfo info;
    std::wstring readinessMessage;
    const long readinessResult = EnsureAntivirusReady(nullptr, &info, &readinessMessage);
    if (readinessResult != antivirus::kRpcResultOk) {
        CopyRpcText(readinessMessage, messageCapacity, message);
        return readinessResult;
    }

    if (isLoaded) {
        *isLoaded = info.isLoaded ? 1 : 0;
    }
    if (recordCount) {
        *recordCount = info.recordCount;
    }
    CopyRpcText(info.releaseDate, releaseDateCapacity, releaseDate);
    CopyRpcText(L"Antivirus bases are loaded in memory.", messageCapacity, message);
    return antivirus::kRpcResultOk;
}

extern "C" long ServiceScanFilePath(
    wchar_t* path,
    long* isMalicious,
    long* scannedCount,
    long* detectedCount,
    long summaryCapacity,
    wchar_t* summary
) {
    std::wstring textSummary;
    const long result = ScanFileInternal(
        path ? std::wstring(path) : std::wstring(),
        isMalicious,
        scannedCount,
        detectedCount,
        &textSummary
    );
    CopyRpcText(textSummary, summaryCapacity, summary);
    return result;
}

extern "C" long ServiceScanDirectoryPath(
    wchar_t* path,
    long* hasDetections,
    long* scannedCount,
    long* detectedCount,
    long summaryCapacity,
    wchar_t* summary
) {
    std::wstring textSummary;
    const long result = ScanDirectoryInternal(
        path ? std::wstring(path) : std::wstring(),
        hasDetections,
        scannedCount,
        detectedCount,
        &textSummary
    );
    CopyRpcText(textSummary, summaryCapacity, summary);
    return result;
}

extern "C" long ServiceScanFixedDrives(
    long* hasDetections,
    long* scannedCount,
    long* detectedCount,
    long summaryCapacity,
    wchar_t* summary
) {
    std::wstring textSummary;
    const long result = ScanFixedDrivesInternal(
        hasDetections,
        scannedCount,
        detectedCount,
        &textSummary
    );
    CopyRpcText(textSummary, summaryCapacity, summary);
    return result;
}

extern "C" long ServiceConfigureScheduledScan(
    long isEnabled,
    long intervalSeconds,
    wchar_t* targetPath,
    long messageCapacity,
    wchar_t* message
) {
    std::wstring textMessage;
    const long result = ConfigureScheduledScanInternal(
        isEnabled != 0,
        intervalSeconds,
        targetPath ? std::wstring(targetPath) : std::wstring(),
        &textMessage
    );
    CopyRpcText(textMessage, messageCapacity, message);
    return result;
}

extern "C" long ServiceGetScheduledScanState(
    long* isEnabled,
    long* intervalSeconds,
    long targetCapacity,
    wchar_t* targetPath,
    long nextRunCapacity,
    wchar_t* nextRunText,
    long lastRunCapacity,
    wchar_t* lastRunText,
    long* lastResultCode,
    long summaryCapacity,
    wchar_t* lastSummary
) {
    std::wstring target;
    std::wstring nextRun;
    std::wstring lastRun;
    std::wstring summary;
    const long result = GetScheduledScanStateInternal(
        isEnabled,
        intervalSeconds,
        &target,
        &nextRun,
        &lastRun,
        lastResultCode,
        &summary
    );

    CopyRpcText(target, targetCapacity, targetPath);
    CopyRpcText(nextRun, nextRunCapacity, nextRunText);
    CopyRpcText(lastRun, lastRunCapacity, lastRunText);
    CopyRpcText(summary, summaryCapacity, lastSummary);
    return result;
}

extern "C" long ServiceAddMonitoredDirectory(
    wchar_t* path,
    long messageCapacity,
    wchar_t* message
) {
    std::wstring textMessage;
    const long result = AddMonitoredDirectoryInternal(
        path ? std::wstring(path) : std::wstring(),
        &textMessage
    );
    CopyRpcText(textMessage, messageCapacity, message);
    return result;
}

extern "C" long ServiceRemoveMonitoredDirectory(
    wchar_t* path,
    long messageCapacity,
    wchar_t* message
) {
    std::wstring textMessage;
    const long result = RemoveMonitoredDirectoryInternal(
        path ? std::wstring(path) : std::wstring(),
        &textMessage
    );
    CopyRpcText(textMessage, messageCapacity, message);
    return result;
}

extern "C" long ServiceGetMonitoringState(
    long directoriesCapacity,
    wchar_t* directories,
    long eventsCapacity,
    wchar_t* events
) {
    std::wstring directoryText;
    std::wstring eventText;
    const long result = GetMonitoringStateInternal(&directoryText, &eventText);
    CopyRpcText(directoryText, directoriesCapacity, directories);
    CopyRpcText(eventText, eventsCapacity, events);
    return result;
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

        if (command == L"--db-info") {
            antivirus::RpcAvDatabaseInfo info;
            if (!GetAvDatabaseInfoViaRpc(&info)) {
                std::fwprintf(stderr, L"Unable to query antivirus database info via RPC.\n");
                return 1;
            }

            std::wprintf(L"Loaded: %ls\n", info.isLoaded ? L"yes" : L"no");
            std::wprintf(L"Record count: %ld\n", info.recordCount);
            if (!info.releaseDate.empty()) {
                std::wprintf(L"Release date: %ls\n", info.releaseDate.c_str());
            }
            if (!info.message.empty()) {
                std::wprintf(L"Message: %ls\n", info.message.c_str());
            }
            std::wprintf(L"Result code: %ld\n", info.resultCode);
            return info.resultCode == antivirus::kRpcResultOk ? 0 : 1;
        }

        if (command == L"--scan-file") {
            if (argc < 3) {
                std::fwprintf(stderr, L"Usage: antivirus_service.exe --scan-file <path>\n");
                return 1;
            }

            antivirus::RpcScanSummary summary;
            if (!ScanFileViaRpc(argv[2], &summary)) {
                std::fwprintf(stderr, L"Unable to scan file via RPC.\n");
                return 1;
            }

            if (!summary.summary.empty()) {
                std::wprintf(L"%ls\n", summary.summary.c_str());
            }
            std::wprintf(L"Scanned objects: %ld\n", summary.scannedCount);
            std::wprintf(L"Detected threats: %ld\n", summary.detectedCount);
            std::wprintf(L"Result code: %ld\n", summary.resultCode);
            return summary.resultCode == antivirus::kRpcResultOk ? 0 : 1;
        }

        if (command == L"--scan-dir") {
            if (argc < 3) {
                std::fwprintf(stderr, L"Usage: antivirus_service.exe --scan-dir <path>\n");
                return 1;
            }

            antivirus::RpcScanSummary summary;
            if (!ScanDirectoryViaRpc(argv[2], &summary)) {
                std::fwprintf(stderr, L"Unable to scan directory via RPC.\n");
                return 1;
            }

            if (!summary.summary.empty()) {
                std::wprintf(L"%ls\n", summary.summary.c_str());
            }
            std::wprintf(L"Scanned objects: %ld\n", summary.scannedCount);
            std::wprintf(L"Detected threats: %ld\n", summary.detectedCount);
            std::wprintf(L"Result code: %ld\n", summary.resultCode);
            return summary.resultCode == antivirus::kRpcResultOk ? 0 : 1;
        }

        if (command == L"--scan-fixed") {
            antivirus::RpcScanSummary summary;
            if (!ScanFixedDrivesViaRpc(&summary)) {
                std::fwprintf(stderr, L"Unable to scan fixed drives via RPC.\n");
                return 1;
            }

            if (!summary.summary.empty()) {
                std::wprintf(L"%ls\n", summary.summary.c_str());
            }
            std::wprintf(L"Scanned objects: %ld\n", summary.scannedCount);
            std::wprintf(L"Detected threats: %ld\n", summary.detectedCount);
            std::wprintf(L"Result code: %ld\n", summary.resultCode);
            return summary.resultCode == antivirus::kRpcResultOk ? 0 : 1;
        }

        if (command == L"--schedule-enable") {
            if (argc < 4) {
                std::fwprintf(stderr, L"Usage: antivirus_service.exe --schedule-enable <seconds> <directory>\n");
                return 1;
            }

            std::wstring message;
            long resultCode = antivirus::kRpcResultUnexpectedResponse;
            const long intervalSeconds = _wtol(argv[2]);
            if (!ConfigureScheduledScanViaRpc(true, intervalSeconds, argv[3], &message, &resultCode)) {
                std::fwprintf(stderr, L"Unable to configure scheduled scanning via RPC.\n");
                return 1;
            }

            if (!message.empty()) {
                std::wprintf(L"%ls\n", message.c_str());
            }
            std::wprintf(L"Result code: %ld\n", resultCode);
            return resultCode == antivirus::kRpcResultOk ? 0 : 1;
        }

        if (command == L"--schedule-disable") {
            std::wstring message;
            long resultCode = antivirus::kRpcResultUnexpectedResponse;
            if (!ConfigureScheduledScanViaRpc(false, 0, L"", &message, &resultCode)) {
                std::fwprintf(stderr, L"Unable to disable scheduled scanning via RPC.\n");
                return 1;
            }

            if (!message.empty()) {
                std::wprintf(L"%ls\n", message.c_str());
            }
            std::wprintf(L"Result code: %ld\n", resultCode);
            return resultCode == antivirus::kRpcResultOk ? 0 : 1;
        }

        if (command == L"--schedule-state") {
            antivirus::RpcScheduledScanState state;
            if (!GetScheduledScanStateViaRpc(&state)) {
                std::fwprintf(stderr, L"Unable to query scheduled scanning state via RPC.\n");
                return 1;
            }

            std::wprintf(L"Enabled: %ls\n", state.isEnabled ? L"yes" : L"no");
            std::wprintf(L"Interval (sec): %ld\n", state.intervalSeconds);
            if (!state.targetPath.empty()) {
                std::wprintf(L"Target: %ls\n", state.targetPath.c_str());
            }
            if (!state.nextRunText.empty()) {
                std::wprintf(L"Next run: %ls\n", state.nextRunText.c_str());
            }
            if (!state.lastRunText.empty()) {
                std::wprintf(L"Last run: %ls\n", state.lastRunText.c_str());
            }
            if (!state.lastSummary.empty()) {
                std::wprintf(L"Last summary:\n%ls\n", state.lastSummary.c_str());
            }
            std::wprintf(L"Last result code: %ld\n", state.lastResultCode);
            std::wprintf(L"Result code: %ld\n", state.resultCode);
            return state.resultCode == antivirus::kRpcResultOk ? 0 : 1;
        }

        if (command == L"--monitor-add") {
            if (argc < 3) {
                std::fwprintf(stderr, L"Usage: antivirus_service.exe --monitor-add <directory>\n");
                return 1;
            }

            std::wstring message;
            long resultCode = antivirus::kRpcResultUnexpectedResponse;
            if (!AddMonitoredDirectoryViaRpc(argv[2], &message, &resultCode)) {
                std::fwprintf(stderr, L"Unable to add monitored directory via RPC.\n");
                return 1;
            }

            if (!message.empty()) {
                std::wprintf(L"%ls\n", message.c_str());
            }
            std::wprintf(L"Result code: %ld\n", resultCode);
            return resultCode == antivirus::kRpcResultOk ? 0 : 1;
        }

        if (command == L"--monitor-remove") {
            if (argc < 3) {
                std::fwprintf(stderr, L"Usage: antivirus_service.exe --monitor-remove <directory>\n");
                return 1;
            }

            std::wstring message;
            long resultCode = antivirus::kRpcResultUnexpectedResponse;
            if (!RemoveMonitoredDirectoryViaRpc(argv[2], &message, &resultCode)) {
                std::fwprintf(stderr, L"Unable to remove monitored directory via RPC.\n");
                return 1;
            }

            if (!message.empty()) {
                std::wprintf(L"%ls\n", message.c_str());
            }
            std::wprintf(L"Result code: %ld\n", resultCode);
            return resultCode == antivirus::kRpcResultOk ? 0 : 1;
        }

        if (command == L"--monitor-state") {
            antivirus::RpcMonitoringState state;
            if (!GetMonitoringStateViaRpc(&state)) {
                std::fwprintf(stderr, L"Unable to query monitoring state via RPC.\n");
                return 1;
            }

            std::wprintf(L"Directories:\n%ls\n", state.directories.c_str());
            std::wprintf(L"Events:\n%ls\n", state.events.c_str());
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

