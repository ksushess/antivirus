#pragma once

#include <string>

namespace antivirus {

struct RpcAuthenticationState {
    bool isAuthenticated = false;
    long resultCode = 0;
    std::wstring username;
    std::wstring message;
};

struct RpcLicenseState {
    long licenseState = 0;
    long resultCode = 0;
    std::wstring expirationDate;
    std::wstring message;
};

struct RpcAvDatabaseInfo {
    bool isLoaded = false;
    long recordCount = 0;
    long resultCode = 0;
    std::wstring releaseDate;
    std::wstring message;
};

struct RpcScanSummary {
    bool hasDetections = false;
    long scannedCount = 0;
    long detectedCount = 0;
    long resultCode = 0;
    std::wstring summary;
};

struct RpcScheduledScanState {
    bool isEnabled = false;
    long intervalSeconds = 0;
    long lastResultCode = 0;
    long resultCode = 0;
    std::wstring targetPath;
    std::wstring nextRunText;
    std::wstring lastRunText;
    std::wstring lastSummary;
};

struct RpcMonitoringState {
    long resultCode = 0;
    std::wstring directories;
    std::wstring events;
};

} // namespace antivirus

bool RequestServiceStopViaRpc();
bool GetAuthenticationStateViaRpc(antivirus::RpcAuthenticationState* state);
bool LoginUserViaRpc(
    const std::wstring& username,
    const std::wstring& password,
    antivirus::RpcAuthenticationState* state
);
bool LogoutUserViaRpc(std::wstring* message, long* resultCode);
bool GetLicenseStateViaRpc(antivirus::RpcLicenseState* state);
bool ActivateProductViaRpc(const std::wstring& activationCode, antivirus::RpcLicenseState* state);
bool GetAvDatabaseInfoViaRpc(antivirus::RpcAvDatabaseInfo* info);
bool ScanFileViaRpc(const std::wstring& path, antivirus::RpcScanSummary* summary);
bool ScanDirectoryViaRpc(const std::wstring& path, antivirus::RpcScanSummary* summary);
bool ScanFixedDrivesViaRpc(antivirus::RpcScanSummary* summary);
bool ConfigureScheduledScanViaRpc(
    bool isEnabled,
    long intervalSeconds,
    const std::wstring& targetPath,
    std::wstring* message,
    long* resultCode
);
bool GetScheduledScanStateViaRpc(antivirus::RpcScheduledScanState* state);
bool AddMonitoredDirectoryViaRpc(const std::wstring& path, std::wstring* message, long* resultCode);
bool RemoveMonitoredDirectoryViaRpc(const std::wstring& path, std::wstring* message, long* resultCode);
bool GetMonitoringStateViaRpc(antivirus::RpcMonitoringState* state);
