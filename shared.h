#pragma once

#include <windows.h>

namespace antivirus {

constexpr wchar_t kServiceName[] = L"AntivirusTrayService";
constexpr wchar_t kServiceDisplayName[] = L"Antivirus Tray Service";
constexpr wchar_t kServiceDescription[] = L"Starts and manages the Antivirus tray application in user sessions.";
constexpr wchar_t kTrayExecutableName[] = L"antivirus.exe";
constexpr wchar_t kRpcEndpoint[] = L"antivirus_service";
constexpr wchar_t kWindowClassName[] = L"AntivirusTrayAppClass";
constexpr wchar_t kWindowTitle[] = L"Antivirus";
constexpr wchar_t kTrayTooltip[] = L"Antivirus";
constexpr wchar_t kAppMutexName[] = L"Local\\AntivirusTrayApp";
constexpr long kRpcTextBufferChars = 16384;

constexpr long kRpcResultOk = 0;
constexpr long kRpcResultInvalidCredentials = 1;
constexpr long kRpcResultNotAuthenticated = 2;
constexpr long kRpcResultBackendUnavailable = 3;
constexpr long kRpcResultUnexpectedResponse = 4;
constexpr long kRpcResultTransportError = 5;
constexpr long kRpcResultLicenseRequired = 6;
constexpr long kRpcResultActivationFailed = 7;
constexpr long kRpcResultScanFailed = 8;
constexpr long kRpcResultInvalidPath = 9;
constexpr long kRpcResultDatabaseUnavailable = 10;
constexpr long kRpcResultInvalidConfiguration = 11;

constexpr long kLicenseStateUnknown = 0;
constexpr long kLicenseStateMissing = 1;
constexpr long kLicenseStateActive = 2;
constexpr long kLicenseStateExpired = 3;
constexpr long kLicenseStateBlocked = 4;

constexpr UINT kTrayIconMessage = WM_APP + 1;
constexpr UINT kShowMainWindowMessage = WM_APP + 2;
constexpr UINT kTrayMenuExit = 1001;
constexpr UINT kTrayMenuOpen = 1002;
constexpr UINT kFileMenuExit = 2001;

} // namespace antivirus
