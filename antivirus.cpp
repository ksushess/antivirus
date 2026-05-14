#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>

#include <algorithm>
#include <vector>
#include <memory>
#include <string>

#include "rpc_client.h"
#include "shared.h"

namespace {

HINSTANCE g_instance = nullptr;
HWND g_mainWindow = nullptr;
NOTIFYICONDATAW g_trayIconData = {};
UINT g_taskbarCreatedMessage = 0;
HANDLE g_instanceMutex = nullptr;
HFONT g_uiFont = nullptr;
bool g_isRefreshingState = false;
std::wstring g_transientErrorMessage;
std::wstring g_scanSummaryText;
std::wstring g_selectedScheduleFolder;
std::wstring g_selectedScanFilePath;
bool g_scanInProgress = false;
bool g_hasCachedScheduledState = false;
bool g_hasCachedMonitoringState = false;
antivirus::RpcScheduledScanState g_cachedScheduledState;
antivirus::RpcMonitoringState g_cachedMonitoringState;

constexpr UINT_PTR kStatePollTimerId = 1;
constexpr UINT kStatePollIntervalMs = 10000;

enum class LaunchContext {
    ServiceManaged,
    ExplorerManaged,
    BackgroundManaged
};

enum class ScreenMode {
    Login,
    Activation,
    Licensed
};

enum class ScanOperation {
    File,
    Directory,
    FixedDrives
};

constexpr UINT kScanCompletedMessage = WM_APP + 10;

enum ControlId : int {
    kHeaderLabelId = 3001,
    kUsernameLabelId,
    kProtectionLabelId,
    kLicenseLabelId,
    kErrorLabelId,
    kLoginUsernameLabelId,
    kLoginUsernameEditId,
    kLoginPasswordLabelId,
    kLoginPasswordEditId,
    kLoginButtonId,
    kActivationLabelId,
    kActivationEditId,
    kActivationButtonId,
    kLogoutButtonId,
    kDatabaseLabelId,
    kScanFilePathLabelId,
    kScanFilePathEditId,
    kScanFileBrowseButtonId,
    kScanFileButtonId,
    kScanFixedDrivesButtonId,
    kScanFolderButtonId,
    kScanResultsLabelId,
    kScanResultsEditId,
    kScheduleSectionLabelId,
    kScheduleTargetLabelId,
    kSchedulePickFolderButtonId,
    kScheduleIntervalLabelId,
    kScheduleIntervalEditId,
    kScheduleEnableButtonId,
    kScheduleDisableButtonId,
    kMonitoringSectionLabelId,
    kMonitoringAddButtonId,
    kMonitoringRemoveButtonId,
    kBackgroundStatusLabelId,
    kBackgroundStatusEditId
};

struct Controls {
    HWND headerLabel = nullptr;
    HWND usernameLabel = nullptr;
    HWND protectionLabel = nullptr;
    HWND licenseLabel = nullptr;
    HWND errorLabel = nullptr;
    HWND loginUsernameLabel = nullptr;
    HWND loginUsernameEdit = nullptr;
    HWND loginPasswordLabel = nullptr;
    HWND loginPasswordEdit = nullptr;
    HWND loginButton = nullptr;
    HWND activationLabel = nullptr;
    HWND activationEdit = nullptr;
    HWND activationButton = nullptr;
    HWND logoutButton = nullptr;
    HWND databaseLabel = nullptr;
    HWND scanFilePathLabel = nullptr;
    HWND scanFilePathEdit = nullptr;
    HWND scanFileBrowseButton = nullptr;
    HWND scanFileButton = nullptr;
    HWND scanFixedDrivesButton = nullptr;
    HWND scanFolderButton = nullptr;
    HWND scanResultsLabel = nullptr;
    HWND scanResultsEdit = nullptr;
    HWND scheduleSectionLabel = nullptr;
    HWND scheduleTargetLabel = nullptr;
    HWND schedulePickFolderButton = nullptr;
    HWND scheduleIntervalLabel = nullptr;
    HWND scheduleIntervalEdit = nullptr;
    HWND scheduleEnableButton = nullptr;
    HWND scheduleDisableButton = nullptr;
    HWND monitoringSectionLabel = nullptr;
    HWND monitoringAddButton = nullptr;
    HWND monitoringRemoveButton = nullptr;
    HWND backgroundStatusLabel = nullptr;
    HWND backgroundStatusEdit = nullptr;
};

struct ScreenState {
    ScreenMode mode = ScreenMode::Login;
    std::wstring username;
    std::wstring protectionText;
    std::wstring licenseText;
    std::wstring databaseText;
    std::wstring scheduleTargetText;
    std::wstring scheduleIntervalText;
    std::wstring backgroundStatusText;
    std::wstring errorText;
    bool protectionUnlocked = false;
    bool scanAvailable = false;
};

struct ScanRequestContext {
    HWND window = nullptr;
    ScanOperation operation = ScanOperation::File;
    std::wstring path;
};

struct ScanCompletedState {
    bool rpcOk = false;
    ScanOperation operation = ScanOperation::File;
    antivirus::RpcScanSummary summary;
};

Controls g_controls;
ScreenState g_screenState;

bool IsConsoleParentExecutable(const std::wstring& executableName) {
    return !executableName.empty() && (
        lstrcmpiW(executableName.c_str(), L"cmd.exe") == 0 ||
        lstrcmpiW(executableName.c_str(), L"powershell.exe") == 0 ||
        lstrcmpiW(executableName.c_str(), L"pwsh.exe") == 0 ||
        lstrcmpiW(executableName.c_str(), L"WindowsTerminal.exe") == 0 ||
        lstrcmpiW(executableName.c_str(), L"OpenConsole.exe") == 0 ||
        lstrcmpiW(executableName.c_str(), L"conhost.exe") == 0
    );
}

DWORD GetParentProcessId() {
    const DWORD currentProcessId = GetCurrentProcessId();
    DWORD parentProcessId = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W processEntry = {};
    processEntry.dwSize = sizeof(processEntry);

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (processEntry.th32ProcessID == currentProcessId) {
                parentProcessId = processEntry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return parentProcessId;
}

std::wstring GetProcessExecutableName(DWORD processId) {
    if (processId == 0) {
        return L"";
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return L"";
    }

    PROCESSENTRY32W processEntry = {};
    processEntry.dwSize = sizeof(processEntry);
    std::wstring executableName;

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (processEntry.th32ProcessID == processId) {
                executableName = processEntry.szExeFile;
                break;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return executableName;
}

bool QueryServiceStatusProcess(SERVICE_STATUS_PROCESS* statusProcess) {
    if (!statusProcess) {
        return false;
    }

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(
        scm,
        antivirus::kServiceName,
        SERVICE_QUERY_STATUS | SERVICE_START
    );
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    DWORD bytesNeeded = 0;
    const BOOL ok = QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(statusProcess),
        sizeof(*statusProcess),
        &bytesNeeded
    );

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return ok == TRUE;
}

bool WaitForServiceState(SC_HANDLE service, DWORD desiredState, DWORD timeoutMs) {
    const DWORD startTick = GetTickCount();

    while (true) {
        SERVICE_STATUS_PROCESS statusProcess = {};
        DWORD bytesNeeded = 0;
        if (!QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&statusProcess),
                sizeof(statusProcess),
                &bytesNeeded)) {
            return false;
        }

        if (statusProcess.dwCurrentState == desiredState) {
            return true;
        }

        if (statusProcess.dwCurrentState == SERVICE_STOPPED && desiredState != SERVICE_STOPPED) {
            return false;
        }

        if (GetTickCount() - startTick >= timeoutMs) {
            return false;
        }

        Sleep(250);
    }
}

bool EnsureServiceRunning() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(
        scm,
        antivirus::kServiceName,
        SERVICE_QUERY_STATUS | SERVICE_START
    );
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS statusProcess = {};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&statusProcess),
            sizeof(statusProcess),
            &bytesNeeded)) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }

    bool result = false;
    if (statusProcess.dwCurrentState == SERVICE_RUNNING) {
        result = true;
    } else if (statusProcess.dwCurrentState == SERVICE_STOPPED) {
        if (StartServiceW(service, 0, nullptr)) {
            result = WaitForServiceState(service, SERVICE_RUNNING, 15000);
        }
    } else if (statusProcess.dwCurrentState == SERVICE_START_PENDING) {
        result = WaitForServiceState(service, SERVICE_RUNNING, 15000);
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return result;
}

bool IsParentServiceProcess() {
    SERVICE_STATUS_PROCESS statusProcess = {};
    if (!QueryServiceStatusProcess(&statusProcess)) {
        return false;
    }

    if (statusProcess.dwCurrentState != SERVICE_RUNNING || statusProcess.dwProcessId == 0) {
        return false;
    }

    return GetParentProcessId() == statusProcess.dwProcessId;
}

LaunchContext DetectLaunchContext() {
    if (IsParentServiceProcess()) {
        return LaunchContext::ServiceManaged;
    }

    const std::wstring parentExecutable = GetProcessExecutableName(GetParentProcessId());
    if (GetConsoleWindow() != nullptr || IsConsoleParentExecutable(parentExecutable)) {
        return LaunchContext::BackgroundManaged;
    }

    return LaunchContext::ExplorerManaged;
}

void AddTrayIcon(HWND window) {
    ZeroMemory(&g_trayIconData, sizeof(g_trayIconData));
    g_trayIconData.cbSize = sizeof(g_trayIconData);
    g_trayIconData.hWnd = window;
    g_trayIconData.uID = 1;
    g_trayIconData.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_trayIconData.uCallbackMessage = antivirus::kTrayIconMessage;
    g_trayIconData.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcscpy_s(g_trayIconData.szTip, antivirus::kTrayTooltip);

    Shell_NotifyIconW(NIM_ADD, &g_trayIconData);
}

void RemoveTrayIcon() {
    if (g_trayIconData.hWnd) {
        Shell_NotifyIconW(NIM_DELETE, &g_trayIconData);
    }
}

void ShowMainWindow() {
    if (!g_mainWindow) {
        return;
    }

    if (IsIconic(g_mainWindow)) {
        ShowWindow(g_mainWindow, SW_RESTORE);
    }

    ShowWindow(g_mainWindow, SW_SHOWNORMAL);
    SetForegroundWindow(g_mainWindow);
}

void HideMainWindow() {
    if (g_mainWindow) {
        ShowWindow(g_mainWindow, SW_HIDE);
    }
}

void RequestServiceStopFromUi(HWND owner) {
    if (!RequestServiceStopViaRpc()) {
        MessageBoxW(
            owner,
            L"\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u043E\u0441\u0442\u0430\u043D\u043E\u0432\u0438\u0442\u044C Windows-\u0441\u043B\u0443\u0436\u0431\u0443.",
            antivirus::kWindowTitle,
            MB_OK | MB_ICONERROR
        );
    }
}

HWND WaitForMainWindow(DWORD timeoutMs) {
    const DWORD startTick = GetTickCount();

    while (true) {
        HWND window = FindWindowW(antivirus::kWindowClassName, nullptr);
        if (window) {
            return window;
        }

        if (GetTickCount() - startTick >= timeoutMs) {
            return nullptr;
        }

        Sleep(100);
    }
}

void RequestExistingInstanceToShowWindow() {
    HWND window = WaitForMainWindow(15000);
    if (!window) {
        return;
    }

    DWORD_PTR result = 0;
    SendMessageTimeoutW(
        window,
        antivirus::kShowMainWindowMessage,
        0,
        0,
        SMTO_ABORTIFHUNG,
        2000,
        &result
    );
}

void ShowContextMenu(HWND window) {
    HMENU menu = CreatePopupMenu();
    if (!menu) {
        return;
    }

    AppendMenuW(menu, MF_STRING, antivirus::kTrayMenuOpen, L"\u041E\u0442\u043A\u0440\u044B\u0442\u044C");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, antivirus::kTrayMenuExit, L"\u0412\u044B\u0445\u043E\u0434");

    POINT cursor = {};
    GetCursorPos(&cursor);

    SetForegroundWindow(window);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, cursor.x, cursor.y, 0, window, nullptr);
    PostMessageW(window, WM_NULL, 0, 0);

    DestroyMenu(menu);
}

HMENU CreateMainMenu() {
    HMENU menuBar = CreateMenu();
    HMENU fileMenu = CreatePopupMenu();

    AppendMenuW(fileMenu, MF_STRING, antivirus::kFileMenuExit, L"\u0412\u044B\u0445\u043E\u0434");
    AppendMenuW(menuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"\u0424\u0430\u0439\u043B");

    return menuBar;
}

void SetControlFont(HWND control) {
    if (control && g_uiFont) {
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_uiFont), TRUE);
    }
}

HWND CreateUiControl(
    HWND parent,
    const wchar_t* className,
    const wchar_t* text,
    DWORD style,
    int controlId
) {
    HWND control = CreateWindowExW(
        0,
        className,
        text,
        WS_CHILD | style,
        0,
        0,
        0,
        0,
        parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(controlId)),
        g_instance,
        nullptr
    );
    SetControlFont(control);
    return control;
}

void CreateChildControls(HWND window) {
    g_uiFont = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

    g_controls.headerLabel = CreateUiControl(window, L"STATIC", L"Antivirus Console", WS_VISIBLE, kHeaderLabelId);
    g_controls.usernameLabel = CreateUiControl(window, L"STATIC", L"", WS_VISIBLE, kUsernameLabelId);
    g_controls.protectionLabel = CreateUiControl(window, L"STATIC", L"", WS_VISIBLE, kProtectionLabelId);
    g_controls.licenseLabel = CreateUiControl(window, L"STATIC", L"", WS_VISIBLE, kLicenseLabelId);
    g_controls.databaseLabel = CreateUiControl(window, L"STATIC", L"", WS_VISIBLE, kDatabaseLabelId);
    g_controls.errorLabel = CreateUiControl(window, L"STATIC", L"", WS_VISIBLE, kErrorLabelId);

    g_controls.loginUsernameLabel = CreateUiControl(window, L"STATIC", L"Username", WS_VISIBLE, kLoginUsernameLabelId);
    g_controls.loginUsernameEdit = CreateUiControl(window, L"EDIT", L"", WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, kLoginUsernameEditId);
    g_controls.loginPasswordLabel = CreateUiControl(window, L"STATIC", L"Password", WS_VISIBLE, kLoginPasswordLabelId);
    g_controls.loginPasswordEdit = CreateUiControl(window, L"EDIT", L"", WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD | WS_TABSTOP, kLoginPasswordEditId);
    g_controls.loginButton = CreateUiControl(window, L"BUTTON", L"Sign In", WS_VISIBLE | WS_TABSTOP, kLoginButtonId);

    g_controls.activationLabel = CreateUiControl(window, L"STATIC", L"Activation Code", WS_VISIBLE, kActivationLabelId);
    g_controls.activationEdit = CreateUiControl(window, L"EDIT", L"", WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, kActivationEditId);
    g_controls.activationButton = CreateUiControl(window, L"BUTTON", L"Activate", WS_VISIBLE | WS_TABSTOP, kActivationButtonId);
    g_controls.logoutButton = CreateUiControl(window, L"BUTTON", L"Log Out", WS_VISIBLE | WS_TABSTOP, kLogoutButtonId);
    g_controls.scanFilePathLabel = CreateUiControl(window, L"STATIC", L"File path", WS_VISIBLE, kScanFilePathLabelId);
    g_controls.scanFilePathEdit = CreateUiControl(window, L"EDIT", L"", WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, kScanFilePathEditId);
    g_controls.scanFileBrowseButton = CreateUiControl(window, L"BUTTON", L"Browse", WS_VISIBLE | WS_TABSTOP, kScanFileBrowseButtonId);
    g_controls.scanFileButton = CreateUiControl(window, L"BUTTON", L"Scan File", WS_VISIBLE | WS_TABSTOP, kScanFileButtonId);
    g_controls.scanFixedDrivesButton = CreateUiControl(window, L"BUTTON", L"Scan Fixed Drives", WS_VISIBLE | WS_TABSTOP, kScanFixedDrivesButtonId);
    g_controls.scanFolderButton = CreateUiControl(window, L"BUTTON", L"Scan Folder", WS_VISIBLE | WS_TABSTOP, kScanFolderButtonId);
    g_controls.scanResultsLabel = CreateUiControl(window, L"STATIC", L"Scan Results", WS_VISIBLE, kScanResultsLabelId);
    g_controls.scanResultsEdit = CreateUiControl(
        window,
        L"EDIT",
        L"",
        WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL | WS_TABSTOP,
        kScanResultsEditId
    );
    g_controls.scheduleSectionLabel = CreateUiControl(window, L"STATIC", L"Automation", WS_VISIBLE, kScheduleSectionLabelId);
    g_controls.scheduleTargetLabel = CreateUiControl(window, L"STATIC", L"Target folder: not selected", WS_VISIBLE, kScheduleTargetLabelId);
    g_controls.schedulePickFolderButton = CreateUiControl(window, L"BUTTON", L"Choose", WS_VISIBLE | WS_TABSTOP, kSchedulePickFolderButtonId);
    g_controls.scheduleIntervalLabel = CreateUiControl(window, L"STATIC", L"Every (sec)", WS_VISIBLE, kScheduleIntervalLabelId);
    g_controls.scheduleIntervalEdit = CreateUiControl(window, L"EDIT", L"30", WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, kScheduleIntervalEditId);
    g_controls.scheduleEnableButton = CreateUiControl(window, L"BUTTON", L"Enable", WS_VISIBLE | WS_TABSTOP, kScheduleEnableButtonId);
    g_controls.scheduleDisableButton = CreateUiControl(window, L"BUTTON", L"Disable", WS_VISIBLE | WS_TABSTOP, kScheduleDisableButtonId);
    g_controls.monitoringSectionLabel = CreateUiControl(window, L"STATIC", L"Monitoring", WS_VISIBLE, kMonitoringSectionLabelId);
    g_controls.monitoringAddButton = CreateUiControl(window, L"BUTTON", L"Add Folder", WS_VISIBLE | WS_TABSTOP, kMonitoringAddButtonId);
    g_controls.monitoringRemoveButton = CreateUiControl(window, L"BUTTON", L"Remove Folder", WS_VISIBLE | WS_TABSTOP, kMonitoringRemoveButtonId);
    g_controls.backgroundStatusLabel = CreateUiControl(window, L"STATIC", L"Automation Status", WS_VISIBLE, kBackgroundStatusLabelId);
    g_controls.backgroundStatusEdit = CreateUiControl(
        window,
        L"EDIT",
        L"",
        WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL | WS_TABSTOP,
        kBackgroundStatusEditId
    );
}

void LayoutControls(HWND window) {
    RECT clientRect = {};
    GetClientRect(window, &clientRect);

    const int left = 20;
    const int top = 20;
    const int contentWidth = clientRect.right - clientRect.left - 40;
    const int labelColumnWidth = 110;
    const int fieldLeft = left + labelColumnWidth + 10;
    const int fieldWidth = std::max(120, contentWidth - labelColumnWidth - 10);
    const int fullWidth = std::max(120, contentWidth);
    const int scanPathTop = top + 260;
    const int buttonTop = top + 296;
    const int resultsTop = top + 340;
    const int clientHeight = static_cast<int>(clientRect.bottom - clientRect.top);
    const int resultsHeight = 120;
    const int scheduleTop = resultsTop + 24 + resultsHeight + 12;
    const int monitoringTop = scheduleTop + 74;
    const int backgroundTop = monitoringTop + 54;
    const int backgroundHeight = std::max(100, clientHeight - backgroundTop - 64);

    MoveWindow(g_controls.headerLabel, left, top, fullWidth, 24, TRUE);
    MoveWindow(g_controls.usernameLabel, left, top + 34, fullWidth, 20, TRUE);
    MoveWindow(g_controls.protectionLabel, left, top + 58, fullWidth, 20, TRUE);
    MoveWindow(g_controls.licenseLabel, left, top + 82, fullWidth, 20, TRUE);
    MoveWindow(g_controls.databaseLabel, left, top + 106, fullWidth, 20, TRUE);
    MoveWindow(g_controls.errorLabel, left, top + 134, fullWidth, 42, TRUE);

    MoveWindow(g_controls.loginUsernameLabel, left, top + 186, labelColumnWidth, 20, TRUE);
    MoveWindow(g_controls.loginUsernameEdit, fieldLeft, top + 182, fieldWidth, 24, TRUE);
    MoveWindow(g_controls.loginPasswordLabel, left, top + 220, labelColumnWidth, 20, TRUE);
    MoveWindow(g_controls.loginPasswordEdit, fieldLeft, top + 216, fieldWidth, 24, TRUE);
    MoveWindow(g_controls.loginButton, fieldLeft, top + 252, 120, 28, TRUE);

    MoveWindow(g_controls.activationLabel, left, top + 186, labelColumnWidth, 20, TRUE);
    MoveWindow(g_controls.activationEdit, fieldLeft, top + 182, fieldWidth, 24, TRUE);
    MoveWindow(g_controls.activationButton, fieldLeft, top + 218, 120, 28, TRUE);

    MoveWindow(g_controls.scanFilePathLabel, left, scanPathTop + 4, 70, 20, TRUE);
    MoveWindow(g_controls.scanFilePathEdit, left + 74, scanPathTop, fullWidth - 170, 24, TRUE);
    MoveWindow(g_controls.scanFileBrowseButton, clientRect.right - 90, scanPathTop - 2, 70, 28, TRUE);
    MoveWindow(g_controls.scanFileButton, left, buttonTop, 140, 30, TRUE);
    MoveWindow(g_controls.scanFixedDrivesButton, left + 150, buttonTop, 160, 30, TRUE);
    MoveWindow(g_controls.scanFolderButton, left + 320, buttonTop, 140, 30, TRUE);
    MoveWindow(g_controls.scanResultsLabel, left, resultsTop, fullWidth, 20, TRUE);
    MoveWindow(g_controls.scanResultsEdit, left, resultsTop + 24, fullWidth, resultsHeight, TRUE);

    MoveWindow(g_controls.scheduleSectionLabel, left, scheduleTop, fullWidth, 20, TRUE);
    MoveWindow(g_controls.scheduleTargetLabel, left, scheduleTop + 24, fullWidth - 100, 20, TRUE);
    MoveWindow(g_controls.schedulePickFolderButton, clientRect.right - 110, scheduleTop + 20, 90, 28, TRUE);
    MoveWindow(g_controls.scheduleIntervalLabel, left, scheduleTop + 48, 82, 20, TRUE);
    MoveWindow(g_controls.scheduleIntervalEdit, left + 88, scheduleTop + 46, 56, 24, TRUE);
    MoveWindow(g_controls.scheduleEnableButton, left + 160, scheduleTop + 44, 92, 28, TRUE);
    MoveWindow(g_controls.scheduleDisableButton, left + 260, scheduleTop + 44, 92, 28, TRUE);

    MoveWindow(g_controls.monitoringSectionLabel, left, monitoringTop, fullWidth, 20, TRUE);
    MoveWindow(g_controls.monitoringAddButton, left, monitoringTop + 22, 120, 28, TRUE);
    MoveWindow(g_controls.monitoringRemoveButton, left + 130, monitoringTop + 22, 130, 28, TRUE);

    MoveWindow(g_controls.backgroundStatusLabel, left, backgroundTop, fullWidth, 20, TRUE);
    MoveWindow(g_controls.backgroundStatusEdit, left, backgroundTop + 24, fullWidth, backgroundHeight, TRUE);

    MoveWindow(g_controls.logoutButton, clientRect.right - 160, clientRect.bottom - 60, 140, 30, TRUE);
}

void SetControlVisible(HWND control, bool visible) {
    if (control) {
        ShowWindow(control, visible ? SW_SHOW : SW_HIDE);
    }
}

void SetControlEnabled(HWND control, bool enabled) {
    if (control) {
        EnableWindow(control, enabled ? TRUE : FALSE);
    }
}

std::wstring GetEditText(HWND control) {
    if (!control) {
        return L"";
    }

    const int length = GetWindowTextLengthW(control);
    std::wstring value(static_cast<size_t>(length) + 1, L'\0');
    GetWindowTextW(control, value.data(), length + 1);
    value.resize(static_cast<size_t>(length));
    return value;
}

std::wstring ShowOpenFileDialog(HWND owner) {
    wchar_t filePath[MAX_PATH] = {};
    OPENFILENAMEW dialog = {};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = owner;
    dialog.lpstrFile = filePath;
    dialog.nMaxFile = static_cast<DWORD>(std::size(filePath));
    dialog.lpstrFilter = L"All Files\0*.*\0\0";
    dialog.nFilterIndex = 1;
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;

    return GetOpenFileNameW(&dialog) ? std::wstring(filePath) : L"";
}

std::wstring ShowFolderDialog(HWND owner) {
    BROWSEINFOW browseInfo = {};
    browseInfo.hwndOwner = owner;
    browseInfo.lpszTitle = L"Select a folder to scan";
    browseInfo.ulFlags = BIF_RETURNONLYFSDIRS | BIF_USENEWUI;

    PIDLIST_ABSOLUTE itemId = SHBrowseForFolderW(&browseInfo);
    if (!itemId) {
        return L"";
    }

    wchar_t folderPath[MAX_PATH] = {};
    std::wstring result;
    if (SHGetPathFromIDListW(itemId, folderPath)) {
        result = folderPath;
    }

    CoTaskMemFree(itemId);
    return result;
}

bool IsDefaultUnauthenticatedMessage(const std::wstring& message) {
    return message.empty() || message == L"User is not authenticated.";
}

std::wstring BuildProtectionText(long licenseState) {
    switch (licenseState) {
    case antivirus::kLicenseStateExpired:
        return L"Protection is blocked. The license has expired.";
    case antivirus::kLicenseStateBlocked:
        return L"Protection is blocked. The license is blocked on the server.";
    case antivirus::kLicenseStateMissing:
    default:
        return L"Protection is blocked. An activation code is required.";
    }
}

std::wstring BuildBackgroundStatusText(
    const antivirus::RpcScheduledScanState& scheduledState,
    const antivirus::RpcMonitoringState& monitoringState
) {
    const auto splitLines = [](const std::wstring& text) {
        std::vector<std::wstring> lines;
        std::wstring current;
        for (wchar_t character : text) {
            if (character == L'\r') {
                continue;
            }
            if (character == L'\n') {
                if (!current.empty()) {
                    lines.push_back(current);
                    current.clear();
                }
                continue;
            }
            current += character;
        }
        if (!current.empty()) {
            lines.push_back(current);
        }
        return lines;
    };

    std::wstring targetPath = scheduledState.targetPath.empty()
        ? (g_selectedScheduleFolder.empty() ? L"not selected" : g_selectedScheduleFolder)
        : scheduledState.targetPath;

    std::wstring text = L"Schedule: ";
    text += scheduledState.isEnabled ? L"enabled\r\n" : L"disabled\r\n";
    text += L"Folder: " + targetPath + L"\r\n";
    text += L"Interval: " + std::to_wstring(scheduledState.intervalSeconds) + L" sec\r\n";
    if (!scheduledState.nextRunText.empty()) {
        text += L"Next: " + scheduledState.nextRunText + L"\r\n";
    }
    if (!scheduledState.lastRunText.empty()) {
        text += L"Last: " + scheduledState.lastRunText + L"\r\n";
    }
    if (!scheduledState.lastSummary.empty()) {
        text += L"Last result:\r\n" + scheduledState.lastSummary + L"\r\n";
    }

    const std::vector<std::wstring> directories = splitLines(monitoringState.directories);
    const std::vector<std::wstring> events = splitLines(monitoringState.events);

    text += L"\r\nMonitors: " + std::to_wstring(directories.size()) + L"\r\n";
    if (!directories.empty()) {
        const size_t directoriesToShow = std::min<size_t>(directories.size(), 2);
        for (size_t index = 0; index < directoriesToShow; ++index) {
            text += L"- " + directories[index] + L"\r\n";
        }
        if (directories.size() > directoriesToShow) {
            text += L"...\r\n";
        }
    } else {
        text += L"No monitored folders\r\n";
    }

    text += L"\r\nRecent events\r\n";
    if (!events.empty()) {
        const size_t firstEvent = events.size() > 3 ? events.size() - 3 : 0;
        for (size_t index = firstEvent; index < events.size(); ++index) {
            text += events[index] + L"\r\n";
        }
    } else {
        text += L"No monitoring events yet.";
    }

    return text;
}

ScreenState QueryScreenState() {
    ScreenState state;
    state.mode = ScreenMode::Login;
    state.protectionText = L"Protection is blocked until you sign in.";
    state.scheduleTargetText = g_selectedScheduleFolder.empty()
        ? L"Target folder: not selected"
        : L"Target folder: " + g_selectedScheduleFolder;
    state.scheduleIntervalText = L"30";

    antivirus::RpcAuthenticationState authState;
    if (!GetAuthenticationStateViaRpc(&authState)) {
        if (g_screenState.mode != ScreenMode::Login) {
            state = g_screenState;
        }
        state.errorText = !g_transientErrorMessage.empty()
            ? g_transientErrorMessage
            : L"Unable to contact the antivirus service.";
        return state;
    }

    if (authState.resultCode != antivirus::kRpcResultOk || !authState.isAuthenticated) {
        if (!g_transientErrorMessage.empty()) {
            state.errorText = g_transientErrorMessage;
        } else if (!IsDefaultUnauthenticatedMessage(authState.message)) {
            state.errorText = authState.message;
        }
        return state;
    }

    state.username = authState.username;

    antivirus::RpcLicenseState licenseState;
    if (!GetLicenseStateViaRpc(&licenseState)) {
        if (g_screenState.mode == ScreenMode::Licensed || g_screenState.mode == ScreenMode::Activation) {
            state = g_screenState;
        } else {
            state.mode = ScreenMode::Activation;
            state.protectionText = L"Protection is blocked until the license state can be loaded.";
        }
        state.errorText = !g_transientErrorMessage.empty()
            ? g_transientErrorMessage
            : L"Unable to contact the antivirus service.";
        return state;
    }

    if (licenseState.resultCode == antivirus::kRpcResultNotAuthenticated) {
        state.mode = ScreenMode::Login;
        state.username.clear();
        state.protectionText = L"Protection is blocked until you sign in.";
        state.errorText = !g_transientErrorMessage.empty()
            ? g_transientErrorMessage
            : licenseState.message;
        return state;
    }

    if (licenseState.licenseState == antivirus::kLicenseStateActive) {
        state.mode = ScreenMode::Licensed;
        state.protectionUnlocked = true;
        state.protectionText = L"Protection is active.";
        state.licenseText = L"License valid until: " + licenseState.expirationDate;

        antivirus::RpcAvDatabaseInfo databaseInfo;
        if (!GetAvDatabaseInfoViaRpc(&databaseInfo)) {
            if (g_screenState.mode == ScreenMode::Licensed) {
                state.databaseText = g_screenState.databaseText;
                state.backgroundStatusText = g_screenState.backgroundStatusText;
                state.scanAvailable = g_screenState.scanAvailable;
            } else {
                state.scanAvailable = false;
                state.databaseText = L"Antivirus bases: unavailable";
            }
            state.errorText = !g_transientErrorMessage.empty()
                ? g_transientErrorMessage
                : L"Unable to load antivirus database information.";
            return state;
        }

        if (databaseInfo.resultCode == antivirus::kRpcResultOk && databaseInfo.isLoaded) {
            state.scanAvailable = true;
            state.databaseText = L"Database release date: " + databaseInfo.releaseDate +
                L" | Records: " + std::to_wstring(databaseInfo.recordCount);

            antivirus::RpcScheduledScanState scheduledState;
            antivirus::RpcMonitoringState monitoringState;
            const bool hasScheduledState = GetScheduledScanStateViaRpc(&scheduledState);
            const bool hasMonitoringState = GetMonitoringStateViaRpc(&monitoringState);

            if (hasScheduledState && !scheduledState.targetPath.empty()) {
                g_selectedScheduleFolder = scheduledState.targetPath;
            }
            if (hasScheduledState) {
                g_cachedScheduledState = scheduledState;
                g_hasCachedScheduledState = true;
            }
            if (hasMonitoringState) {
                g_cachedMonitoringState = monitoringState;
                g_hasCachedMonitoringState = true;
            }

            state.scheduleTargetText = g_selectedScheduleFolder.empty()
                ? L"Target folder: not selected"
                : L"Target folder: " + g_selectedScheduleFolder;
            const antivirus::RpcScheduledScanState* scheduledForUi = hasScheduledState
                ? &scheduledState
                : (g_hasCachedScheduledState ? &g_cachedScheduledState : nullptr);
            const antivirus::RpcMonitoringState* monitoringForUi = hasMonitoringState
                ? &monitoringState
                : (g_hasCachedMonitoringState ? &g_cachedMonitoringState : nullptr);

            state.scheduleIntervalText = scheduledForUi && scheduledForUi->intervalSeconds > 0
                ? std::to_wstring(scheduledForUi->intervalSeconds)
                : L"30";

            if (scheduledForUi && monitoringForUi) {
                state.backgroundStatusText = BuildBackgroundStatusText(*scheduledForUi, *monitoringForUi);
            } else {
                state.backgroundStatusText = g_screenState.backgroundStatusText.empty()
                    ? L"Automation status will appear after the first successful update."
                    : g_screenState.backgroundStatusText;
            }
        } else {
            state.scanAvailable = false;
            state.databaseText = L"Antivirus bases: unavailable";
            state.protectionText = L"Protection is limited until antivirus bases are loaded.";
            if (!databaseInfo.message.empty()) {
                state.errorText = databaseInfo.message;
            }
            state.scheduleTargetText = L"Target folder: not selected";
            state.scheduleIntervalText = L"30";
        }

        if (!g_transientErrorMessage.empty()) {
            state.errorText = g_transientErrorMessage;
        }
        return state;
    }

    state.mode = ScreenMode::Activation;
    state.protectionText = BuildProtectionText(licenseState.licenseState);
    state.licenseText = L"Enter an activation code to unlock protection.";
    state.scheduleTargetText = g_selectedScheduleFolder.empty()
        ? L"Target folder: not selected"
        : L"Target folder: " + g_selectedScheduleFolder;
    state.scheduleIntervalText = L"30";

    if (!g_transientErrorMessage.empty()) {
        state.errorText = g_transientErrorMessage;
    } else if (licenseState.resultCode != antivirus::kRpcResultLicenseRequired &&
               licenseState.resultCode != antivirus::kRpcResultOk &&
               !licenseState.message.empty()) {
        state.errorText = licenseState.message;
    }

    return state;
}

void ApplyScreenState() {
    SetWindowTextW(g_controls.headerLabel, L"Antivirus Console");

    if (g_screenState.username.empty()) {
        SetWindowTextW(g_controls.usernameLabel, L"User: not signed in");
    } else {
        std::wstring userText = L"User: " + g_screenState.username;
        SetWindowTextW(g_controls.usernameLabel, userText.c_str());
    }

    SetWindowTextW(g_controls.protectionLabel, g_screenState.protectionText.c_str());
    SetWindowTextW(g_controls.licenseLabel, g_screenState.licenseText.c_str());
    SetWindowTextW(g_controls.databaseLabel, g_screenState.databaseText.c_str());
    SetWindowTextW(g_controls.errorLabel, g_screenState.errorText.c_str());
    SetWindowTextW(g_controls.scanResultsEdit, g_scanSummaryText.c_str());
    if (GetFocus() != g_controls.scanFilePathEdit) {
        const std::wstring currentPathText = GetEditText(g_controls.scanFilePathEdit);
        if (currentPathText != g_selectedScanFilePath) {
            SetWindowTextW(g_controls.scanFilePathEdit, g_selectedScanFilePath.c_str());
        }
    }
    SetWindowTextW(g_controls.scheduleTargetLabel, g_screenState.scheduleTargetText.c_str());
    if (GetFocus() != g_controls.scheduleIntervalEdit) {
        const std::wstring currentIntervalText = GetEditText(g_controls.scheduleIntervalEdit);
        if (currentIntervalText != g_screenState.scheduleIntervalText) {
            SetWindowTextW(g_controls.scheduleIntervalEdit, g_screenState.scheduleIntervalText.c_str());
        }
    }
    SetWindowTextW(g_controls.backgroundStatusEdit, g_screenState.backgroundStatusText.c_str());

    const bool showLogin = g_screenState.mode == ScreenMode::Login;
    const bool showActivation = g_screenState.mode == ScreenMode::Activation;
    const bool showLogout = g_screenState.mode != ScreenMode::Login;
    const bool showScanControls = g_screenState.mode == ScreenMode::Licensed;

    SetControlVisible(g_controls.loginUsernameLabel, showLogin);
    SetControlVisible(g_controls.loginUsernameEdit, showLogin);
    SetControlVisible(g_controls.loginPasswordLabel, showLogin);
    SetControlVisible(g_controls.loginPasswordEdit, showLogin);
    SetControlVisible(g_controls.loginButton, showLogin);

    SetControlVisible(g_controls.activationLabel, showActivation);
    SetControlVisible(g_controls.activationEdit, showActivation);
    SetControlVisible(g_controls.activationButton, showActivation);
    SetControlVisible(g_controls.logoutButton, showLogout);
    SetControlVisible(g_controls.databaseLabel, !g_screenState.databaseText.empty());
    SetControlVisible(g_controls.scanFilePathLabel, showScanControls);
    SetControlVisible(g_controls.scanFilePathEdit, showScanControls);
    SetControlVisible(g_controls.scanFileBrowseButton, showScanControls);
    SetControlVisible(g_controls.scanFileButton, showScanControls);
    SetControlVisible(g_controls.scanFixedDrivesButton, showScanControls);
    SetControlVisible(g_controls.scanFolderButton, showScanControls);
    SetControlVisible(g_controls.scanResultsLabel, showScanControls);
    SetControlVisible(g_controls.scanResultsEdit, showScanControls);
    SetControlVisible(g_controls.scheduleSectionLabel, showScanControls);
    SetControlVisible(g_controls.scheduleTargetLabel, showScanControls);
    SetControlVisible(g_controls.schedulePickFolderButton, showScanControls);
    SetControlVisible(g_controls.scheduleIntervalLabel, showScanControls);
    SetControlVisible(g_controls.scheduleIntervalEdit, showScanControls);
    SetControlVisible(g_controls.scheduleEnableButton, showScanControls);
    SetControlVisible(g_controls.scheduleDisableButton, showScanControls);
    SetControlVisible(g_controls.monitoringSectionLabel, showScanControls);
    SetControlVisible(g_controls.monitoringAddButton, showScanControls);
    SetControlVisible(g_controls.monitoringRemoveButton, showScanControls);
    SetControlVisible(g_controls.backgroundStatusLabel, showScanControls);
    SetControlVisible(g_controls.backgroundStatusEdit, showScanControls);

    SetControlVisible(g_controls.errorLabel, !g_screenState.errorText.empty());
    SetControlVisible(g_controls.licenseLabel, !g_screenState.licenseText.empty());
    SetControlEnabled(g_controls.scanFilePathEdit, g_screenState.scanAvailable && !g_scanInProgress);
    SetControlEnabled(g_controls.scanFileBrowseButton, g_screenState.scanAvailable && !g_scanInProgress);
    SetControlEnabled(g_controls.scanFileButton, g_screenState.scanAvailable && !g_scanInProgress);
    SetControlEnabled(g_controls.scanFixedDrivesButton, g_screenState.scanAvailable && !g_scanInProgress);
    SetControlEnabled(g_controls.scanFolderButton, g_screenState.scanAvailable && !g_scanInProgress);
    SetControlEnabled(g_controls.schedulePickFolderButton, g_screenState.scanAvailable);
    SetControlEnabled(g_controls.scheduleIntervalEdit, g_screenState.scanAvailable);
    SetControlEnabled(g_controls.scheduleEnableButton, g_screenState.scanAvailable);
    SetControlEnabled(g_controls.scheduleDisableButton, g_screenState.scanAvailable);
    SetControlEnabled(g_controls.monitoringAddButton, g_screenState.scanAvailable);
    SetControlEnabled(g_controls.monitoringRemoveButton, g_screenState.scanAvailable);
}

void RefreshUiState() {
    if (g_isRefreshingState) {
        return;
    }

    g_isRefreshingState = true;
    const ScreenMode previousMode = g_screenState.mode;
    g_screenState = QueryScreenState();
    if (g_screenState.mode != ScreenMode::Licensed && previousMode == ScreenMode::Licensed) {
        g_scanSummaryText.clear();
    }
    ApplyScreenState();
    g_isRefreshingState = false;
}

void ClearTransientErrorOnSuccess() {
    g_transientErrorMessage.clear();
}

DWORD WINAPI ScanWorkerThread(LPVOID parameter) {
    std::unique_ptr<ScanRequestContext> request(static_cast<ScanRequestContext*>(parameter));
    std::unique_ptr<ScanCompletedState> completed = std::make_unique<ScanCompletedState>();
    completed->operation = request->operation;

    switch (request->operation) {
    case ScanOperation::File:
        completed->rpcOk = ScanFileViaRpc(request->path, &completed->summary);
        break;
    case ScanOperation::Directory:
        completed->rpcOk = ScanDirectoryViaRpc(request->path, &completed->summary);
        break;
    case ScanOperation::FixedDrives:
        completed->rpcOk = ScanFixedDrivesViaRpc(&completed->summary);
        break;
    }

    ScanCompletedState* completedRaw = completed.release();
    if (!PostMessageW(request->window, kScanCompletedMessage, 0, reinterpret_cast<LPARAM>(completedRaw))) {
        delete completedRaw;
    }
    return 0;
}

void StartAsyncScan(HWND window, ScanOperation operation, const std::wstring& path = L"") {
    if (g_scanInProgress) {
        g_transientErrorMessage = L"Another scan is already running.";
        RefreshUiState();
        return;
    }

    auto* request = new ScanRequestContext();
    request->window = window;
    request->operation = operation;
    request->path = path;

    HANDLE thread = CreateThread(nullptr, 0, ScanWorkerThread, request, 0, nullptr);
    if (!thread) {
        delete request;
        g_transientErrorMessage = L"Unable to start the scan worker thread.";
        RefreshUiState();
        return;
    }

    CloseHandle(thread);
    g_scanInProgress = true;
    g_scanSummaryText = (operation == ScanOperation::FixedDrives)
        ? L"Fixed drives scan is running in the background..."
        : L"Scan is running in the background...";
    ClearTransientErrorOnSuccess();
    ApplyScreenState();
}

void HandleScanCompleted(HWND window, ScanCompletedState* completed) {
    std::unique_ptr<ScanCompletedState> result(completed);
    g_scanInProgress = false;

    if (!result || !result->rpcOk) {
        g_scanSummaryText = L"Unable to send the scan request.";
        ApplyScreenState();
        return;
    }

    g_scanSummaryText = result->summary.summary.empty()
        ? L"No scan result was returned."
        : result->summary.summary;

    if (result->summary.resultCode == antivirus::kRpcResultNotAuthenticated ||
        result->summary.resultCode == antivirus::kRpcResultLicenseRequired ||
        result->summary.resultCode == antivirus::kRpcResultDatabaseUnavailable) {
        RefreshUiState();
        return;
    }

    if (result->summary.resultCode != antivirus::kRpcResultOk) {
        g_transientErrorMessage = L"Scan finished with an error.";
    }

    ApplyScreenState();
}

void HandleLoginRequest() {
    const std::wstring username = GetEditText(g_controls.loginUsernameEdit);
    const std::wstring password = GetEditText(g_controls.loginPasswordEdit);

    antivirus::RpcAuthenticationState authState;
    if (!LoginUserViaRpc(username, password, &authState)) {
        g_transientErrorMessage = L"Unable to send the sign-in request.";
    } else if (authState.resultCode == antivirus::kRpcResultInvalidCredentials) {
        g_transientErrorMessage = L"Incorrect username or password.";
        SetWindowTextW(g_controls.loginUsernameEdit, L"");
        SetWindowTextW(g_controls.loginPasswordEdit, L"");
        SetFocus(g_controls.loginUsernameEdit);
    } else if (authState.resultCode != antivirus::kRpcResultOk) {
        g_transientErrorMessage = authState.message.empty()
            ? L"Sign-in failed."
            : authState.message;
    } else {
        ClearTransientErrorOnSuccess();
        SetWindowTextW(g_controls.loginPasswordEdit, L"");
    }

    RefreshUiState();
}

void HandleActivationRequest() {
    const std::wstring activationCode = GetEditText(g_controls.activationEdit);

    antivirus::RpcLicenseState licenseState;
    if (!ActivateProductViaRpc(activationCode, &licenseState)) {
        g_transientErrorMessage = L"Unable to send the activation request.";
    } else if (licenseState.resultCode != antivirus::kRpcResultOk) {
        g_transientErrorMessage = licenseState.message.empty()
            ? L"Activation failed."
            : licenseState.message;
    } else {
        ClearTransientErrorOnSuccess();
        SetWindowTextW(g_controls.activationEdit, L"");
    }

    RefreshUiState();
}

void HandleLogoutRequest() {
    std::wstring message;
    long resultCode = antivirus::kRpcResultUnexpectedResponse;

    if (!LogoutUserViaRpc(&message, &resultCode)) {
        g_transientErrorMessage = L"Unable to send the sign-out request.";
    } else if (resultCode != antivirus::kRpcResultOk) {
        g_transientErrorMessage = message.empty()
            ? L"Sign-out failed."
            : message;
    } else {
        ClearTransientErrorOnSuccess();
        SetWindowTextW(g_controls.loginPasswordEdit, L"");
        SetWindowTextW(g_controls.activationEdit, L"");
        g_scanSummaryText.clear();
    }

    RefreshUiState();
}

void HandleScanFileRequest(HWND owner) {
    std::wstring path = GetEditText(g_controls.scanFilePathEdit);
    if (path.empty()) {
        path = ShowOpenFileDialog(owner);
    }
    if (path.empty()) {
        return;
    }

    g_selectedScanFilePath = path;
    StartAsyncScan(owner, ScanOperation::File, path);
}

void HandleBrowseScanFileRequest(HWND owner) {
    const std::wstring path = ShowOpenFileDialog(owner);
    if (path.empty()) {
        return;
    }

    g_selectedScanFilePath = path;
    SetWindowTextW(g_controls.scanFilePathEdit, g_selectedScanFilePath.c_str());
}

void HandleScanFolderRequest(HWND owner) {
    const std::wstring path = ShowFolderDialog(owner);
    if (path.empty()) {
        return;
    }
    StartAsyncScan(owner, ScanOperation::Directory, path);
}

void HandleScanFixedDrivesRequest(HWND window) {
    StartAsyncScan(window, ScanOperation::FixedDrives);
}

void HandlePickScheduleFolderRequest(HWND owner) {
    const std::wstring path = ShowFolderDialog(owner);
    if (path.empty()) {
        return;
    }

    g_selectedScheduleFolder = path;
    RefreshUiState();
}

long ReadScheduleIntervalSeconds() {
    const std::wstring text = GetEditText(g_controls.scheduleIntervalEdit);
    if (text.empty()) {
        return 0;
    }

    try {
        return std::stol(text);
    } catch (...) {
        return 0;
    }
}

void HandleEnableScheduleRequest() {
    const long intervalSeconds = ReadScheduleIntervalSeconds();
    std::wstring message;
    long resultCode = antivirus::kRpcResultUnexpectedResponse;

    if (!ConfigureScheduledScanViaRpc(true, intervalSeconds, g_selectedScheduleFolder, &message, &resultCode)) {
        g_transientErrorMessage = L"Unable to configure scheduled scanning.";
    } else if (resultCode != antivirus::kRpcResultOk) {
        g_transientErrorMessage = message.empty() ? L"Scheduled scanning could not be enabled." : message;
    } else {
        ClearTransientErrorOnSuccess();
        g_scanSummaryText = message;
    }

    RefreshUiState();
}

void HandleDisableScheduleRequest() {
    std::wstring message;
    long resultCode = antivirus::kRpcResultUnexpectedResponse;

    if (!ConfigureScheduledScanViaRpc(false, 0, L"", &message, &resultCode)) {
        g_transientErrorMessage = L"Unable to disable scheduled scanning.";
    } else if (resultCode != antivirus::kRpcResultOk) {
        g_transientErrorMessage = message.empty() ? L"Scheduled scanning could not be disabled." : message;
    } else {
        ClearTransientErrorOnSuccess();
        g_scanSummaryText = message;
    }

    RefreshUiState();
}

void HandleAddMonitorRequest(HWND owner) {
    const std::wstring path = ShowFolderDialog(owner);
    if (path.empty()) {
        return;
    }

    std::wstring message;
    long resultCode = antivirus::kRpcResultUnexpectedResponse;
    if (!AddMonitoredDirectoryViaRpc(path, &message, &resultCode)) {
        g_transientErrorMessage = L"Unable to add the monitored directory.";
    } else if (resultCode != antivirus::kRpcResultOk) {
        g_transientErrorMessage = message.empty() ? L"The monitored directory could not be added." : message;
    } else {
        ClearTransientErrorOnSuccess();
        g_scanSummaryText = message;
    }

    RefreshUiState();
}

void HandleRemoveMonitorRequest(HWND owner) {
    const std::wstring path = ShowFolderDialog(owner);
    if (path.empty()) {
        return;
    }

    std::wstring message;
    long resultCode = antivirus::kRpcResultUnexpectedResponse;
    if (!RemoveMonitoredDirectoryViaRpc(path, &message, &resultCode)) {
        g_transientErrorMessage = L"Unable to remove the monitored directory.";
    } else if (resultCode != antivirus::kRpcResultOk) {
        g_transientErrorMessage = message.empty() ? L"The monitored directory could not be removed." : message;
    } else {
        ClearTransientErrorOnSuccess();
        g_scanSummaryText = message;
    }

    RefreshUiState();
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == g_taskbarCreatedMessage) {
        AddTrayIcon(window);
        return 0;
    }

    switch (message) {
    case WM_CREATE:
        SetMenu(window, CreateMainMenu());
        AddTrayIcon(window);
        CreateChildControls(window);
        LayoutControls(window);
        SetTimer(window, kStatePollTimerId, kStatePollIntervalMs, nullptr);
        RefreshUiState();
        return 0;

    case WM_SIZE:
        LayoutControls(window);
        return 0;

    case WM_TIMER:
        if (wParam == kStatePollTimerId) {
            RefreshUiState();
            return 0;
        }
        break;

    case kScanCompletedMessage:
        HandleScanCompleted(window, reinterpret_cast<ScanCompletedState*>(lParam));
        return 0;

    case antivirus::kTrayIconMessage:
        if (lParam == WM_LBUTTONDOWN) {
            ShowMainWindow();
        } else if (lParam == WM_RBUTTONDOWN) {
            ShowContextMenu(window);
        }
        return 0;

    case antivirus::kShowMainWindowMessage:
        RefreshUiState();
        ShowMainWindow();
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case antivirus::kTrayMenuOpen:
            RefreshUiState();
            ShowMainWindow();
            return 0;

        case antivirus::kTrayMenuExit:
        case antivirus::kFileMenuExit:
            RequestServiceStopFromUi(window);
            return 0;

        case kLoginButtonId:
            HandleLoginRequest();
            return 0;

        case kActivationButtonId:
            HandleActivationRequest();
            return 0;

        case kLogoutButtonId:
            HandleLogoutRequest();
            return 0;

        case kScanFileButtonId:
            HandleScanFileRequest(window);
            return 0;

        case kScanFileBrowseButtonId:
            HandleBrowseScanFileRequest(window);
            return 0;

        case kScanFixedDrivesButtonId:
            HandleScanFixedDrivesRequest(window);
            return 0;

        case kScanFolderButtonId:
            HandleScanFolderRequest(window);
            return 0;

        case kSchedulePickFolderButtonId:
            HandlePickScheduleFolderRequest(window);
            return 0;

        case kScheduleEnableButtonId:
            HandleEnableScheduleRequest();
            return 0;

        case kScheduleDisableButtonId:
            HandleDisableScheduleRequest();
            return 0;

        case kMonitoringAddButtonId:
            HandleAddMonitorRequest(window);
            return 0;

        case kMonitoringRemoveButtonId:
            HandleRemoveMonitorRequest(window);
            return 0;

        }
        break;

    case WM_CLOSE:
        HideMainWindow();
        return 0;

    case WM_DESTROY:
        KillTimer(window, kStatePollTimerId);
        RemoveTrayIcon();
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(window, message, wParam, lParam);
}

HWND CreateMainWindow(HINSTANCE instance) {
    WNDCLASSW windowClass = {};
    windowClass.lpfnWndProc = WindowProc;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    windowClass.lpszClassName = antivirus::kWindowClassName;

    RegisterClassW(&windowClass);

    return CreateWindowExW(
        0,
        antivirus::kWindowClassName,
        antivirus::kWindowTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        780,
        760,
        nullptr,
        nullptr,
        instance,
        nullptr
    );
}

} // namespace

int WINAPI WinMain(HINSTANCE instance, HINSTANCE, LPSTR, int) {
    const LaunchContext launchContext = DetectLaunchContext();

    if (!EnsureServiceRunning()) {
        return 0;
    }

    if (launchContext != LaunchContext::ServiceManaged) {
        if (launchContext == LaunchContext::ExplorerManaged) {
            RequestExistingInstanceToShowWindow();
        }
        return 0;
    }

    g_instanceMutex = CreateMutexW(nullptr, TRUE, antivirus::kAppMutexName);
    if (!g_instanceMutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        if (g_instanceMutex) {
            CloseHandle(g_instanceMutex);
        }
        return 0;
    }

    g_instance = instance;
    g_taskbarCreatedMessage = RegisterWindowMessageW(L"TaskbarCreated");
    g_mainWindow = CreateMainWindow(instance);
    if (!g_mainWindow) {
        CloseHandle(g_instanceMutex);
        return 1;
    }

    MSG message = {};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    RemoveTrayIcon();
    CloseHandle(g_instanceMutex);
    return 0;
}
