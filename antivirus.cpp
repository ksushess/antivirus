#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>

#include <algorithm>
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
    kLogoutButtonId
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
};

struct ScreenState {
    ScreenMode mode = ScreenMode::Login;
    std::wstring username;
    std::wstring protectionText;
    std::wstring licenseText;
    std::wstring errorText;
    bool protectionUnlocked = false;
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

    MoveWindow(g_controls.headerLabel, left, top, fullWidth, 24, TRUE);
    MoveWindow(g_controls.usernameLabel, left, top + 34, fullWidth, 20, TRUE);
    MoveWindow(g_controls.protectionLabel, left, top + 58, fullWidth, 20, TRUE);
    MoveWindow(g_controls.licenseLabel, left, top + 82, fullWidth, 20, TRUE);
    MoveWindow(g_controls.errorLabel, left, top + 110, fullWidth, 34, TRUE);

    MoveWindow(g_controls.loginUsernameLabel, left, top + 160, labelColumnWidth, 20, TRUE);
    MoveWindow(g_controls.loginUsernameEdit, fieldLeft, top + 156, fieldWidth, 24, TRUE);
    MoveWindow(g_controls.loginPasswordLabel, left, top + 194, labelColumnWidth, 20, TRUE);
    MoveWindow(g_controls.loginPasswordEdit, fieldLeft, top + 190, fieldWidth, 24, TRUE);
    MoveWindow(g_controls.loginButton, fieldLeft, top + 226, 120, 28, TRUE);

    MoveWindow(g_controls.activationLabel, left, top + 160, labelColumnWidth, 20, TRUE);
    MoveWindow(g_controls.activationEdit, fieldLeft, top + 156, fieldWidth, 24, TRUE);
    MoveWindow(g_controls.activationButton, fieldLeft, top + 192, 120, 28, TRUE);

    MoveWindow(g_controls.logoutButton, clientRect.right - 160, clientRect.bottom - 60, 140, 30, TRUE);
}

void SetControlVisible(HWND control, bool visible) {
    if (control) {
        ShowWindow(control, visible ? SW_SHOW : SW_HIDE);
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

ScreenState QueryScreenState() {
    ScreenState state;
    state.mode = ScreenMode::Login;
    state.protectionText = L"Protection is blocked until you sign in.";

    antivirus::RpcAuthenticationState authState;
    if (!GetAuthenticationStateViaRpc(&authState)) {
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
        state.mode = ScreenMode::Activation;
        state.protectionText = L"Protection is blocked until the license state can be loaded.";
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
        if (!g_transientErrorMessage.empty()) {
            state.errorText = g_transientErrorMessage;
        } else if (licenseState.resultCode != antivirus::kRpcResultOk && !licenseState.message.empty()) {
            state.errorText = licenseState.message;
        }
        return state;
    }

    state.mode = ScreenMode::Activation;
    state.protectionText = BuildProtectionText(licenseState.licenseState);
    state.licenseText = L"Enter an activation code to unlock protection.";

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
    SetWindowTextW(g_controls.errorLabel, g_screenState.errorText.c_str());

    const bool showLogin = g_screenState.mode == ScreenMode::Login;
    const bool showActivation = g_screenState.mode == ScreenMode::Activation;
    const bool showLogout = g_screenState.mode != ScreenMode::Login;

    SetControlVisible(g_controls.loginUsernameLabel, showLogin);
    SetControlVisible(g_controls.loginUsernameEdit, showLogin);
    SetControlVisible(g_controls.loginPasswordLabel, showLogin);
    SetControlVisible(g_controls.loginPasswordEdit, showLogin);
    SetControlVisible(g_controls.loginButton, showLogin);

    SetControlVisible(g_controls.activationLabel, showActivation);
    SetControlVisible(g_controls.activationEdit, showActivation);
    SetControlVisible(g_controls.activationButton, showActivation);
    SetControlVisible(g_controls.logoutButton, showLogout);

    SetControlVisible(g_controls.errorLabel, !g_screenState.errorText.empty());
    SetControlVisible(g_controls.licenseLabel, !g_screenState.licenseText.empty());
}

void RefreshUiState() {
    if (g_isRefreshingState) {
        return;
    }

    g_isRefreshingState = true;
    g_screenState = QueryScreenState();
    ApplyScreenState();
    g_isRefreshingState = false;
}

void ClearTransientErrorOnSuccess() {
    g_transientErrorMessage.clear();
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
        560,
        420,
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
