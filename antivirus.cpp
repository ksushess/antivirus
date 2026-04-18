#include <windows.h>
#include <shellapi.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

// Константы
#define WM_TRAYICON (WM_APP + 1)
#define ID_TRAY_EXIT 1001
#define ID_TRAY_OPEN 1002
#define ID_FILE_EXIT 2001

// Глобальные переменные
HINSTANCE g_hInst = NULL;
HWND g_hMainWnd = NULL;
NOTIFYICONDATAW g_nid = { 0 };
HANDLE g_hMutex = NULL;

// Прототипы функций
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void AddTrayIcon(HWND hWnd);
void RemoveTrayIcon();
void ShowContextMenu(HWND hWnd);
void ShowMainWindow();
void HideMainWindow();

// Создание главного окна
HWND CreateMainWindow(HINSTANCE hInst, int nCmdShow) {
    // Регистрация класса окна
    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"TrayAppClass";

    RegisterClassW(&wc);

    // Создание окна (НО НЕ ПОКАЗЫВАЕМ - пункт 7)
    HWND hWnd = CreateWindowExW(
        0,
        L"TrayAppClass",
        L"Antivirus",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 300,
        NULL, NULL, hInst, NULL
    );

    return hWnd;
}

// Добавление иконки в трей
void AddTrayIcon(HWND hWnd) {
    memset(&g_nid, 0, sizeof(NOTIFYICONDATAW));
    g_nid.cbSize = sizeof(NOTIFYICONDATAW);
    g_nid.hWnd = hWnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION); // Стандартная иконка
    wcscpy_s(g_nid.szTip, L"Antivirus");

    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

// Удаление иконки из трея
void RemoveTrayIcon() {
    if (g_nid.hWnd) {
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        if (g_nid.hIcon) {
            DestroyIcon(g_nid.hIcon);
        }
    }
}

// Показ контекстного меню 
void ShowContextMenu(HWND hWnd) {
    HMENU hMenu = CreatePopupMenu();

    AppendMenuW(hMenu, MF_STRING, ID_TRAY_OPEN, L"Открыть");   // пункт 4
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"Выход");      // пункт 5

    POINT pt;
    GetCursorPos(&pt);

    // Чтобы меню закрывалось по клику вне его
    SetForegroundWindow(hWnd);
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
    PostMessage(hWnd, WM_NULL, 0, 0);

    DestroyMenu(hMenu);
}

// Показ главного окна
void ShowMainWindow() {
    if (g_hMainWnd) {
        ShowWindow(g_hMainWnd, SW_SHOW);
        SetForegroundWindow(g_hMainWnd);
    }
}

// Скрытие главного окна
void HideMainWindow() {
    if (g_hMainWnd) {
        ShowWindow(g_hMainWnd, SW_HIDE);
    }
}

// Создание меню для главного окна 
HMENU CreateMainMenu() {
    HMENU hMenu = CreateMenu();
    HMENU hFileMenu = CreatePopupMenu();

    AppendMenuW(hFileMenu, MF_STRING, ID_FILE_EXIT, L"Выход");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, L"Файл");

    return hMenu;
}

// Обработчик сообщений окна
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE: {
        // Создаем меню 
        HMENU hMenu = CreateMainMenu();
        SetMenu(hWnd, hMenu);

        // Добавляем иконку в трей 
        AddTrayIcon(hWnd);
        break;
    }

    case WM_TRAYICON: {
        if (lParam == WM_LBUTTONDOWN) {      // клик левой кнопкой
            ShowMainWindow();
        }
        else if (lParam == WM_RBUTTONDOWN) { // клик правой кнопкой
            ShowContextMenu(hWnd);
        }
        break;
    }

    case WM_COMMAND: {
        int wmId = LOWORD(wParam);

        switch (wmId) {
        case ID_TRAY_OPEN:   // "Открыть" в меню трея
            ShowMainWindow();
            break;

        case ID_TRAY_EXIT:   // "Выход" в меню трея
            RemoveTrayIcon();
            PostQuitMessage(0);
            break;

        case ID_FILE_EXIT:   // "Выход" в меню окна
            RemoveTrayIcon();
            PostQuitMessage(0);
            break;
        }
        break;
    }

    case WM_CLOSE: {
        // закрытие окна не завершает приложение, а скрывает его
        HideMainWindow();
        return 0; // Не передаем в DefWindowProc
    }

    case WM_DESTROY: {
        PostQuitMessage(0);
        break;
    }

    default:
    // Восстановление иконки при перезапуске проводника
    static UINT uTaskbarRestart = RegisterWindowMessageW(L"TaskbarCreated");
    if (message == uTaskbarRestart) {
        AddTrayIcon(hWnd);
        return 0;
    }
    return DefWindowProc(hWnd, message, wParam, lParam);
}
return 0;
}

// Главная функция
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // проверка единственного экземпляра
    g_hMutex = CreateMutexW(NULL, TRUE, L"Global\\AntivirusTrayApp");

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // Приложение уже запущено - завершаемся ДО добавления иконки в трей
        return 0;
    }

    g_hInst = hInstance;

    // Создаем главное окно 
    g_hMainWnd = CreateMainWindow(hInstance, nCmdShow);

    if (!g_hMainWnd) {
        return 1;
    }

    // регистрируем сообщение о пересоздании панели задач
    UINT uTaskbarRestart = RegisterWindowMessageW(L"TaskbarCreated");

    // Главный цикл сообщений
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        // если панель задач пересоздана, добавляем иконку заново
        if (msg.message == uTaskbarRestart) {
            AddTrayIcon(g_hMainWnd);
        }

        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Очистка
    RemoveTrayIcon();
    if (g_hMutex) CloseHandle(g_hMutex);

    return 0;
}
