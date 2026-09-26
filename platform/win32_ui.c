/**
 * win32_ui.c - Modern Dark-Themed Win32 GUI for Password Manager
 *
 * Rewritten to use the Unicode (W) Win32 API throughout. This fixes the
 * previous garbled-character bug (UTF-8 bytes and wide strings being pushed
 * through ANSI "A" APIs) and enables proper glyphs (bullets, etc.).
 *
 * Design:
 *  - Dark theme with a clean header bar (icon + title), a rounded search box,
 *    a card-style credential list, and a bottom action bar.
 *  - Owner-drawn flat buttons with hover/pressed states and an accent primary.
 *  - Double-click a row cell to copy URL / Username / Password.
 *  - Dark title bar via DwmSetWindowAttribute.
 *  - Clipboard auto-clear countdown shown in the status bar.
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "credential.h"
#include "vault.h"
#include "encryption.h"
#include "sync.h"
#include "platform.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "dwmapi.lib")

/* ─── App Icon Resource (see app.rc) ──────────────────────────────────────── */
#ifndef IDI_APPICON
#define IDI_APPICON 101
#endif

/* ─── Dark Theme Palette ──────────────────────────────────────────────────── */

#define CLR_BG_MAIN        RGB(0x1E, 0x1E, 0x2E)  /* window body            */
#define CLR_BG_HEADER      RGB(0x18, 0x18, 0x25)  /* header + action bars   */
#define CLR_SURFACE        RGB(0x25, 0x25, 0x38)  /* cards / inputs         */
#define CLR_SURFACE_ALT    RGB(0x2A, 0x2A, 0x40)  /* alternating rows       */
#define CLR_TEXT           RGB(0xCD, 0xD6, 0xF4)  /* primary text           */
#define CLR_TEXT_DIM       RGB(0x9A, 0xA2, 0xC0)  /* secondary text         */
#define CLR_ACCENT         RGB(0x89, 0xB4, 0xFA)  /* accent (blue)          */
#define CLR_ACCENT_DK      RGB(0x5E, 0x84, 0xC8)  /* accent pressed         */
#define CLR_BTN_BG         RGB(0x31, 0x31, 0x48)  /* button normal          */
#define CLR_BTN_HOVER      RGB(0x3C, 0x3C, 0x58)  /* button hover           */
#define CLR_BTN_TEXT       RGB(0xCD, 0xD6, 0xF4)
#define CLR_SELECTED       RGB(0x34, 0x3A, 0x5C)  /* selected row           */
#define CLR_BORDER         RGB(0x3A, 0x3A, 0x54)

/* ─── Constants ───────────────────────────────────────────────────────────── */

#define APP_CLASS_NAME      L"ROMPasswordManager"
#define APP_TITLE           L"Password Manager"
#define VAULT_FILE_PATH     "vault.vlt"

#define IDC_LISTVIEW        1001
#define IDC_BTN_ADD         1002
#define IDC_BTN_EDIT        1003
#define IDC_BTN_DELETE      1004
#define IDC_BTN_SYNC        1008
#define IDC_BTN_LOCK        1009
#define IDC_STATUSBAR       1010
#define IDC_EDIT_SEARCH     1011
#define IDC_BTN_SEARCH      1012

#define IDT_CLIPBOARD_TIMER 2001
#define IDT_CLIP_INTERVAL   1000
#define IDT_COPIED_TIMER    2002
#define IDT_COPIED_DURATION 2000

/* Dialog control IDs */
#define IDC_EDIT_URL        3001
#define IDC_EDIT_USERNAME   3002
#define IDC_EDIT_PASSWORD   3003
#define IDC_STATIC_ERROR    3004
#define IDC_EDIT_MASTER_PW  3005
#define IDC_STATIC_DELAY    3006

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

/* Layout metrics */
#define HEADER_HEIGHT       56
#define ACTIONBAR_HEIGHT    52
#define STATUSBAR_HEIGHT    24
#define PADDING             16
#define BTN_HEIGHT          34
#define BTN_SPACING         8
#define SEARCH_HEIGHT       30

/* Number of action-bar buttons: Add, Edit, Delete, Sync, Lock */
#define BTN_COUNT           5

/* ─── Application State ───────────────────────────────────────────────────── */

typedef struct {
    Vault vault;
    DerivedKey derived_key;
    char master_password[MAX_PASSWORD_LEN + 1];
    bool is_unlocked;
    bool is_new_vault;
    HWND hwnd_main;
    HWND hwnd_listview;
    HWND hwnd_statusbar;
    HWND hwnd_buttons[BTN_COUNT];
    HWND hwnd_search_edit;
    HFONT hfont_ui;
    HFONT hfont_title;
    HBRUSH hbr_bg;
    HBRUSH hbr_header;
    HBRUSH hbr_surface;
    HICON hicon_app;
    bool show_copied_msg;
    char vault_path[MAX_PATH];
} AppState;

static AppState g_app = {0};

/* ─── Forward Declarations ────────────────────────────────────────────────── */

static LRESULT CALLBACK MainWndProc(HWND, UINT, WPARAM, LPARAM);
static INT_PTR CALLBACK MasterPasswordDlgProc(HWND, UINT, WPARAM, LPARAM);
static INT_PTR CALLBACK CredentialDlgProc(HWND, UINT, WPARAM, LPARAM);

static void UI_RefreshCredentialList(void);
static void UI_UpdateStatusBar(void);
static bool UI_UnlockVault(HWND);
static bool UI_CreateNewVault(HWND);
static void UI_AutoSave(void);
static void UI_LockVault(void);
static int  UI_GetSelectedCredentialId(void);
static void UI_CopyAndNotify(HWND, const char *, size_t);
static void UI_HandleListViewDblClick(HWND, LPNMITEMACTIVATE);
static void UI_StartSync(HWND);
static void UI_LayoutChildren(void);

/* ─── UTF-8 <-> UTF-16 helpers ────────────────────────────────────────────── */

/* Convert UTF-8 (C string) to a freshly allocated wide string. Caller frees. */
static wchar_t *utf8_to_wide(const char *s)
{
    if (!s) s = "";
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) {
        wchar_t *e = (wchar_t *)malloc(sizeof(wchar_t));
        if (e) e[0] = 0;
        return e;
    }
    wchar_t *w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

/* Convert wide string into a UTF-8 buffer. Returns bytes written (excl. NUL). */
static size_t wide_to_utf8(const wchar_t *w, char *out, size_t out_size)
{
    if (!w) w = L"";
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)out_size, NULL, NULL);
    if (n <= 0) {
        if (out_size > 0) out[0] = 0;
        return 0;
    }
    return (size_t)(n - 1);
}

/* ─── Dark Title Bar ──────────────────────────────────────────────────────── */

static void UI_EnableDarkTitleBar(HWND hwnd)
{
    BOOL value = TRUE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &value, sizeof(value));
}

/* ─── Fonts ───────────────────────────────────────────────────────────────── */

static HFONT UI_CreateFontPx(int height, int weight)
{
    return CreateFontW(
        height, 0, 0, 0, weight,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
}

/* ─── Owner-Drawn Buttons ─────────────────────────────────────────────────── */

/* Distinguish the primary (accent) button from secondary ones by index. */
static LRESULT CALLBACK ButtonSubclassProc(HWND hwnd, UINT msg,
                                            WPARAM wParam, LPARAM lParam,
                                            UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
    (void)dwRefData;
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);

        POINT pt; GetCursorPos(&pt); ScreenToClient(hwnd, &pt);
        bool hovered = PtInRect(&rc, pt) != 0;
        bool primary = (uIdSubclass == 0); /* index 0 == "Add" is primary */

        COLORREF fill;
        if (primary) {
            fill = hovered ? CLR_ACCENT : CLR_ACCENT_DK;
        } else {
            fill = hovered ? CLR_BTN_HOVER : CLR_BTN_BG;
        }

        HBRUSH hbr = CreateSolidBrush(fill);
        FillRect(hdc, &rc, hbr);
        DeleteObject(hbr);

        /* Rounded outline */
        HPEN pen = CreatePen(PS_SOLID, 1, primary ? CLR_ACCENT : CLR_BORDER);
        HPEN oldPen = (HPEN)SelectObject(hdc, pen);
        HBRUSH oldBr = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
        RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 10, 10);
        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBr);
        DeleteObject(pen);

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, primary ? RGB(0x11, 0x14, 0x20) : CLR_BTN_TEXT);
        HFONT oldFont = (HFONT)SelectObject(hdc, g_app.hfont_ui);
        wchar_t text[64] = {0};
        GetWindowTextW(hwnd, text, 63);
        DrawTextW(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, oldFont);

        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_MOUSEMOVE: {
        TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
        TrackMouseEvent(&tme);
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }
    case WM_MOUSELEAVE:
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_NCDESTROY:
        RemoveWindowSubclass(hwnd, ButtonSubclassProc, uIdSubclass);
        break;
    }
    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

/* ─── ListView Setup ──────────────────────────────────────────────────────── */

static void ListView_SetupCols(HWND lv)
{
    ListView_SetExtendedListViewStyle(lv,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

    ListView_SetBkColor(lv, CLR_BG_MAIN);
    ListView_SetTextBkColor(lv, CLR_BG_MAIN);
    ListView_SetTextColor(lv, CLR_TEXT);

    LVCOLUMNW col = {0};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    col.iSubItem = 0; col.pszText = L"URL";       col.cx = 340;
    ListView_InsertColumn(lv, 0, &col);
    col.iSubItem = 1; col.pszText = L"Username";  col.cx = 240;
    ListView_InsertColumn(lv, 1, &col);
    col.iSubItem = 2; col.pszText = L"Password";  col.cx = 160;
    ListView_InsertColumn(lv, 2, &col);
}

static void UI_AddRow(HWND lv, int index, const Credential *cred)
{
    wchar_t *wurl = utf8_to_wide(cred->url);
    wchar_t *wuser = utf8_to_wide(cred->username);

    LVITEMW item = {0};
    item.mask = LVIF_TEXT | LVIF_PARAM;
    item.iItem = index;
    item.iSubItem = 0;
    item.pszText = wurl ? wurl : L"";
    item.lParam = (LPARAM)cred->id;
    int idx = ListView_InsertItem(lv, &item);

    ListView_SetItemText(lv, idx, 1, wuser ? wuser : L"");
    /* Masked password: real Unicode bullets now render correctly. */
    ListView_SetItemText(lv, idx, 2, L"\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022");

    free(wurl);
    free(wuser);
}

static void UI_RefreshCredentialList(void)
{
    if (!g_app.hwnd_listview) return;
    ListView_DeleteAllItems(g_app.hwnd_listview);
    cred_sort_by_url(&g_app.vault);

    int row = 0;
    for (uint32_t i = 0; i < g_app.vault.count; i++) {
        Credential *cred = &g_app.vault.entries[i];
        if (cred->deleted) continue;
        UI_AddRow(g_app.hwnd_listview, row++, cred);
    }
    UI_UpdateStatusBar();
}

static int UI_GetSelectedCredentialId(void)
{
    int sel = ListView_GetNextItem(g_app.hwnd_listview, -1, LVNI_SELECTED);
    if (sel < 0) return -1;
    LVITEMW item = {0};
    item.mask = LVIF_PARAM;
    item.iItem = sel;
    ListView_GetItem(g_app.hwnd_listview, &item);
    return (int)item.lParam;
}

/* ─── Copy + Notify ───────────────────────────────────────────────────────── */

static void UI_CopyAndNotify(HWND hwnd, const char *text, size_t len)
{
    ClipResult cr = clip_copy(text, len);
    if (cr == CLIP_OK) {
        g_app.show_copied_msg = true;
        SendMessageW(g_app.hwnd_statusbar, SB_SETTEXTW, 0, (LPARAM)L"  Copied to clipboard");
        SetTimer(hwnd, IDT_COPIED_TIMER, IDT_COPIED_DURATION, NULL);
    }
}

static void UI_HandleListViewDblClick(HWND hwnd, LPNMITEMACTIVATE pnmia)
{
    if (pnmia->iItem < 0) return;

    LVITEMW item = {0};
    item.mask = LVIF_PARAM;
    item.iItem = pnmia->iItem;
    ListView_GetItem(g_app.hwnd_listview, &item);
    int cred_id = (int)item.lParam;

    Credential *cred = cred_get(&g_app.vault, (uint32_t)cred_id);
    if (!cred) return;

    LVHITTESTINFO ht = {0};
    ht.pt = pnmia->ptAction;
    ListView_SubItemHitTest(g_app.hwnd_listview, &ht);

    switch (ht.iSubItem) {
    case 0: UI_CopyAndNotify(hwnd, cred->url, strlen(cred->url)); break;
    case 1: UI_CopyAndNotify(hwnd, cred->username, strlen(cred->username)); break;
    case 2: UI_CopyAndNotify(hwnd, cred->password, strlen(cred->password)); break;
    }
}

/* ─── Status Bar ──────────────────────────────────────────────────────────── */

static void UI_UpdateStatusBar(void)
{
    if (!g_app.hwnd_statusbar) return;
    if (g_app.show_copied_msg) return;

    uint32_t remaining = clip_get_remaining_seconds();
    wchar_t text[160];
    if (remaining > 0) {
        _snwprintf_s(text, 160, _TRUNCATE,
                     L"  Clipboard clears in %u second(s)", remaining);
    } else {
        _snwprintf_s(text, 160, _TRUNCATE,
                     L"  Ready   \u2022   %u credential(s)   \u2022   Double-click a cell to copy",
                     g_app.vault.count);
    }
    SendMessageW(g_app.hwnd_statusbar, SB_SETTEXTW, 0, (LPARAM)text);
}

/* ─── Auto-Save ───────────────────────────────────────────────────────────── */

static void UI_AutoSave(void)
{
    if (!g_app.vault.is_dirty) return;

    uint8_t *data = NULL;
    size_t len = 0;
    StoreResult sr = vault_serialize(&g_app.vault, &g_app.derived_key, &data, &len);
    if (sr != STORE_OK) {
        MessageBoxW(g_app.hwnd_main,
                    L"Failed to serialize vault. Changes may not be saved.",
                    L"Save Error", MB_OK | MB_ICONERROR);
        return;
    }
    sr = store_save(g_app.vault_path, data, len);
    free(data);
    if (sr != STORE_OK) {
        MessageBoxW(g_app.hwnd_main,
                    L"Failed to write vault file. Changes may not be saved.",
                    L"Save Error", MB_OK | MB_ICONERROR);
    } else {
        g_app.vault.is_dirty = false;
    }
}

/* ─── Lock Vault ──────────────────────────────────────────────────────────── */

static void UI_LockVault(void)
{
    if (g_app.vault.entries) {
        enc_secure_zero(g_app.vault.entries,
                        g_app.vault.capacity * sizeof(Credential));
        free(g_app.vault.entries);
        g_app.vault.entries = NULL;
    }
    g_app.vault.count = 0;
    g_app.vault.capacity = 0;
    g_app.vault.is_dirty = false;

    enc_secure_zero(&g_app.derived_key, sizeof(DerivedKey));
    enc_secure_zero(g_app.master_password, sizeof(g_app.master_password));
    g_app.is_unlocked = false;

    if (g_app.hwnd_listview) ListView_DeleteAllItems(g_app.hwnd_listview);
    clip_clear();

    if (!UI_UnlockVault(g_app.hwnd_main)) {
        PostQuitMessage(0);
    } else {
        UI_RefreshCredentialList();
    }
}

/* ─── Responsive Wait (keeps UI painting during auth delay) ───────────────── */

static void UI_ResponsiveWait(uint32_t ms)
{
    if (ms == 0) return;
    DWORD start = GetTickCount();
    while ((GetTickCount() - start) < ms) {
        MSG msg;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }
}

/* ─── Master Password Dialog ──────────────────────────────────────────────── */

typedef struct {
    bool is_create;
    char password[MAX_PASSWORD_LEN + 1];
    bool success;
} MasterPwDlgData;

static INT_PTR CALLBACK MasterPasswordDlgProc(HWND hDlg, UINT msg,
                                               WPARAM wParam, LPARAM lParam)
{
    MasterPwDlgData *data = (MasterPwDlgData *)GetWindowLongPtrW(hDlg, GWLP_USERDATA);

    switch (msg) {
    case WM_INITDIALOG:
        data = (MasterPwDlgData *)lParam;
        SetWindowLongPtrW(hDlg, GWLP_USERDATA, (LONG_PTR)data);

        if (data->is_create) {
            SetWindowTextW(hDlg, L"Create New Vault");
            SetDlgItemTextW(hDlg, IDC_STATIC_DELAY,
                            L"Choose a master password (minimum 8 characters):");
        } else {
            SetWindowTextW(hDlg, L"Unlock Vault");
            uint32_t failures = master_password_get_failure_count();
            if (failures > 0) {
                wchar_t buf[128];
                _snwprintf_s(buf, 128, _TRUNCATE,
                             L"Enter master password (delay: %u sec after failure):",
                             failures);
                SetDlgItemTextW(hDlg, IDC_STATIC_DELAY, buf);
            } else {
                SetDlgItemTextW(hDlg, IDC_STATIC_DELAY, L"Enter your master password:");
            }
        }
        SetFocus(GetDlgItem(hDlg, IDC_EDIT_MASTER_PW));
        return FALSE;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            wchar_t wpw[MAX_PASSWORD_LEN + 1] = {0};
            GetDlgItemTextW(hDlg, IDC_EDIT_MASTER_PW, wpw, MAX_PASSWORD_LEN + 1);

            char pw[MAX_PASSWORD_LEN + 1] = {0};
            size_t pw_len = wide_to_utf8(wpw, pw, sizeof(pw));
            SecureZeroMemory(wpw, sizeof(wpw));

            if (data->is_create) {
                if (!master_password_validate(pw, pw_len)) {
                    SetDlgItemTextW(hDlg, IDC_STATIC_ERROR,
                                    L"Password must be at least 8 characters.");
                    enc_secure_zero(pw, sizeof(pw));
                    return TRUE;
                }
            }
            strncpy(data->password, pw, MAX_PASSWORD_LEN);
            data->password[MAX_PASSWORD_LEN] = '\0';
            data->success = true;
            enc_secure_zero(pw, sizeof(pw));
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        case IDCANCEL:
            data->success = false;
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        data->success = false;
        EndDialog(hDlg, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

static INT_PTR ShowMasterPasswordDialog(HWND hwndParent, MasterPwDlgData *data)
{
    /* Build a wide dialog template in memory. */
    BYTE buf[2048] = {0};
    DLGTEMPLATE *pDlg = (DLGTEMPLATE *)buf;
    pDlg->style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE;
    pDlg->cdit = 5;
    pDlg->cx = 240; pDlg->cy = 104;

    WORD *pw = (WORD *)(pDlg + 1);
    *pw++ = 0; *pw++ = 0; *pw++ = 0; /* menu, class, title */

    #define ALIGN_DWORD(p) (BYTE*)(((ULONG_PTR)(p) + 3) & ~3)

    /* label */
    pw = (WORD *)ALIGN_DWORD(pw);
    DLGITEMTEMPLATE *it = (DLGITEMTEMPLATE *)pw;
    it->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    it->x = 12; it->y = 12; it->cx = 216; it->cy = 12; it->id = IDC_STATIC_DELAY;
    pw = (WORD *)(it + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0082; *pw++ = 0; *pw++ = 0;

    /* edit (password) */
    pw = (WORD *)ALIGN_DWORD(pw);
    it = (DLGITEMTEMPLATE *)pw;
    it->style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL;
    it->x = 12; it->y = 28; it->cx = 216; it->cy = 14; it->id = IDC_EDIT_MASTER_PW;
    pw = (WORD *)(it + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0081; *pw++ = 0; *pw++ = 0;

    /* error label */
    pw = (WORD *)ALIGN_DWORD(pw);
    it = (DLGITEMTEMPLATE *)pw;
    it->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    it->x = 12; it->y = 46; it->cx = 216; it->cy = 12; it->id = IDC_STATIC_ERROR;
    pw = (WORD *)(it + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0082; *pw++ = 0; *pw++ = 0;

    /* OK */
    pw = (WORD *)ALIGN_DWORD(pw);
    it = (DLGITEMTEMPLATE *)pw;
    it->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON;
    it->x = 70; it->y = 74; it->cx = 74; it->cy = 16; it->id = IDOK;
    pw = (WORD *)(it + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0080;
    *pw++ = L'O'; *pw++ = L'K'; *pw++ = 0; *pw++ = 0;

    /* Cancel */
    pw = (WORD *)ALIGN_DWORD(pw);
    it = (DLGITEMTEMPLATE *)pw;
    it->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON;
    it->x = 154; it->y = 74; it->cx = 74; it->cy = 16; it->id = IDCANCEL;
    pw = (WORD *)(it + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0080;
    *pw++ = L'C'; *pw++ = L'a'; *pw++ = L'n'; *pw++ = L'c';
    *pw++ = L'e'; *pw++ = L'l'; *pw++ = 0; *pw++ = 0;

    #undef ALIGN_DWORD

    return DialogBoxIndirectParamW(GetModuleHandle(NULL), pDlg, hwndParent,
                                   MasterPasswordDlgProc, (LPARAM)data);
}

static bool UI_UnlockVault(HWND hwndParent)
{
    MasterPwDlgData dlg_data = {0};
    dlg_data.is_create = false;

    while (1) {
        INT_PTR result = ShowMasterPasswordDialog(hwndParent, &dlg_data);
        if (result == IDCANCEL || !dlg_data.success) {
            return false;
        }

        uint8_t *file_data = NULL;
        size_t file_len = 0;
        StoreResult sr = store_load(g_app.vault_path, &file_data, &file_len);
        if (sr != STORE_OK) {
            MessageBoxW(hwndParent, L"Failed to read vault file.",
                        L"Error", MB_OK | MB_ICONERROR);
            enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));
            return false;
        }
        if (file_len < VAULT_HEADER_SIZE) {
            free(file_data);
            MessageBoxW(hwndParent, L"Vault file is corrupted.",
                        L"Error", MB_OK | MB_ICONERROR);
            enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));
            return false;
        }

        /* Read the KDF parameters and salt stored in the vault header so we
         * derive the key exactly as it was written (honoring higher-cost
         * vaults, not just the compile-time minimums). Header layout:
         * iterations@7 (u32 LE), memory_kb@11 (u32 LE), parallelism@15, salt@16. */
        uint32_t hdr_iters = (uint32_t)file_data[7] | ((uint32_t)file_data[8] << 8) |
                             ((uint32_t)file_data[9] << 16) | ((uint32_t)file_data[10] << 24);
        uint32_t hdr_mem   = (uint32_t)file_data[11] | ((uint32_t)file_data[12] << 8) |
                             ((uint32_t)file_data[13] << 16) | ((uint32_t)file_data[14] << 24);
        uint8_t  hdr_par   = file_data[15];

        uint8_t salt[ENC_SALT_SIZE];
        memcpy(salt, file_data + 16, ENC_SALT_SIZE);

        EncResult er = enc_derive_key_params(dlg_data.password, strlen(dlg_data.password),
                                             salt, hdr_iters, hdr_mem, hdr_par,
                                             &g_app.derived_key);
        if (er != ENC_OK) {
            free(file_data);
            MessageBoxW(hwndParent, L"Key derivation failed.",
                        L"Error", MB_OK | MB_ICONERROR);
            enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));
            return false;
        }

        sr = vault_deserialize(file_data, file_len, &g_app.derived_key, &g_app.vault);
        free(file_data);

        if (sr == STORE_OK) {
            master_password_record_success();
            strncpy(g_app.master_password, dlg_data.password, MAX_PASSWORD_LEN);
            g_app.master_password[MAX_PASSWORD_LEN] = '\0';
            enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));
            g_app.is_unlocked = true;
            return true;
        } else if (sr == STORE_ERR_AUTH) {
            master_password_record_failure_no_delay();
            enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));
            enc_secure_zero(&g_app.derived_key, sizeof(DerivedKey));

            uint32_t new_failures = master_password_get_failure_count();
            wchar_t err[160];
            _snwprintf_s(err, 160, _TRUNCATE,
                         L"Incorrect master password. Next attempt delayed %u second(s).",
                         new_failures);
            MessageBoxW(hwndParent, err, L"Authentication Failed",
                        MB_OK | MB_ICONWARNING);
            UI_ResponsiveWait(master_password_get_delay_ms());
        } else {
            enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));
            enc_secure_zero(&g_app.derived_key, sizeof(DerivedKey));
            const wchar_t *msg = (sr == STORE_ERR_CORRUPT)
                ? L"The vault file is damaged and could not be read.\nThis is not a password problem."
                : L"Failed to read the vault file.";
            MessageBoxW(hwndParent, msg, L"Vault Error", MB_OK | MB_ICONERROR);
            return false;
        }
    }
}

static bool UI_CreateNewVault(HWND hwndParent)
{
    MasterPwDlgData dlg_data = {0};
    dlg_data.is_create = true;

    INT_PTR result = ShowMasterPasswordDialog(hwndParent, &dlg_data);
    if (result == IDCANCEL || !dlg_data.success) return false;

    uint8_t salt[ENC_SALT_SIZE];
    if (!platform_random_bytes(salt, ENC_SALT_SIZE)) {
        MessageBoxW(hwndParent, L"Failed to generate random salt.",
                    L"Error", MB_OK | MB_ICONERROR);
        enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));
        return false;
    }

    EncResult er = enc_derive_key(dlg_data.password, strlen(dlg_data.password),
                                  salt, &g_app.derived_key);
    strncpy(g_app.master_password, dlg_data.password, MAX_PASSWORD_LEN);
    g_app.master_password[MAX_PASSWORD_LEN] = '\0';
    enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));

    if (er != ENC_OK) {
        MessageBoxW(hwndParent, L"Key derivation failed.",
                    L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    g_app.vault.entries = (Credential *)calloc(MAX_CREDENTIALS, sizeof(Credential));
    if (!g_app.vault.entries) {
        MessageBoxW(hwndParent, L"Memory allocation failed.",
                    L"Error", MB_OK | MB_ICONERROR);
        return false;
    }
    g_app.vault.count = 0;
    g_app.vault.capacity = MAX_CREDENTIALS;
    g_app.vault.is_dirty = true;
    UI_AutoSave();
    g_app.is_unlocked = true;
    return true;
}

/* ─── Credential Add/Edit Dialog ──────────────────────────────────────────── */

typedef struct {
    bool is_edit;
    uint32_t cred_id;
    char url[MAX_URL_LEN + 1];
    char username[MAX_USERNAME_LEN + 1];
    char password[MAX_PASSWORD_LEN + 1];
    bool success;
} CredDlgData;

static INT_PTR CALLBACK CredentialDlgProc(HWND hDlg, UINT msg,
                                           WPARAM wParam, LPARAM lParam)
{
    CredDlgData *data = (CredDlgData *)GetWindowLongPtrW(hDlg, GWLP_USERDATA);

    switch (msg) {
    case WM_INITDIALOG: {
        data = (CredDlgData *)lParam;
        SetWindowLongPtrW(hDlg, GWLP_USERDATA, (LONG_PTR)data);

        if (data->is_edit) {
            SetWindowTextW(hDlg, L"Edit Credential");
            wchar_t *w;
            w = utf8_to_wide(data->url);      SetDlgItemTextW(hDlg, IDC_EDIT_URL, w);      free(w);
            w = utf8_to_wide(data->username); SetDlgItemTextW(hDlg, IDC_EDIT_USERNAME, w); free(w);
            w = utf8_to_wide(data->password); SetDlgItemTextW(hDlg, IDC_EDIT_PASSWORD, w); free(w);
        } else {
            SetWindowTextW(hDlg, L"Add Credential");
        }
        SetFocus(GetDlgItem(hDlg, IDC_EDIT_URL));
        return FALSE;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            wchar_t wurl[MAX_URL_LEN + 1] = {0};
            wchar_t wuser[MAX_USERNAME_LEN + 1] = {0};
            wchar_t wpass[MAX_PASSWORD_LEN + 1] = {0};
            GetDlgItemTextW(hDlg, IDC_EDIT_URL, wurl, MAX_URL_LEN + 1);
            GetDlgItemTextW(hDlg, IDC_EDIT_USERNAME, wuser, MAX_USERNAME_LEN + 1);
            GetDlgItemTextW(hDlg, IDC_EDIT_PASSWORD, wpass, MAX_PASSWORD_LEN + 1);

            char url[MAX_URL_LEN + 1] = {0};
            char username[MAX_USERNAME_LEN + 1] = {0};
            char password[MAX_PASSWORD_LEN + 1] = {0};
            wide_to_utf8(wurl, url, sizeof(url));
            wide_to_utf8(wuser, username, sizeof(username));
            wide_to_utf8(wpass, password, sizeof(password));
            SecureZeroMemory(wpass, sizeof(wpass));

            char error_msg[256] = {0};
            if (!cred_validate(url, username, password, error_msg, sizeof(error_msg))) {
                wchar_t *werr = utf8_to_wide(error_msg);
                SetDlgItemTextW(hDlg, IDC_STATIC_ERROR, werr ? werr : L"Invalid input");
                free(werr);
                enc_secure_zero(password, sizeof(password));
                return TRUE;
            }
            strncpy(data->url, url, MAX_URL_LEN);
            strncpy(data->username, username, MAX_USERNAME_LEN);
            strncpy(data->password, password, MAX_PASSWORD_LEN);
            data->success = true;
            enc_secure_zero(password, sizeof(password));
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        case IDCANCEL:
            data->success = false;
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        data->success = false;
        EndDialog(hDlg, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

static void add_label(WORD **ppw, int x, int y, int cx, int cy, WORD id, const wchar_t *text)
{
    #define ALIGN_DWORD(p) (WORD*)(((ULONG_PTR)(p) + 3) & ~3)
    WORD *pw = ALIGN_DWORD(*ppw);
    DLGITEMTEMPLATE *it = (DLGITEMTEMPLATE *)pw;
    it->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    it->x = x; it->y = y; it->cx = cx; it->cy = cy; it->id = id;
    pw = (WORD *)(it + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0082; /* static class */
    if (text) { while (*text) *pw++ = *text++; }
    *pw++ = 0;
    *pw++ = 0;
    *ppw = pw;
    #undef ALIGN_DWORD
}

static void add_edit(WORD **ppw, int x, int y, int cx, int cy, WORD id, DWORD extra)
{
    #define ALIGN_DWORD(p) (WORD*)(((ULONG_PTR)(p) + 3) & ~3)
    WORD *pw = ALIGN_DWORD(*ppw);
    DLGITEMTEMPLATE *it = (DLGITEMTEMPLATE *)pw;
    it->style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL | extra;
    it->x = x; it->y = y; it->cx = cx; it->cy = cy; it->id = id;
    pw = (WORD *)(it + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0081; /* edit class */
    *pw++ = 0;
    *pw++ = 0;
    *ppw = pw;
    #undef ALIGN_DWORD
}

static void add_button(WORD **ppw, int x, int y, int cx, int cy, WORD id, DWORD style, const wchar_t *text)
{
    #define ALIGN_DWORD(p) (WORD*)(((ULONG_PTR)(p) + 3) & ~3)
    WORD *pw = ALIGN_DWORD(*ppw);
    DLGITEMTEMPLATE *it = (DLGITEMTEMPLATE *)pw;
    it->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | style;
    it->x = x; it->y = y; it->cx = cx; it->cy = cy; it->id = id;
    pw = (WORD *)(it + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0080; /* button class */
    if (text) { while (*text) *pw++ = *text++; }
    *pw++ = 0;
    *pw++ = 0;
    *ppw = pw;
    #undef ALIGN_DWORD
}

static INT_PTR ShowCredentialDialog(HWND hwndParent, CredDlgData *data)
{
    BYTE buf[4096] = {0};
    DLGTEMPLATE *pDlg = (DLGTEMPLATE *)buf;
    pDlg->style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE;
    pDlg->cdit = 9;
    pDlg->cx = 260; pDlg->cy = 150;

    WORD *pw = (WORD *)(pDlg + 1);
    *pw++ = 0; *pw++ = 0; *pw++ = 0;

    add_label (&pw, 12, 12, 60, 10, (WORD)-1, L"URL");
    add_edit  (&pw, 76, 10, 172, 14, IDC_EDIT_URL, 0);
    add_label (&pw, 12, 34, 60, 10, (WORD)-1, L"Username");
    add_edit  (&pw, 76, 32, 172, 14, IDC_EDIT_USERNAME, 0);
    add_label (&pw, 12, 56, 60, 10, (WORD)-1, L"Password");
    add_edit  (&pw, 76, 54, 172, 14, IDC_EDIT_PASSWORD, ES_PASSWORD);
    add_label (&pw, 12, 78, 236, 20, IDC_STATIC_ERROR, L"");
    add_button(&pw, 96, 122, 70, 16, IDOK, BS_DEFPUSHBUTTON, L"Save");
    add_button(&pw, 174, 122, 70, 16, IDCANCEL, BS_PUSHBUTTON, L"Cancel");

    return DialogBoxIndirectParamW(GetModuleHandle(NULL), pDlg, hwndParent,
                                   CredentialDlgProc, (LPARAM)data);
}

/* ─── ADB USB Sync ────────────────────────────────────────────────────────── */

static bool adb_run(const char *cmd, const char *output_file)
{
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hStdOut = INVALID_HANDLE_VALUE;
    if (output_file) {
        hStdOut = CreateFileA(output_file, GENERIC_WRITE, 0, &sa,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hStdOut == INVALID_HANDLE_VALUE) return false;
    }

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    if (output_file) {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hStdOut;
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    }
    PROCESS_INFORMATION pi = {0};

    char cmd_buf[2048];
    strncpy(cmd_buf, cmd, sizeof(cmd_buf) - 1);
    cmd_buf[sizeof(cmd_buf) - 1] = '\0';

    BOOL ok = CreateProcessA(NULL, cmd_buf, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!ok) {
        if (hStdOut != INVALID_HANDLE_VALUE) CloseHandle(hStdOut);
        return false;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (hStdOut != INVALID_HANDLE_VALUE) CloseHandle(hStdOut);
    return (exit_code == 0);
}

static bool adb_pull_vault(const char *local_path)
{
    return adb_run("adb exec-out run-as com.passwordmanager cat files/vault.vlt", local_path);
}

static bool adb_push_vault(const char *local_path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "adb push \"%s\" /data/local/tmp/vault_sync.vlt", local_path);
    if (!adb_run(cmd, NULL)) return false;
    return adb_run("adb shell run-as com.passwordmanager cp /data/local/tmp/vault_sync.vlt files/vault.vlt", NULL);
}

static void UI_StartSync(HWND hwndParent)
{
    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
    const char *remote_path = "sync_remote.vlt";

    if (!adb_pull_vault(remote_path)) {
        SetCursor(hOldCursor);
        MessageBoxW(hwndParent,
                    L"Failed to pull vault from phone.\n\n"
                    L"Make sure:\n"
                    L"\u2022 Phone is connected via USB\n"
                    L"\u2022 USB debugging is enabled\n"
                    L"\u2022 ADB is in your PATH\n"
                    L"\u2022 The app is installed on the phone",
                    L"Sync Error", MB_OK | MB_ICONERROR);
        DeleteFileA(remote_path);
        return;
    }

    uint8_t *remote_data = NULL;
    size_t remote_len = 0;
    if (!platform_file_read(remote_path, &remote_data, &remote_len) || remote_len == 0) {
        SetCursor(hOldCursor);
        MessageBoxW(hwndParent,
                    L"Failed to read remote vault file. The phone vault may be empty or corrupted.",
                    L"Sync Error", MB_OK | MB_ICONERROR);
        DeleteFileA(remote_path);
        return;
    }

    if (remote_len < VAULT_HEADER_SIZE) {
        SetCursor(hOldCursor);
        free(remote_data);
        MessageBoxW(hwndParent, L"Remote vault file is too small/corrupted.",
                    L"Sync Error", MB_OK | MB_ICONERROR);
        DeleteFileA(remote_path);
        return;
    }

    uint32_t r_iters = (uint32_t)remote_data[7] | ((uint32_t)remote_data[8] << 8) |
                       ((uint32_t)remote_data[9] << 16) | ((uint32_t)remote_data[10] << 24);
    uint32_t r_mem   = (uint32_t)remote_data[11] | ((uint32_t)remote_data[12] << 8) |
                       ((uint32_t)remote_data[13] << 16) | ((uint32_t)remote_data[14] << 24);
    uint8_t  r_par   = remote_data[15];

    uint8_t remote_salt[ENC_SALT_SIZE];
    memcpy(remote_salt, remote_data + 16, ENC_SALT_SIZE);

    DerivedKey remote_key;
    EncResult enc_res = enc_derive_key_params(g_app.master_password, strlen(g_app.master_password),
                                              remote_salt, r_iters, r_mem, r_par, &remote_key);
    if (enc_res != ENC_OK) {
        SetCursor(hOldCursor);
        free(remote_data);
        MessageBoxW(hwndParent, L"Failed to derive key for remote vault.",
                    L"Sync Error", MB_OK | MB_ICONERROR);
        DeleteFileA(remote_path);
        return;
    }

    Vault remote_vault;
    memset(&remote_vault, 0, sizeof(Vault));
    StoreResult deser_result = vault_deserialize(remote_data, remote_len,
                                                 &remote_key, &remote_vault);
    free(remote_data);
    enc_secure_zero(&remote_key, sizeof(DerivedKey));

    if (deser_result != STORE_OK) {
        SetCursor(hOldCursor);
        MessageBoxW(hwndParent,
                    L"Failed to decrypt remote vault.\n"
                    L"Make sure both devices use the same master password.",
                    L"Sync Error", MB_OK | MB_ICONERROR);
        DeleteFileA(remote_path);
        return;
    }

    SyncSummary summary;
    memset(&summary, 0, sizeof(summary));
    SyncResult sr = sync_merge(&g_app.vault, &remote_vault, true, &summary);
    free(remote_vault.entries);

    if (sr != SYNC_OK) {
        SetCursor(hOldCursor);
        MessageBoxW(hwndParent, L"Merge failed.", L"Sync Error", MB_OK | MB_ICONERROR);
        DeleteFileA(remote_path);
        return;
    }

    if (summary.deleted > 0 && summary.deleted_id_count > 0) {
        wchar_t del_msg[256];
        _snwprintf_s(del_msg, 256, _TRUNCATE,
                     L"The phone deleted %u credential(s).\nAccept deletions?",
                     summary.deleted);
        int confirm = MessageBoxW(hwndParent, del_msg, L"Confirm Deletions",
                                  MB_YESNO | MB_ICONQUESTION);
        if (confirm == IDNO) {
            for (uint32_t i = 0; i < summary.deleted_id_count; i++) {
                for (uint32_t j = 0; j < g_app.vault.count; j++) {
                    if (g_app.vault.entries[j].id == summary.deleted_ids[i]) {
                        g_app.vault.entries[j].deleted = false;
                        g_app.vault.entries[j].modified_at = platform_time_unix();
                        g_app.vault.is_dirty = true;
                        break;
                    }
                }
            }
        }
    }

    uint8_t *merged_data = NULL;
    size_t merged_len = 0;
    StoreResult ser_result = vault_serialize(&g_app.vault, &g_app.derived_key,
                                             &merged_data, &merged_len);
    if (ser_result != STORE_OK) {
        SetCursor(hOldCursor);
        MessageBoxW(hwndParent, L"Failed to serialize merged vault.",
                    L"Sync Error", MB_OK | MB_ICONERROR);
        DeleteFileA(remote_path);
        return;
    }

    platform_file_write_atomic(g_app.vault_path, merged_data, merged_len);
    g_app.vault.is_dirty = false;

    platform_file_write_atomic("vault_push_tmp.vlt", merged_data, merged_len);
    free(merged_data);

    if (!adb_push_vault("vault_push_tmp.vlt")) {
        SetCursor(hOldCursor);
        MessageBoxW(hwndParent,
                    L"Sync merged locally but failed to push to phone.\n"
                    L"The phone vault was not updated.",
                    L"Sync Warning", MB_OK | MB_ICONWARNING);
        DeleteFileA(remote_path);
        DeleteFileA("vault_push_tmp.vlt");
        UI_RefreshCredentialList();
        return;
    }

    DeleteFileA(remote_path);
    DeleteFileA("vault_push_tmp.vlt");
    SetCursor(hOldCursor);

    wchar_t summary_msg[256];
    _snwprintf_s(summary_msg, 256, _TRUNCATE,
                 L"Sync complete!\n\nAdded: %u\nUpdated: %u\nDeleted: %u",
                 summary.added, summary.updated, summary.deleted);
    MessageBoxW(hwndParent, summary_msg, L"Sync Complete", MB_OK | MB_ICONINFORMATION);
    UI_RefreshCredentialList();
}

/* ─── ListView Custom Draw ────────────────────────────────────────────────── */

static LRESULT UI_HandleCustomDraw(LPNMLVCUSTOMDRAW lpcd)
{
    switch (lpcd->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;
    case CDDS_ITEMPREPAINT: {
        int row = (int)lpcd->nmcd.dwItemSpec;
        bool selected = (lpcd->nmcd.uItemState & CDIS_SELECTED) != 0;
        if (selected) {
            lpcd->clrTextBk = CLR_SELECTED;
            lpcd->clrText = CLR_ACCENT;
        } else if (row % 2 == 0) {
            lpcd->clrTextBk = CLR_BG_MAIN;
            lpcd->clrText = CLR_TEXT;
        } else {
            lpcd->clrTextBk = CLR_SURFACE_ALT;
            lpcd->clrText = CLR_TEXT;
        }
        return CDRF_NEWFONT;
    }
    }
    return CDRF_DODEFAULT;
}

/* ─── Layout ──────────────────────────────────────────────────────────────── */

static void UI_LayoutChildren(void)
{
    RECT rc;
    GetClientRect(g_app.hwnd_main, &rc);
    int w = rc.right;
    int h = rc.bottom;

    /* Search box sits in the header, right-aligned. */
    int search_w = 260;
    if (g_app.hwnd_search_edit) {
        MoveWindow(g_app.hwnd_search_edit,
                   w - PADDING - search_w,
                   (HEADER_HEIGHT - SEARCH_HEIGHT) / 2,
                   search_w, SEARCH_HEIGHT, TRUE);
    }

    /* Action bar buttons along the bottom (above status bar). */
    int action_y = h - STATUSBAR_HEIGHT - ACTIONBAR_HEIGHT
                 + (ACTIONBAR_HEIGHT - BTN_HEIGHT) / 2;
    int btn_w = 92;
    int x = PADDING;
    for (int i = 0; i < BTN_COUNT; i++) {
        if (g_app.hwnd_buttons[i]) {
            MoveWindow(g_app.hwnd_buttons[i], x, action_y, btn_w, BTN_HEIGHT, TRUE);
        }
        x += btn_w + BTN_SPACING;
    }

    /* ListView fills the middle. */
    int lv_top = HEADER_HEIGHT;
    int lv_bottom = h - STATUSBAR_HEIGHT - ACTIONBAR_HEIGHT;
    if (g_app.hwnd_listview) {
        MoveWindow(g_app.hwnd_listview, 0, lv_top, w, lv_bottom - lv_top, TRUE);
    }
    if (g_app.hwnd_statusbar) {
        SendMessageW(g_app.hwnd_statusbar, WM_SIZE, 0, 0);
    }
}

/* ─── Header Painting ─────────────────────────────────────────────────────── */

static void UI_PaintHeader(HDC hdc, int w)
{
    RECT hdr = {0, 0, w, HEADER_HEIGHT};
    FillRect(hdc, &hdr, g_app.hbr_header);

    /* App icon */
    if (g_app.hicon_app) {
        DrawIconEx(hdc, PADDING, (HEADER_HEIGHT - 28) / 2,
                   g_app.hicon_app, 28, 28, 0, NULL, DI_NORMAL);
    }

    /* Title */
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, CLR_TEXT);
    HFONT old = (HFONT)SelectObject(hdc, g_app.hfont_title ? g_app.hfont_title : g_app.hfont_ui);
    RECT tr = {PADDING + 40, 0, w / 2, HEADER_HEIGHT};
    DrawTextW(hdc, APP_TITLE, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, old);

    /* Thin accent divider under header */
    HPEN pen = CreatePen(PS_SOLID, 1, CLR_BORDER);
    HPEN oldp = (HPEN)SelectObject(hdc, pen);
    MoveToEx(hdc, 0, HEADER_HEIGHT - 1, NULL);
    LineTo(hdc, w, HEADER_HEIGHT - 1);
    SelectObject(hdc, oldp);
    DeleteObject(pen);
}

/* ─── Main Window Procedure ───────────────────────────────────────────────── */

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        UI_EnableDarkTitleBar(hwnd);

        g_app.hfont_ui = UI_CreateFontPx(-14, FW_NORMAL);   /* ~10.5pt */
        g_app.hfont_title = UI_CreateFontPx(-19, FW_SEMIBOLD); /* header title */

        g_app.hbr_bg = CreateSolidBrush(CLR_BG_MAIN);
        g_app.hbr_header = CreateSolidBrush(CLR_BG_HEADER);
        g_app.hbr_surface = CreateSolidBrush(CLR_SURFACE);

        /* Search box (in header) */
        g_app.hwnd_search_edit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            0, 0, 260, SEARCH_HEIGHT,
            hwnd, (HMENU)(UINT_PTR)IDC_EDIT_SEARCH, GetModuleHandle(NULL), NULL);
        SendMessageW(g_app.hwnd_search_edit, WM_SETFONT, (WPARAM)g_app.hfont_ui, TRUE);
        SendMessageW(g_app.hwnd_search_edit, EM_SETCUEBANNER, TRUE, (LPARAM)L"Search URL...");

        /* Action bar buttons */
        static const wchar_t *btn_labels[BTN_COUNT] = {L"Add", L"Edit", L"Delete", L"Sync", L"Lock"};
        static const int btn_ids[BTN_COUNT] = {IDC_BTN_ADD, IDC_BTN_EDIT, IDC_BTN_DELETE, IDC_BTN_SYNC, IDC_BTN_LOCK};
        for (int i = 0; i < BTN_COUNT; i++) {
            g_app.hwnd_buttons[i] = CreateWindowExW(
                0, L"BUTTON", btn_labels[i],
                WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                0, 0, 92, BTN_HEIGHT,
                hwnd, (HMENU)(UINT_PTR)btn_ids[i], GetModuleHandle(NULL), NULL);
            SendMessageW(g_app.hwnd_buttons[i], WM_SETFONT, (WPARAM)g_app.hfont_ui, TRUE);
            SetWindowSubclass(g_app.hwnd_buttons[i], ButtonSubclassProc, (UINT_PTR)i, 0);
        }

        /* ListView */
        g_app.hwnd_listview = CreateWindowExW(
            0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            0, HEADER_HEIGHT, 100, 100,
            hwnd, (HMENU)(UINT_PTR)IDC_LISTVIEW, GetModuleHandle(NULL), NULL);
        SendMessageW(g_app.hwnd_listview, WM_SETFONT, (WPARAM)g_app.hfont_ui, TRUE);
        ListView_SetupCols(g_app.hwnd_listview);

        /* Status bar */
        g_app.hwnd_statusbar = CreateWindowExW(
            0, STATUSCLASSNAMEW, NULL, WS_CHILD | WS_VISIBLE,
            0, 0, 0, 0, hwnd, (HMENU)(UINT_PTR)IDC_STATUSBAR, GetModuleHandle(NULL), NULL);
        SendMessageW(g_app.hwnd_statusbar, WM_SETFONT, (WPARAM)g_app.hfont_ui, TRUE);

        SetTimer(hwnd, IDT_CLIPBOARD_TIMER, IDT_CLIP_INTERVAL, NULL);

        UI_LayoutChildren();
        UI_RefreshCredentialList();
        UI_UpdateStatusBar();
        return 0;
    }

    case WM_SIZE:
        UI_LayoutChildren();
        return 0;

    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wParam;
        RECT rc; GetClientRect(hwnd, &rc);
        /* Body */
        RECT body = {0, HEADER_HEIGHT, rc.right, rc.bottom - STATUSBAR_HEIGHT - ACTIONBAR_HEIGHT};
        FillRect(hdc, &body, g_app.hbr_bg);
        /* Action bar */
        RECT action = {0, rc.bottom - STATUSBAR_HEIGHT - ACTIONBAR_HEIGHT, rc.right, rc.bottom - STATUSBAR_HEIGHT};
        FillRect(hdc, &action, g_app.hbr_header);
        /* Header (with icon + title) */
        UI_PaintHeader(hdc, rc.right);
        return 1;
    }

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, CLR_TEXT);
        SetBkColor(hdc, CLR_SURFACE);
        return (LRESULT)g_app.hbr_surface;
    }

    case WM_TIMER:
        if (wParam == IDT_CLIPBOARD_TIMER) {
            clip_tick();
            UI_UpdateStatusBar();
        } else if (wParam == IDT_COPIED_TIMER) {
            KillTimer(hwnd, IDT_COPIED_TIMER);
            g_app.show_copied_msg = false;
            UI_UpdateStatusBar();
        }
        return 0;

    case WM_NOTIFY: {
        LPNMHDR pnmh = (LPNMHDR)lParam;
        if (pnmh->idFrom == IDC_LISTVIEW) {
            switch (pnmh->code) {
            case NM_CUSTOMDRAW:
                return UI_HandleCustomDraw((LPNMLVCUSTOMDRAW)lParam);
            case NM_DBLCLK:
                UI_HandleListViewDblClick(hwnd, (LPNMITEMACTIVATE)lParam);
                return 0;
            }
        }
        break;
    }

    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT pDIS = (LPDRAWITEMSTRUCT)lParam;
        if (pDIS->CtlType == ODT_BUTTON) return TRUE;
        break;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_ADD: {
            CredDlgData dlg = {0};
            dlg.is_edit = false;
            ShowCredentialDialog(hwnd, &dlg);
            if (dlg.success) {
                CredResult cr = cred_add(&g_app.vault, dlg.url, dlg.username, dlg.password);
                enc_secure_zero(dlg.password, sizeof(dlg.password));
                if (cr == CRED_OK) { UI_AutoSave(); UI_RefreshCredentialList(); }
                else MessageBoxW(hwnd, L"Failed to add credential.", L"Error", MB_OK | MB_ICONERROR);
            }
            return 0;
        }
        case IDC_BTN_EDIT: {
            int id = UI_GetSelectedCredentialId();
            if (id < 0) { MessageBoxW(hwnd, L"Please select a credential to edit.", L"No Selection", MB_OK | MB_ICONINFORMATION); return 0; }
            Credential *cred = cred_get(&g_app.vault, (uint32_t)id);
            if (!cred) { MessageBoxW(hwnd, L"Credential not found.", L"Error", MB_OK | MB_ICONERROR); return 0; }
            CredDlgData dlg = {0};
            dlg.is_edit = true;
            dlg.cred_id = (uint32_t)id;
            strncpy(dlg.url, cred->url, MAX_URL_LEN);
            strncpy(dlg.username, cred->username, MAX_USERNAME_LEN);
            strncpy(dlg.password, cred->password, MAX_PASSWORD_LEN);
            ShowCredentialDialog(hwnd, &dlg);
            if (dlg.success) {
                CredResult cr = cred_edit(&g_app.vault, (uint32_t)id, dlg.url, dlg.username, dlg.password);
                enc_secure_zero(dlg.password, sizeof(dlg.password));
                if (cr == CRED_OK) { UI_AutoSave(); UI_RefreshCredentialList(); }
                else MessageBoxW(hwnd, L"Failed to edit credential.", L"Error", MB_OK | MB_ICONERROR);
            }
            return 0;
        }
        case IDC_BTN_DELETE: {
            int id = UI_GetSelectedCredentialId();
            if (id < 0) { MessageBoxW(hwnd, L"Please select a credential to delete.", L"No Selection", MB_OK | MB_ICONINFORMATION); return 0; }
            int confirm = MessageBoxW(hwnd,
                L"Are you sure you want to delete this credential?\nThis action cannot be undone.",
                L"Confirm Delete", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);
            if (confirm == IDYES) {
                CredResult cr = cred_delete(&g_app.vault, (uint32_t)id);
                if (cr == CRED_OK) { UI_AutoSave(); UI_RefreshCredentialList(); }
                else MessageBoxW(hwnd, L"Failed to delete credential.", L"Error", MB_OK | MB_ICONERROR);
            }
            return 0;
        }
        case IDC_BTN_SYNC:
            UI_StartSync(hwnd);
            return 0;
        case IDC_BTN_LOCK:
            UI_AutoSave();
            UI_LockVault();
            return 0;

        case IDC_EDIT_SEARCH:
            if (HIWORD(wParam) == EN_CHANGE) {
                wchar_t wquery[256] = {0};
                GetWindowTextW(g_app.hwnd_search_edit, wquery, 256);
                char query[512] = {0};
                wide_to_utf8(wquery, query, sizeof(query));
                if (query[0]) {
                    Credential *results = NULL;
                    uint32_t rc = 0;
                    if (cred_search(&g_app.vault, query, &results, &rc) == CRED_OK) {
                        ListView_DeleteAllItems(g_app.hwnd_listview);
                        for (uint32_t i = 0; i < rc; i++) {
                            UI_AddRow(g_app.hwnd_listview, (int)i, &results[i]);
                        }
                        free(results);
                    }
                } else {
                    UI_RefreshCredentialList();
                }
            }
            return 0;
        }
        break;

    case WM_DESTROY:
        KillTimer(hwnd, IDT_CLIPBOARD_TIMER);
        KillTimer(hwnd, IDT_COPIED_TIMER);
        UI_AutoSave();
        if (g_app.vault.entries) {
            enc_secure_zero(g_app.vault.entries, g_app.vault.capacity * sizeof(Credential));
            free(g_app.vault.entries);
            g_app.vault.entries = NULL;
        }
        enc_secure_zero(&g_app.derived_key, sizeof(DerivedKey));
        enc_secure_zero(g_app.master_password, sizeof(g_app.master_password));
        clip_clear();
        if (g_app.hfont_ui) DeleteObject(g_app.hfont_ui);
        if (g_app.hfont_title) DeleteObject(g_app.hfont_title);
        if (g_app.hbr_bg) DeleteObject(g_app.hbr_bg);
        if (g_app.hbr_header) DeleteObject(g_app.hbr_header);
        if (g_app.hbr_surface) DeleteObject(g_app.hbr_surface);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* ─── WinMain ─────────────────────────────────────────────────────────────── */

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;
    (void)lpCmdLine;

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES };
    InitCommonControlsEx(&icc);

    strncpy(g_app.vault_path, VAULT_FILE_PATH, MAX_PATH - 1);

    /* Load the branded app icon from resources (falls back to default). */
    g_app.hicon_app = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_APPICON),
                                        IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED);
    if (!g_app.hicon_app) {
        g_app.hicon_app = LoadIcon(NULL, IDI_APPLICATION);
    }

    bool vault_exists = store_exists(g_app.vault_path);
    if (!vault_exists) {
        int choice = MessageBoxW(NULL,
            L"No vault file found. Would you like to create a new vault?",
            APP_TITLE, MB_YESNO | MB_ICONQUESTION);
        if (choice != IDYES) return 0;
        if (!UI_CreateNewVault(NULL)) {
            MessageBoxW(NULL, L"Vault creation cancelled.",
                        APP_TITLE, MB_OK | MB_ICONINFORMATION);
            return 0;
        }
    } else {
        if (!UI_UnlockVault(NULL)) return 0;
    }

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL;
    wc.lpszClassName = APP_CLASS_NAME;
    wc.hIcon = g_app.hicon_app ? g_app.hicon_app : LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm = wc.hIcon;

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(NULL, L"Failed to register window class.", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    g_app.hwnd_main = CreateWindowExW(
        0, APP_CLASS_NAME, APP_TITLE, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 940, 620,
        NULL, NULL, hInstance, NULL);
    if (!g_app.hwnd_main) {
        MessageBoxW(NULL, L"Failed to create main window.", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(g_app.hwnd_main, nCmdShow);
    UpdateWindow(g_app.hwnd_main);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}

#endif /* _WIN32 */
