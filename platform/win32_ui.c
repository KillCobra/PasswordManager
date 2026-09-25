
/**
 * win32_ui.c - Modern Dark-Themed Win32 GUI for Password Manager
 *
 * Features:
 * - Dark theme with custom-drawn ListView (alternating rows, no grid lines)
 * - Owner-drawn flat buttons with hover effects
 * - Double-click-to-copy on ListView cells (URL, Username, Password)
 * - Dark title bar via DwmSetWindowAttribute
 * - "Copied!" notification in status bar
 * - Segoe UI 10pt font throughout
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "credential.h"
#include "vault.h"
#include "encryption.h"
#include "sync.h"
#include "platform.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "dwmapi.lib")

/* ─── Dark Theme Colors ───────────────────────────────────────────────────── */

#define CLR_BG_MAIN        RGB(0x1E, 0x1E, 0x2E)  /* #1E1E2E */
#define CLR_BG_ALT         RGB(0x18, 0x18, 0x25)  /* #181825 */
#define CLR_TEXT            RGB(0xCD, 0xD6, 0xF4)  /* #CDD6F4 */
#define CLR_ACCENT         RGB(0x89, 0xB4, 0xFA)  /* #89B4FA */
#define CLR_BTN_BG         RGB(0x31, 0x31, 0x44)  /* Button normal */
#define CLR_BTN_HOVER      RGB(0x45, 0x47, 0x5A)  /* Button hover */
#define CLR_BTN_TEXT       RGB(0xCD, 0xD6, 0xF4)  /* Button text */
#define CLR_HEADER_BG      RGB(0x11, 0x11, 0x1B)  /* ListView header */
#define CLR_SELECTED       RGB(0x45, 0x47, 0x5A)  /* Selected row */
#define CLR_STATUSBAR_BG   RGB(0x11, 0x11, 0x1B)  /* Status bar */

/* ─── Constants ───────────────────────────────────────────────────────────── */

#define APP_CLASS_NAME      "ROMPasswordManager"
#define APP_TITLE           "ROM Password Manager"
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
#define IDT_CLIP_INTERVAL   1000  /* 1 second */
#define IDT_COPIED_TIMER    2002
#define IDT_COPIED_DURATION 2000  /* 2 seconds */

/* Dialog control IDs */
#define IDC_EDIT_URL        3001
#define IDC_EDIT_USERNAME   3002
#define IDC_EDIT_PASSWORD   3003
#define IDC_STATIC_ERROR    3004
#define IDC_EDIT_MASTER_PW  3005
#define IDC_STATIC_DELAY    3006

/* DWMWA_USE_IMMERSIVE_DARK_MODE - available on Windows 10 build 17763+ */
#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

/* Toolbar dimensions */
#define TOOLBAR_HEIGHT      44
#define BTN_WIDTH           70
#define BTN_HEIGHT          30
#define BTN_SPACING         8
#define BTN_MARGIN_LEFT     12
#define BTN_MARGIN_TOP      7

/* ─── Application State ───────────────────────────────────────────────────── */

typedef struct {
    Vault vault;
    DerivedKey derived_key;
    char master_password[MAX_PASSWORD_LEN + 1]; /* Kept in memory for sync re-derivation */
    bool is_unlocked;
    bool is_new_vault;
    HWND hwnd_main;
    HWND hwnd_listview;
    HWND hwnd_statusbar;
    HWND hwnd_buttons[5]; /* Add, Edit, Delete, Sync, Lock */
    HWND hwnd_search_edit;
    HWND hwnd_search_btn;
    HFONT hfont_ui;
    HBRUSH hbr_bg;
    HBRUSH hbr_alt;
    HBRUSH hbr_toolbar;
    bool show_copied_msg;
    int hover_button; /* index of hovered button, -1 if none */
    char vault_path[MAX_PATH];
} AppState;

static AppState g_app = {0};

/* ─── Forward Declarations ────────────────────────────────────────────────── */

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
static INT_PTR CALLBACK MasterPasswordDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);
static INT_PTR CALLBACK CredentialDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);

static void UI_RefreshCredentialList(void);
static void UI_UpdateStatusBar(void);
static bool UI_UnlockVault(HWND hwndParent);
static bool UI_CreateNewVault(HWND hwndParent);
static void UI_AutoSave(void);
static void UI_LockVault(void);
static int  UI_GetSelectedCredentialId(void);
static void UI_CopyAndNotify(HWND hwnd, const char *text, size_t len);
static void UI_HandleListViewDblClick(HWND hwnd, LPNMITEMACTIVATE pnmia);

/* ─── Dark Title Bar ──────────────────────────────────────────────────────── */

static void UI_EnableDarkTitleBar(HWND hwnd)
{
    BOOL value = TRUE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &value, sizeof(value));
}

/* ─── Font Creation ───────────────────────────────────────────────────────── */

static HFONT UI_CreateFont(void)
{
    return CreateFontA(
        -13,            /* 10pt at 96 DPI */
        0, 0, 0,
        FW_NORMAL,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_SWISS,
        "Segoe UI"
    );
}

/* ─── Owner-Drawn Button Subclass ─────────────────────────────────────────── */

static LRESULT CALLBACK ButtonSubclassProc(HWND hwnd, UINT msg,
                                            WPARAM wParam, LPARAM lParam,
                                            UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
    (void)uIdSubclass;
    (void)dwRefData;

    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rc;
        GetClientRect(hwnd, &rc);

        /* Determine if this button is hovered */
        POINT pt;
        GetCursorPos(&pt);
        ScreenToClient(hwnd, &pt);
        bool hovered = PtInRect(&rc, pt);

        /* Fill background */
        HBRUSH hbr = CreateSolidBrush(hovered ? CLR_BTN_HOVER : CLR_BTN_BG);
        FillRect(hdc, &rc, hbr);
        DeleteObject(hbr);

        /* Draw rounded border with accent on hover */
        HPEN hpen = CreatePen(PS_SOLID, 1, hovered ? CLR_ACCENT : CLR_BTN_BG);
        HPEN old_pen = (HPEN)SelectObject(hdc, hpen);
        HBRUSH old_br = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
        RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 6, 6);
        SelectObject(hdc, old_pen);
        SelectObject(hdc, old_br);
        DeleteObject(hpen);

        /* Draw text */
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, CLR_BTN_TEXT);
        HFONT old_font = (HFONT)SelectObject(hdc, g_app.hfont_ui);

        char text[64] = {0};
        GetWindowTextA(hwnd, text, sizeof(text));
        DrawTextA(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        SelectObject(hdc, old_font);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_MOUSEMOVE: {
        /* Track mouse for hover effect */
        TRACKMOUSEEVENT tme = {0};
        tme.cbSize = sizeof(tme);
        tme.dwFlags = TME_LEAVE;
        tme.hwndTrack = hwnd;
        TrackMouseEvent(&tme);
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }

    case WM_MOUSELEAVE:
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;

    case WM_ERASEBKGND:
        return 1; /* Prevent flicker */

    case WM_NCDESTROY:
        RemoveWindowSubclass(hwnd, ButtonSubclassProc, uIdSubclass);
        break;
    }

    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

/* ─── ListView Helpers ────────────────────────────────────────────────────── */

static void ListView_Setup(HWND hwndLV)
{
    /* Full row select, no grid lines */
    ListView_SetExtendedListViewStyle(hwndLV,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

    /* Set dark background and text colors */
    ListView_SetBkColor(hwndLV, CLR_BG_MAIN);
    ListView_SetTextBkColor(hwndLV, CLR_BG_MAIN);
    ListView_SetTextColor(hwndLV, CLR_TEXT);

    /* Add columns: URL, Username, Password */
    LVCOLUMNA col = {0};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    col.iSubItem = 0;
    col.pszText = "URL";
    col.cx = 320;
    ListView_InsertColumn(hwndLV, 0, &col);

    col.iSubItem = 1;
    col.pszText = "Username";
    col.cx = 220;
    ListView_InsertColumn(hwndLV, 1, &col);

    col.iSubItem = 2;
    col.pszText = "Password";
    col.cx = 140;
    ListView_InsertColumn(hwndLV, 2, &col);
}

static void UI_RefreshCredentialList(void)
{
    if (!g_app.hwnd_listview) return;

    ListView_DeleteAllItems(g_app.hwnd_listview);

    /* Sort credentials alphabetically by URL */
    cred_sort_by_url(&g_app.vault);

    LVITEMA item = {0};
    item.mask = LVIF_TEXT | LVIF_PARAM;

    for (uint32_t i = 0; i < g_app.vault.count; i++) {
        Credential *cred = &g_app.vault.entries[i];
        if (cred->deleted) continue;

        item.iItem = (int)i;
        item.iSubItem = 0;
        item.pszText = cred->url;
        item.lParam = (LPARAM)cred->id;
        int idx = ListView_InsertItem(g_app.hwnd_listview, &item);

        /* Username column */
        ListView_SetItemText(g_app.hwnd_listview, idx, 1, cred->username);

        /* Password column (masked) */
        ListView_SetItemText(g_app.hwnd_listview, idx, 2, "\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2");
    }
}

static int UI_GetSelectedCredentialId(void)
{
    int sel = ListView_GetNextItem(g_app.hwnd_listview, -1, LVNI_SELECTED);
    if (sel < 0) return -1;

    LVITEMA item = {0};
    item.mask = LVIF_PARAM;
    item.iItem = sel;
    ListView_GetItem(g_app.hwnd_listview, &item);
    return (int)item.lParam;
}

/* ─── Copy and Notify ─────────────────────────────────────────────────────── */

static void UI_CopyAndNotify(HWND hwnd, const char *text, size_t len)
{
    ClipResult cr = clip_copy(text, len);
    if (cr == CLIP_OK) {
        g_app.show_copied_msg = true;
        SendMessageA(g_app.hwnd_statusbar, SB_SETTEXTA, 0, (LPARAM)"Copied!");
        SetTimer(hwnd, IDT_COPIED_TIMER, IDT_COPIED_DURATION, NULL);
    }
}

/* ─── Double-Click Handler ────────────────────────────────────────────────── */

static void UI_HandleListViewDblClick(HWND hwnd, LPNMITEMACTIVATE pnmia)
{
    if (pnmia->iItem < 0) return;

    /* Get credential ID from the clicked item */
    LVITEMA item = {0};
    item.mask = LVIF_PARAM;
    item.iItem = pnmia->iItem;
    ListView_GetItem(g_app.hwnd_listview, &item);
    int cred_id = (int)item.lParam;

    Credential *cred = cred_get(&g_app.vault, (uint32_t)cred_id);
    if (!cred) return;

    /* Determine which column was double-clicked using SubItemHitTest */
    LVHITTESTINFO ht = {0};
    ht.pt = pnmia->ptAction;
    ListView_SubItemHitTest(g_app.hwnd_listview, &ht);

    switch (ht.iSubItem) {
    case 0: /* URL */
        UI_CopyAndNotify(hwnd, cred->url, strlen(cred->url));
        break;
    case 1: /* Username */
        UI_CopyAndNotify(hwnd, cred->username, strlen(cred->username));
        break;
    case 2: /* Password (actual, not masked) */
        UI_CopyAndNotify(hwnd, cred->password, strlen(cred->password));
        break;
    }
}

/* ─── Status Bar ──────────────────────────────────────────────────────────── */

static void UI_UpdateStatusBar(void)
{
    if (!g_app.hwnd_statusbar) return;
    if (g_app.show_copied_msg) return; /* Don't overwrite "Copied!" message */

    uint32_t remaining = clip_get_remaining_seconds();
    char status_text[128];

    if (remaining > 0) {
        snprintf(status_text, sizeof(status_text),
                 "  Clipboard clears in %u seconds", remaining);
    } else {
        snprintf(status_text, sizeof(status_text),
                 "  Ready  |  Credentials: %u  |  Double-click to copy",
                 g_app.vault.count);
    }

    SendMessageA(g_app.hwnd_statusbar, SB_SETTEXTA, 0, (LPARAM)status_text);
}

/* ─── Auto-Save ───────────────────────────────────────────────────────────── */

static void UI_AutoSave(void)
{
    if (!g_app.vault.is_dirty) return;

    uint8_t *data = NULL;
    size_t len = 0;

    StoreResult sr = vault_serialize(&g_app.vault, &g_app.derived_key, &data, &len);
    if (sr != STORE_OK) {
        MessageBoxA(g_app.hwnd_main,
                    "Failed to serialize vault. Changes may not be saved.",
                    "Save Error", MB_OK | MB_ICONERROR);
        return;
    }

    sr = store_save(g_app.vault_path, data, len);
    free(data);

    if (sr != STORE_OK) {
        MessageBoxA(g_app.hwnd_main,
                    "Failed to write vault file. Changes may not be saved.",
                    "Save Error", MB_OK | MB_ICONERROR);
    } else {
        g_app.vault.is_dirty = false;
    }
}

/* ─── Lock Vault ──────────────────────────────────────────────────────────── */

static void UI_LockVault(void)
{
    /* Clear all decrypted credential data from memory */
    if (g_app.vault.entries) {
        enc_secure_zero(g_app.vault.entries,
                        g_app.vault.capacity * sizeof(Credential));
        free(g_app.vault.entries);
        g_app.vault.entries = NULL;
    }
    g_app.vault.count = 0;
    g_app.vault.capacity = 0;
    g_app.vault.is_dirty = false;

    /* Clear derived key and master password */
    enc_secure_zero(&g_app.derived_key, sizeof(DerivedKey));
    enc_secure_zero(g_app.master_password, sizeof(g_app.master_password));

    g_app.is_unlocked = false;

    /* Clear the list view */
    if (g_app.hwnd_listview) {
        ListView_DeleteAllItems(g_app.hwnd_listview);
    }

    /* Clear clipboard */
    clip_clear();

    /* Show unlock dialog again */
    if (!UI_UnlockVault(g_app.hwnd_main)) {
        PostQuitMessage(0);
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
    MasterPwDlgData *data = (MasterPwDlgData *)GetWindowLongPtrA(hDlg, GWLP_USERDATA);

    switch (msg) {
    case WM_INITDIALOG:
        data = (MasterPwDlgData *)lParam;
        SetWindowLongPtrA(hDlg, GWLP_USERDATA, (LONG_PTR)data);

        if (data->is_create) {
            SetWindowTextA(hDlg, "Create New Vault");
            SetDlgItemTextA(hDlg, IDC_STATIC_DELAY,
                            "Enter a master password (minimum 8 characters):");
        } else {
            SetWindowTextA(hDlg, "Unlock Vault");
            uint32_t failures = master_password_get_failure_count();
            if (failures > 0) {
                char msg_buf[128];
                snprintf(msg_buf, sizeof(msg_buf),
                         "Enter master password (delay: %u sec after failure):",
                         failures);
                SetDlgItemTextA(hDlg, IDC_STATIC_DELAY, msg_buf);
            } else {
                SetDlgItemTextA(hDlg, IDC_STATIC_DELAY,
                                "Enter your master password:");
            }
        }

        SetFocus(GetDlgItem(hDlg, IDC_EDIT_MASTER_PW));
        return FALSE;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            char pw[MAX_PASSWORD_LEN + 1] = {0};
            GetDlgItemTextA(hDlg, IDC_EDIT_MASTER_PW, pw, sizeof(pw));
            size_t pw_len = strlen(pw);

            if (data->is_create) {
                if (!master_password_validate(pw, pw_len)) {
                    SetDlgItemTextA(hDlg, IDC_STATIC_ERROR,
                                    "Password must be at least 8 characters.");
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
    BYTE buf[2048] = {0};
    DLGTEMPLATE *pDlg = (DLGTEMPLATE *)buf;

    pDlg->style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE;
    pDlg->dwExtendedStyle = 0;
    pDlg->cdit = 5;
    pDlg->x = 0; pDlg->y = 0;
    pDlg->cx = 220; pDlg->cy = 100;

    WORD *pw = (WORD *)(pDlg + 1);
    *pw++ = 0; /* No menu */
    *pw++ = 0; /* Default window class */
    *pw++ = 0; /* Empty title */

    #define ALIGN_DWORD(p) (BYTE*)(((ULONG_PTR)(p) + 3) & ~3)

    /* Static label (IDC_STATIC_DELAY) */
    pw = (WORD *)ALIGN_DWORD(pw);
    DLGITEMTEMPLATE *pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    pItem->dwExtendedStyle = 0;
    pItem->x = 10; pItem->y = 10; pItem->cx = 200; pItem->cy = 12;
    pItem->id = IDC_STATIC_DELAY;
    pw = (WORD *)(pItem + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0082;
    *pw++ = 0; *pw++ = 0;

    /* Edit box (IDC_EDIT_MASTER_PW) */
    pw = (WORD *)ALIGN_DWORD(pw);
    pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL;
    pItem->dwExtendedStyle = 0;
    pItem->x = 10; pItem->y = 26; pItem->cx = 200; pItem->cy = 14;
    pItem->id = IDC_EDIT_MASTER_PW;
    pw = (WORD *)(pItem + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0081;
    *pw++ = 0; *pw++ = 0;

    /* Error label (IDC_STATIC_ERROR) */
    pw = (WORD *)ALIGN_DWORD(pw);
    pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    pItem->dwExtendedStyle = 0;
    pItem->x = 10; pItem->y = 44; pItem->cx = 200; pItem->cy = 12;
    pItem->id = IDC_STATIC_ERROR;
    pw = (WORD *)(pItem + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0082;
    *pw++ = 0; *pw++ = 0;

    /* OK button */
    pw = (WORD *)ALIGN_DWORD(pw);
    pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON;
    pItem->dwExtendedStyle = 0;
    pItem->x = 60; pItem->y = 70; pItem->cx = 50; pItem->cy = 14;
    pItem->id = IDOK;
    pw = (WORD *)(pItem + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0080;
    *pw++ = 'O'; *pw++ = 'K'; *pw++ = 0;
    *pw++ = 0;

    /* Cancel button */
    pw = (WORD *)ALIGN_DWORD(pw);
    pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON;
    pItem->dwExtendedStyle = 0;
    pItem->x = 120; pItem->y = 70; pItem->cx = 50; pItem->cy = 14;
    pItem->id = IDCANCEL;
    pw = (WORD *)(pItem + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0080;
    *pw++ = 'C'; *pw++ = 'a'; *pw++ = 'n'; *pw++ = 'c';
    *pw++ = 'e'; *pw++ = 'l'; *pw++ = 0;
    *pw++ = 0;

    #undef ALIGN_DWORD

    return DialogBoxIndirectParamA(
        GetModuleHandle(NULL),
        pDlg,
        hwndParent,
        MasterPasswordDlgProc,
        (LPARAM)data
    );
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

        /* Enforce progressive delay */
        uint32_t failures = master_password_get_failure_count();
        if (failures > 0) {
            platform_sleep_ms(failures * 1000);
        }

        /* Load vault file */
        uint8_t *file_data = NULL;
        size_t file_len = 0;
        StoreResult sr = store_load(g_app.vault_path, &file_data, &file_len);
        if (sr != STORE_OK) {
            MessageBoxA(hwndParent, "Failed to read vault file.",
                        "Error", MB_OK | MB_ICONERROR);
            enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));
            return false;
        }

        if (file_len < VAULT_HEADER_SIZE) {
            free(file_data);
            MessageBoxA(hwndParent, "Vault file is corrupted.",
                        "Error", MB_OK | MB_ICONERROR);
            enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));
            return false;
        }

        uint8_t salt[ENC_SALT_SIZE];
        memcpy(salt, file_data + 16, ENC_SALT_SIZE);

        EncResult er = enc_derive_key(dlg_data.password, strlen(dlg_data.password),
                                      salt, &g_app.derived_key);
        if (er != ENC_OK) {
            free(file_data);
            MessageBoxA(hwndParent, "Key derivation failed.",
                        "Error", MB_OK | MB_ICONERROR);
            enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));
            return false;
        }

        sr = vault_deserialize(file_data, file_len, &g_app.derived_key, &g_app.vault);
        free(file_data);

        if (sr == STORE_OK) {
            master_password_record_success();
            /* Store password for sync re-derivation */
            strncpy(g_app.master_password, dlg_data.password, MAX_PASSWORD_LEN);
            g_app.master_password[MAX_PASSWORD_LEN] = '\0';
            enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));
            g_app.is_unlocked = true;
            return true;
        } else {
            master_password_record_failure();
            enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));
            enc_secure_zero(&g_app.derived_key, sizeof(DerivedKey));

            uint32_t new_failures = master_password_get_failure_count();
            char err_msg[128];
            snprintf(err_msg, sizeof(err_msg),
                     "Incorrect password. Next attempt delayed %u second(s).",
                     new_failures);
            MessageBoxA(hwndParent, err_msg, "Authentication Failed",
                        MB_OK | MB_ICONWARNING);
        }
    }
}

static bool UI_CreateNewVault(HWND hwndParent)
{
    MasterPwDlgData dlg_data = {0};
    dlg_data.is_create = true;

    INT_PTR result = ShowMasterPasswordDialog(hwndParent, &dlg_data);
    if (result == IDCANCEL || !dlg_data.success) {
        return false;
    }

    uint8_t salt[ENC_SALT_SIZE];
    if (!platform_random_bytes(salt, ENC_SALT_SIZE)) {
        MessageBoxA(hwndParent, "Failed to generate random salt.",
                    "Error", MB_OK | MB_ICONERROR);
        enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));
        return false;
    }

    EncResult er = enc_derive_key(dlg_data.password, strlen(dlg_data.password),
                                  salt, &g_app.derived_key);

    /* Store password for sync re-derivation */
    strncpy(g_app.master_password, dlg_data.password, MAX_PASSWORD_LEN);
    g_app.master_password[MAX_PASSWORD_LEN] = '\0';
    enc_secure_zero(dlg_data.password, sizeof(dlg_data.password));

    if (er != ENC_OK) {
        MessageBoxA(hwndParent, "Key derivation failed.",
                    "Error", MB_OK | MB_ICONERROR);
        return false;
    }

    g_app.vault.entries = (Credential *)calloc(MAX_CREDENTIALS, sizeof(Credential));
    if (!g_app.vault.entries) {
        MessageBoxA(hwndParent, "Memory allocation failed.",
                    "Error", MB_OK | MB_ICONERROR);
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
    CredDlgData *data = (CredDlgData *)GetWindowLongPtrA(hDlg, GWLP_USERDATA);

    switch (msg) {
    case WM_INITDIALOG:
        data = (CredDlgData *)lParam;
        SetWindowLongPtrA(hDlg, GWLP_USERDATA, (LONG_PTR)data);

        if (data->is_edit) {
            SetWindowTextA(hDlg, "Edit Credential");
            SetDlgItemTextA(hDlg, IDC_EDIT_URL, data->url);
            SetDlgItemTextA(hDlg, IDC_EDIT_USERNAME, data->username);
            SetDlgItemTextA(hDlg, IDC_EDIT_PASSWORD, data->password);
        } else {
            SetWindowTextA(hDlg, "Add Credential");
        }

        SetFocus(GetDlgItem(hDlg, IDC_EDIT_URL));
        return FALSE;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            char url[MAX_URL_LEN + 1] = {0};
            char username[MAX_USERNAME_LEN + 1] = {0};
            char password[MAX_PASSWORD_LEN + 1] = {0};

            GetDlgItemTextA(hDlg, IDC_EDIT_URL, url, sizeof(url));
            GetDlgItemTextA(hDlg, IDC_EDIT_USERNAME, username, sizeof(username));
            GetDlgItemTextA(hDlg, IDC_EDIT_PASSWORD, password, sizeof(password));

            char error_msg[256] = {0};
            if (!cred_validate(url, username, password, error_msg, sizeof(error_msg))) {
                SetDlgItemTextA(hDlg, IDC_STATIC_ERROR, error_msg);
                return TRUE;
            }

            strncpy(data->url, url, MAX_URL_LEN);
            strncpy(data->username, username, MAX_USERNAME_LEN);
            strncpy(data->password, password, MAX_PASSWORD_LEN);
            data->success = true;

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

static INT_PTR ShowCredentialDialog(HWND hwndParent, CredDlgData *data)
{
    BYTE buf[4096] = {0};
    DLGTEMPLATE *pDlg = (DLGTEMPLATE *)buf;

    pDlg->style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE;
    pDlg->dwExtendedStyle = 0;
    pDlg->cdit = 9;
    pDlg->x = 0; pDlg->y = 0;
    pDlg->cx = 260; pDlg->cy = 150;

    WORD *pw = (WORD *)(pDlg + 1);
    *pw++ = 0; *pw++ = 0; *pw++ = 0;

    #define ALIGN_DWORD(p) (BYTE*)(((ULONG_PTR)(p) + 3) & ~3)

    /* Static: "URL:" */
    pw = (WORD *)ALIGN_DWORD(pw);
    DLGITEMTEMPLATE *pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    pItem->x = 10; pItem->y = 10; pItem->cx = 50; pItem->cy = 10;
    pItem->id = (WORD)-1;
    pw = (WORD *)(pItem + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0082;
    *pw++ = 'U'; *pw++ = 'R'; *pw++ = 'L'; *pw++ = ':'; *pw++ = 0;
    *pw++ = 0;

    /* Edit: URL */
    pw = (WORD *)ALIGN_DWORD(pw);
    pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL;
    pItem->x = 70; pItem->y = 8; pItem->cx = 180; pItem->cy = 14;
    pItem->id = IDC_EDIT_URL;
    pw = (WORD *)(pItem + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0081;
    *pw++ = 0; *pw++ = 0;

    /* Static: "Username:" */
    pw = (WORD *)ALIGN_DWORD(pw);
    pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    pItem->x = 10; pItem->y = 30; pItem->cx = 55; pItem->cy = 10;
    pItem->id = (WORD)-1;
    pw = (WORD *)(pItem + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0082;
    *pw++ = 'U'; *pw++ = 's'; *pw++ = 'e'; *pw++ = 'r'; *pw++ = 'n';
    *pw++ = 'a'; *pw++ = 'm'; *pw++ = 'e'; *pw++ = ':'; *pw++ = 0;
    *pw++ = 0;

    /* Edit: Username */
    pw = (WORD *)ALIGN_DWORD(pw);
    pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL;
    pItem->x = 70; pItem->y = 28; pItem->cx = 180; pItem->cy = 14;
    pItem->id = IDC_EDIT_USERNAME;
    pw = (WORD *)(pItem + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0081;
    *pw++ = 0; *pw++ = 0;

    /* Static: "Password:" */
    pw = (WORD *)ALIGN_DWORD(pw);
    pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    pItem->x = 10; pItem->y = 50; pItem->cx = 55; pItem->cy = 10;
    pItem->id = (WORD)-1;
    pw = (WORD *)(pItem + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0082;
    *pw++ = 'P'; *pw++ = 'a'; *pw++ = 's'; *pw++ = 's'; *pw++ = 'w';
    *pw++ = 'o'; *pw++ = 'r'; *pw++ = 'd'; *pw++ = ':'; *pw++ = 0;
    *pw++ = 0;

    /* Edit: Password */
    pw = (WORD *)ALIGN_DWORD(pw);
    pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL;
    pItem->x = 70; pItem->y = 48; pItem->cx = 180; pItem->cy = 14;
    pItem->id = IDC_EDIT_PASSWORD;
    pw = (WORD *)(pItem + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0081;
    *pw++ = 0; *pw++ = 0;

    /* Static: Error message */
    pw = (WORD *)ALIGN_DWORD(pw);
    pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    pItem->x = 10; pItem->y = 70; pItem->cx = 240; pItem->cy = 20;
    pItem->id = IDC_STATIC_ERROR;
    pw = (WORD *)(pItem + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0082;
    *pw++ = 0; *pw++ = 0;

    /* OK button */
    pw = (WORD *)ALIGN_DWORD(pw);
    pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON;
    pItem->x = 90; pItem->y = 120; pItem->cx = 50; pItem->cy = 14;
    pItem->id = IDOK;
    pw = (WORD *)(pItem + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0080;
    *pw++ = 'O'; *pw++ = 'K'; *pw++ = 0;
    *pw++ = 0;

    /* Cancel button */
    pw = (WORD *)ALIGN_DWORD(pw);
    pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON;
    pItem->x = 150; pItem->y = 120; pItem->cx = 50; pItem->cy = 14;
    pItem->id = IDCANCEL;
    pw = (WORD *)(pItem + 1);
    *pw++ = 0xFFFF; *pw++ = 0x0080;
    *pw++ = 'C'; *pw++ = 'a'; *pw++ = 'n'; *pw++ = 'c';
    *pw++ = 'e'; *pw++ = 'l'; *pw++ = 0;
    *pw++ = 0;

    #undef ALIGN_DWORD

    return DialogBoxIndirectParamA(
        GetModuleHandle(NULL),
        pDlg,
        hwndParent,
        CredentialDlgProc,
        (LPARAM)data
    );
}

/* ─── ADB USB Sync ────────────────────────────────────────────────────────── */

/**
 * Run an ADB command via CreateProcessA with no console window.
 * If output_file is not NULL, stdout is redirected to that file.
 * Returns true if the process exits with code 0.
 */
static bool adb_run(const char *cmd, const char *output_file)
{
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hStdOut = INVALID_HANDLE_VALUE;

    if (output_file) {
        hStdOut = CreateFileA(output_file, GENERIC_WRITE, 0, &sa,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hStdOut == INVALID_HANDLE_VALUE) {
            return false;
        }
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

    /* CreateProcessA needs a mutable command string */
    char cmd_buf[2048];
    strncpy(cmd_buf, cmd, sizeof(cmd_buf) - 1);
    cmd_buf[sizeof(cmd_buf) - 1] = '\0';

    BOOL ok = CreateProcessA(
        NULL, cmd_buf, NULL, NULL, TRUE,
        CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi
    );

    if (!ok) {
        if (hStdOut != INVALID_HANDLE_VALUE) CloseHandle(hStdOut);
        return false;
    }

    WaitForSingleObject(pi.hProcess, 30000); /* 30 second timeout */

    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (hStdOut != INVALID_HANDLE_VALUE) CloseHandle(hStdOut);

    return (exit_code == 0);
}

/**
 * Pull the vault from the phone via ADB.
 * Uses: adb exec-out run-as com.passwordmanager cat files/vault.vlt
 * Stdout is redirected to local_path.
 */
static bool adb_pull_vault(const char *local_path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "adb exec-out run-as com.passwordmanager cat files/vault.vlt");
    return adb_run(cmd, local_path);
}

/**
 * Push the vault to the phone via ADB.
 * Step 1: adb push <local_path> /data/local/tmp/vault_sync.vlt
 * Step 2: adb shell run-as com.passwordmanager cp /data/local/tmp/vault_sync.vlt files/vault.vlt
 */
static bool adb_push_vault(const char *local_path)
{
    char cmd[512];

    /* Step 1: Push to temp location */
    snprintf(cmd, sizeof(cmd),
             "adb push \"%s\" /data/local/tmp/vault_sync.vlt", local_path);
    if (!adb_run(cmd, NULL)) {
        return false;
    }

    /* Step 2: Copy into app's private directory */
    snprintf(cmd, sizeof(cmd),
             "adb shell run-as com.passwordmanager cp /data/local/tmp/vault_sync.vlt files/vault.vlt");
    return adb_run(cmd, NULL);
}

static void UI_StartSync(HWND hwndParent)
{
    /* Show wait cursor */
    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));

    /* Step 1: Pull remote vault from phone */
    const char *remote_path = "sync_remote.vlt";
    if (!adb_pull_vault(remote_path)) {
        SetCursor(hOldCursor);
        MessageBoxA(hwndParent,
                    "Failed to pull vault from phone.\n\n"
                    "Make sure:\n"
                    "- Phone is connected via USB\n"
                    "- USB debugging is enabled\n"
                    "- ADB is in your PATH\n"
                    "- The app is installed on the phone",
                    "Sync Error", MB_OK | MB_ICONERROR);
        DeleteFileA(remote_path);
        return;
    }

    /* Step 2: Load and deserialize the remote vault */
    uint8_t *remote_data = NULL;
    size_t remote_len = 0;
    if (!platform_file_read(remote_path, &remote_data, &remote_len) || remote_len == 0) {
        SetCursor(hOldCursor);
        MessageBoxA(hwndParent,
                    "Failed to read remote vault file. The phone vault may be empty or corrupted.",
                    "Sync Error", MB_OK | MB_ICONERROR);
        DeleteFileA(remote_path);
        return;
    }

    /* The remote vault has its own salt — derive a key using our password + remote salt */
    if (remote_len < VAULT_HEADER_SIZE) {
        SetCursor(hOldCursor);
        free(remote_data);
        MessageBoxA(hwndParent, "Remote vault file is too small/corrupted.",
                    "Sync Error", MB_OK | MB_ICONERROR);
        DeleteFileA(remote_path);
        return;
    }

    uint8_t remote_salt[ENC_SALT_SIZE];
    memcpy(remote_salt, remote_data + 16, ENC_SALT_SIZE); /* Salt at header offset 16 */

    DerivedKey remote_key;
    EncResult enc_res = enc_derive_key(g_app.master_password, strlen(g_app.master_password),
                                       remote_salt, &remote_key);
    if (enc_res != ENC_OK) {
        SetCursor(hOldCursor);
        free(remote_data);
        MessageBoxA(hwndParent, "Failed to derive key for remote vault.",
                    "Sync Error", MB_OK | MB_ICONERROR);
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
        MessageBoxA(hwndParent,
                    "Failed to decrypt remote vault.\n"
                    "Make sure both devices use the same master password.",
                    "Sync Error", MB_OK | MB_ICONERROR);
        DeleteFileA(remote_path);
        return;
    }

    /* Step 3: Merge remote into local (desktop is initiator) */
    SyncSummary summary;
    memset(&summary, 0, sizeof(summary));
    SyncResult sr = sync_merge(&g_app.vault, &remote_vault, true, &summary);
    free(remote_vault.entries);

    if (sr != SYNC_OK) {
        SetCursor(hOldCursor);
        MessageBoxA(hwndParent, "Merge failed.", "Sync Error", MB_OK | MB_ICONERROR);
        DeleteFileA(remote_path);
        return;
    }

    /* Step 4: If there were deletions, ask the user to confirm */
    if (summary.deleted > 0 && summary.deleted_id_count > 0) {
        char del_msg[512];
        snprintf(del_msg, sizeof(del_msg),
                 "The phone deleted %u credential(s).\n"
                 "Accept deletions?",
                 summary.deleted);

        int confirm = MessageBoxA(hwndParent, del_msg, "Confirm Deletions",
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

    /* Step 5: Serialize the merged vault */
    uint8_t *merged_data = NULL;
    size_t merged_len = 0;
    StoreResult ser_result = vault_serialize(&g_app.vault, &g_app.derived_key,
                                             &merged_data, &merged_len);
    if (ser_result != STORE_OK) {
        SetCursor(hOldCursor);
        MessageBoxA(hwndParent, "Failed to serialize merged vault.",
                    "Sync Error", MB_OK | MB_ICONERROR);
        DeleteFileA(remote_path);
        return;
    }

    /* Step 6: Save merged vault locally */
    platform_file_write_atomic(g_app.vault_path, merged_data, merged_len);
    g_app.vault.is_dirty = false;

    /* Step 7: Push merged vault to phone */
    /* Write merged data to a temp file for pushing */
    platform_file_write_atomic("vault_push_tmp.vlt", merged_data, merged_len);
    free(merged_data);

    if (!adb_push_vault("vault_push_tmp.vlt")) {
        SetCursor(hOldCursor);
        MessageBoxA(hwndParent,
                    "Sync merged locally but failed to push to phone.\n"
                    "The phone vault was not updated.",
                    "Sync Warning", MB_OK | MB_ICONWARNING);
        DeleteFileA(remote_path);
        DeleteFileA("vault_push_tmp.vlt");
        UI_RefreshCredentialList();
        return;
    }

    /* Step 8: Clean up temp files */
    DeleteFileA(remote_path);
    DeleteFileA("vault_push_tmp.vlt");

    SetCursor(hOldCursor);

    /* Step 9: Show summary */
    char summary_msg[256];
    snprintf(summary_msg, sizeof(summary_msg),
             "Sync complete!\n\n"
             "Added: %u\nUpdated: %u\nDeleted: %u",
             summary.added, summary.updated, summary.deleted);
    MessageBoxA(hwndParent, summary_msg, "Sync Complete", MB_OK | MB_ICONINFORMATION);

    /* Step 10: Refresh the credential list */
    UI_RefreshCredentialList();
}

/* ─── ListView Custom Draw (Dark Theme + Alternating Rows) ────────────────── */

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
            lpcd->clrTextBk = CLR_BG_ALT;
            lpcd->clrText = CLR_TEXT;
        }
        return CDRF_NEWFONT;
    }
    }

    return CDRF_DODEFAULT;
}

/* ─── Main Window Procedure ───────────────────────────────────────────────── */

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg,
                                     WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        /* Enable dark title bar */
        UI_EnableDarkTitleBar(hwnd);

        /* Create UI font */
        g_app.hfont_ui = UI_CreateFont();

        /* Create brushes */
        g_app.hbr_bg = CreateSolidBrush(CLR_BG_MAIN);
        g_app.hbr_alt = CreateSolidBrush(CLR_BG_ALT);
        g_app.hbr_toolbar = CreateSolidBrush(CLR_HEADER_BG);

        /* Create toolbar buttons: [+ Add] [Edit] [Delete] [Sync] [Lock] */
        static const char *btn_labels[] = {"+ Add", "Edit", "Delete", "Sync", "Lock"};
        static const int btn_ids[] = {IDC_BTN_ADD, IDC_BTN_EDIT, IDC_BTN_DELETE, IDC_BTN_SYNC, IDC_BTN_LOCK};
        int btn_x = BTN_MARGIN_LEFT;

        for (int i = 0; i < 5; i++) {
            int w = (i == 0) ? BTN_WIDTH + 10 : BTN_WIDTH; /* "+ Add" is slightly wider */
            g_app.hwnd_buttons[i] = CreateWindowExA(
                0, "BUTTON", btn_labels[i],
                WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                btn_x, BTN_MARGIN_TOP, w, BTN_HEIGHT,
                hwnd, (HMENU)(UINT_PTR)btn_ids[i],
                GetModuleHandle(NULL), NULL
            );
            SendMessageA(g_app.hwnd_buttons[i], WM_SETFONT, (WPARAM)g_app.hfont_ui, TRUE);
            SetWindowSubclass(g_app.hwnd_buttons[i], ButtonSubclassProc, (UINT_PTR)i, 0);
            btn_x += w + BTN_SPACING;
        }

        /* Create ListView */
        btn_x += 20; /* Extra spacing before search */

        /* Create search edit box */
        g_app.hwnd_search_edit = CreateWindowExA(
            WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            btn_x, BTN_MARGIN_TOP + 2, 180, BTN_HEIGHT - 4,
            hwnd, (HMENU)(UINT_PTR)IDC_EDIT_SEARCH,
            GetModuleHandle(NULL), NULL
        );
        SendMessageA(g_app.hwnd_search_edit, WM_SETFONT, (WPARAM)g_app.hfont_ui, TRUE);
        SendMessageA(g_app.hwnd_search_edit, EM_SETCUEBANNER, TRUE, (LPARAM)L"Search URL...");
        btn_x += 180 + BTN_SPACING;

        /* Create search/clear button */
        g_app.hwnd_search_btn = CreateWindowExA(
            0, "BUTTON", "X",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            btn_x, BTN_MARGIN_TOP, 30, BTN_HEIGHT,
            hwnd, (HMENU)(UINT_PTR)IDC_BTN_SEARCH,
            GetModuleHandle(NULL), NULL
        );
        SendMessageA(g_app.hwnd_search_btn, WM_SETFONT, (WPARAM)g_app.hfont_ui, TRUE);
        SetWindowSubclass(g_app.hwnd_search_btn, ButtonSubclassProc, 5, 0);

        RECT rc;
        GetClientRect(hwnd, &rc);

        g_app.hwnd_listview = CreateWindowExA(
            0,
            WC_LISTVIEWA,
            "",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            0, TOOLBAR_HEIGHT, rc.right, rc.bottom - TOOLBAR_HEIGHT - 22,
            hwnd,
            (HMENU)(UINT_PTR)IDC_LISTVIEW,
            GetModuleHandle(NULL),
            NULL
        );

        SendMessageA(g_app.hwnd_listview, WM_SETFONT, (WPARAM)g_app.hfont_ui, TRUE);
        ListView_Setup(g_app.hwnd_listview);

        /* Create Status Bar */
        g_app.hwnd_statusbar = CreateWindowExA(
            0,
            STATUSCLASSNAMEA,
            NULL,
            WS_CHILD | WS_VISIBLE,
            0, 0, 0, 0,
            hwnd,
            (HMENU)(UINT_PTR)IDC_STATUSBAR,
            GetModuleHandle(NULL),
            NULL
        );
        SendMessageA(g_app.hwnd_statusbar, WM_SETFONT, (WPARAM)g_app.hfont_ui, TRUE);

        /* Start clipboard countdown timer */
        SetTimer(hwnd, IDT_CLIPBOARD_TIMER, IDT_CLIP_INTERVAL, NULL);

        /* Populate credential list */
        UI_RefreshCredentialList();
        UI_UpdateStatusBar();

        return 0;
    }

    case WM_SIZE: {
        RECT rc;
        GetClientRect(hwnd, &rc);

        if (g_app.hwnd_listview) {
            MoveWindow(g_app.hwnd_listview, 0, TOOLBAR_HEIGHT,
                       rc.right, rc.bottom - TOOLBAR_HEIGHT - 22, TRUE);
        }
        if (g_app.hwnd_statusbar) {
            SendMessageA(g_app.hwnd_statusbar, WM_SIZE, 0, 0);
        }
        return 0;
    }

    case WM_ERASEBKGND: {
        /* Paint the toolbar area with dark background */
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        RECT toolbar_rc = {0, 0, rc.right, TOOLBAR_HEIGHT};
        FillRect(hdc, &toolbar_rc, g_app.hbr_toolbar);
        /* Fill rest with main bg */
        RECT body_rc = {0, TOOLBAR_HEIGHT, rc.right, rc.bottom};
        FillRect(hdc, &body_rc, g_app.hbr_bg);
        return 1;
    }

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, CLR_TEXT);
        SetBkColor(hdc, CLR_BG_MAIN);
        return (LRESULT)g_app.hbr_bg;
    }

    case WM_TIMER:
        if (wParam == IDT_CLIPBOARD_TIMER) {
            clip_tick();
            UI_UpdateStatusBar();
        } else if (wParam == IDT_COPIED_TIMER) {
            /* "Copied!" message expired, revert to normal status */
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
        /* Owner-draw for buttons is handled by subclass, but we need to
           return TRUE to indicate we handled it */
        LPDRAWITEMSTRUCT pDIS = (LPDRAWITEMSTRUCT)lParam;
        if (pDIS->CtlType == ODT_BUTTON) {
            return TRUE;
        }
        break;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_ADD: {
            CredDlgData dlg_data = {0};
            dlg_data.is_edit = false;

            ShowCredentialDialog(hwnd, &dlg_data);
            if (dlg_data.success) {
                CredResult cr = cred_add(&g_app.vault,
                                         dlg_data.url,
                                         dlg_data.username,
                                         dlg_data.password);
                if (cr == CRED_OK) {
                    UI_AutoSave();
                    UI_RefreshCredentialList();
                } else {
                    MessageBoxA(hwnd, "Failed to add credential.",
                                "Error", MB_OK | MB_ICONERROR);
                }
            }
            return 0;
        }

        case IDC_BTN_EDIT: {
            int cred_id = UI_GetSelectedCredentialId();
            if (cred_id < 0) {
                MessageBoxA(hwnd, "Please select a credential to edit.",
                            "No Selection", MB_OK | MB_ICONINFORMATION);
                return 0;
            }

            Credential *cred = cred_get(&g_app.vault, (uint32_t)cred_id);
            if (!cred) {
                MessageBoxA(hwnd, "Credential not found.",
                            "Error", MB_OK | MB_ICONERROR);
                return 0;
            }

            CredDlgData dlg_data = {0};
            dlg_data.is_edit = true;
            dlg_data.cred_id = (uint32_t)cred_id;
            strncpy(dlg_data.url, cred->url, MAX_URL_LEN);
            strncpy(dlg_data.username, cred->username, MAX_USERNAME_LEN);
            strncpy(dlg_data.password, cred->password, MAX_PASSWORD_LEN);

            ShowCredentialDialog(hwnd, &dlg_data);
            if (dlg_data.success) {
                CredResult cr = cred_edit(&g_app.vault, (uint32_t)cred_id,
                                          dlg_data.url,
                                          dlg_data.username,
                                          dlg_data.password);
                if (cr == CRED_OK) {
                    UI_AutoSave();
                    UI_RefreshCredentialList();
                } else {
                    MessageBoxA(hwnd, "Failed to edit credential.",
                                "Error", MB_OK | MB_ICONERROR);
                }
            }
            return 0;
        }

        case IDC_BTN_DELETE: {
            int cred_id = UI_GetSelectedCredentialId();
            if (cred_id < 0) {
                MessageBoxA(hwnd, "Please select a credential to delete.",
                            "No Selection", MB_OK | MB_ICONINFORMATION);
                return 0;
            }

            int confirm = MessageBoxA(hwnd,
                "Are you sure you want to delete this credential?\n"
                "This action cannot be undone.",
                "Confirm Delete",
                MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);

            if (confirm == IDYES) {
                CredResult cr = cred_delete(&g_app.vault, (uint32_t)cred_id);
                if (cr == CRED_OK) {
                    UI_AutoSave();
                    UI_RefreshCredentialList();
                } else {
                    MessageBoxA(hwnd, "Failed to delete credential.",
                                "Error", MB_OK | MB_ICONERROR);
                }
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

        case IDC_BTN_SEARCH: {
            /* Clear search and refresh full list */
            SetWindowTextA(g_app.hwnd_search_edit, "");
            UI_RefreshCredentialList();
            return 0;
        }

        case IDC_EDIT_SEARCH: {
            /* Handle EN_CHANGE notification for live search */
            if (HIWORD(wParam) == EN_CHANGE) {
                char query[256] = {0};
                GetWindowTextA(g_app.hwnd_search_edit, query, sizeof(query));
                if (strlen(query) > 0) {
                    /* Search and display filtered results */
                    Credential *results = NULL;
                    uint32_t result_count = 0;
                    CredResult cr = cred_search(&g_app.vault, query, &results, &result_count);
                    if (cr == CRED_OK) {
                        ListView_DeleteAllItems(g_app.hwnd_listview);
                        LVITEMA item = {0};
                        item.mask = LVIF_TEXT | LVIF_PARAM;
                        for (uint32_t i = 0; i < result_count; i++) {
                            item.iItem = (int)i;
                            item.iSubItem = 0;
                            item.pszText = results[i].url;
                            item.lParam = (LPARAM)results[i].id;
                            int idx = ListView_InsertItem(g_app.hwnd_listview, &item);
                            ListView_SetItemText(g_app.hwnd_listview, idx, 1, results[i].username);
                            ListView_SetItemText(g_app.hwnd_listview, idx, 2,
                                "\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2");
                        }
                        free(results);
                    }
                } else {
                    UI_RefreshCredentialList();
                }
            }
            return 0;
        }
        }
        break;

    case WM_DESTROY:
        KillTimer(hwnd, IDT_CLIPBOARD_TIMER);
        KillTimer(hwnd, IDT_COPIED_TIMER);
        UI_AutoSave();

        /* Securely clear sensitive data */
        if (g_app.vault.entries) {
            enc_secure_zero(g_app.vault.entries,
                            g_app.vault.capacity * sizeof(Credential));
            free(g_app.vault.entries);
            g_app.vault.entries = NULL;
        }
        enc_secure_zero(&g_app.derived_key, sizeof(DerivedKey));
        enc_secure_zero(g_app.master_password, sizeof(g_app.master_password));

        clip_clear();

        /* Clean up GDI objects */
        if (g_app.hfont_ui) DeleteObject(g_app.hfont_ui);
        if (g_app.hbr_bg) DeleteObject(g_app.hbr_bg);
        if (g_app.hbr_alt) DeleteObject(g_app.hbr_alt);
        if (g_app.hbr_toolbar) DeleteObject(g_app.hbr_toolbar);

        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* ─── WinMain Entry Point ─────────────────────────────────────────────────── */

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;
    (void)lpCmdLine;

    /* Initialize Common Controls (for ListView, StatusBar) */
    INITCOMMONCONTROLSEX icc = {0};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);

    /* Set vault file path */
    strncpy(g_app.vault_path, VAULT_FILE_PATH, MAX_PATH - 1);

    /* Check if vault exists */
    bool vault_exists = store_exists(g_app.vault_path);

    if (!vault_exists) {
        int choice = MessageBoxA(NULL,
            "No vault file found. Would you like to create a new vault?",
            APP_TITLE,
            MB_YESNO | MB_ICONQUESTION);

        if (choice != IDYES) {
            return 0;
        }

        if (!UI_CreateNewVault(NULL)) {
            MessageBoxA(NULL, "Vault creation cancelled.",
                        APP_TITLE, MB_OK | MB_ICONINFORMATION);
            return 0;
        }
    } else {
        if (!UI_UnlockVault(NULL)) {
            return 0;
        }
    }

    /* Register window class */
    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL; /* We handle painting ourselves */
    wc.lpszClassName = APP_CLASS_NAME;
    /* TODO: Replace with custom .ico resource for branded app icon.
     * Add a .rc file with: IDI_APPICON ICON "app_icon.ico"
     * Then use: wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APPICON)); */
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassExA(&wc)) {
        MessageBoxA(NULL, "Failed to register window class.",
                    "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    /* Create main window */
    g_app.hwnd_main = CreateWindowExA(
        0,
        APP_CLASS_NAME,
        APP_TITLE,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        900, 600,
        NULL, NULL,
        hInstance,
        NULL
    );

    if (!g_app.hwnd_main) {
        MessageBoxA(NULL, "Failed to create main window.",
                    "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(g_app.hwnd_main, nCmdShow);
    UpdateWindow(g_app.hwnd_main);

    /* Message loop */
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return (int)msg.wParam;
}

#endif /* _WIN32 */