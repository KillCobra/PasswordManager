
package com.passwordmanager;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.google.android.material.floatingactionbutton.FloatingActionButton;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends Activity {

    private String vaultPath;
    private ListView listView;
    private FloatingActionButton fabAdd;
    private FloatingActionButton fabSearch;
    private LinearLayout searchBar;
    private EditText editSearch;
    private ImageButton btnClearSearch;
    private CredentialAdapter adapter;
    private final List<CredentialEntry> credentials = new ArrayList<>();
    private boolean searchVisible = false;

    private static class CredentialEntry {
        int id;
        String url;
        String username;
        String password;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        vaultPath = new File(getFilesDir(), "vault.vlt").getAbsolutePath();

        listView = findViewById(R.id.credential_list);
        fabAdd = findViewById(R.id.fab_add);
        fabSearch = findViewById(R.id.fab_search);
        searchBar = findViewById(R.id.search_bar);
        editSearch = findViewById(R.id.edit_search);
        btnClearSearch = findViewById(R.id.btn_clear_search);

        adapter = new CredentialAdapter();
        listView.setAdapter(adapter);

        listView.setOnItemClickListener((parent, view, position, id) -> showDetailDialog(position));
        listView.setOnItemLongClickListener((parent, view, position, id) -> {
            copyPassword(position);
            return true;
        });

        fabAdd.setOnClickListener(v -> showAddDialog());
        fabSearch.setOnClickListener(v -> toggleSearch());

        btnClearSearch.setOnClickListener(v -> {
            editSearch.setText("");
            toggleSearch();
            refreshCredentials();
        });

        editSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                performSearch(s.toString());
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });

        // Hide UI until unlocked
        listView.setVisibility(View.GONE);
        fabAdd.setVisibility(View.GONE);
        fabSearch.setVisibility(View.GONE);

        showMasterPasswordDialog();
    }

    @Override
    protected void onStop() {
        super.onStop();
        NativeLib.nativeLockVault();
    }

    /* ─── Search ──────────────────────────────────────────────────────────── */

    private void toggleSearch() {
        searchVisible = !searchVisible;
        searchBar.setVisibility(searchVisible ? View.VISIBLE : View.GONE);
        if (searchVisible) {
            editSearch.requestFocus();
            showKeyboard(editSearch);
        } else {
            editSearch.setText("");
            hideKeyboard(editSearch);
        }
    }

    private void showKeyboard(View view) {
        // Post so the view is laid out/focusable before we request the IME.
        view.post(() -> {
            view.requestFocus();
            InputMethodManager imm =
                    (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
            if (imm != null) {
                imm.showSoftInput(view, InputMethodManager.SHOW_IMPLICIT);
            }
        });
    }

    private void hideKeyboard(View view) {
        InputMethodManager imm =
                (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
        if (imm != null) {
            imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
        }
    }

    private void performSearch(String query) {
        credentials.clear();
        if (query.isEmpty()) {
            // Show all
            String[] raw = NativeLib.nativeGetAllCredentials();
            if (raw != null) {
                parseCredentials(raw);
            }
        } else {
            // Search by URL
            String[] raw = NativeLib.nativeSearchCredentials(query);
            if (raw != null) {
                parseCredentials(raw);
            }
        }
        adapter.notifyDataSetChanged();
    }

    /* ─── Master Password ─────────────────────────────────────────────────── */

    private void showMasterPasswordDialog() {
        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_master_password, null);
        EditText editPassword = dialogView.findViewById(R.id.edit_master_password);

        boolean vaultExists = new File(vaultPath).exists();

        new AlertDialog.Builder(this)
                .setTitle(vaultExists ? "Unlock Vault" : "Create Vault")
                .setView(dialogView)
                .setCancelable(false)
                .setPositiveButton("Unlock", (dialog, which) -> {
                    String password = editPassword.getText().toString();
                    if (password.isEmpty()) {
                        Toast.makeText(this, "Password cannot be empty", Toast.LENGTH_SHORT).show();
                        showMasterPasswordDialog();
                        return;
                    }
                    hideKeyboard(editPassword);
                    unlockWithLoader(password, vaultExists);
                })
                .setNegativeButton("Exit", (dialog, which) -> finish())
                .show();
    }

    /**
     * Run vault creation/unlock off the UI thread while showing a loader, so the
     * user gets immediate feedback that their tap registered (Argon2id key
     * derivation takes a moment) rather than a frozen screen.
     */
    private void unlockWithLoader(String password, boolean vaultExists) {
        AlertDialog loader = buildLoaderDialog(vaultExists ? "Unlocking vault..." : "Creating vault...");
        loader.show();

        ExecutorService exec = Executors.newSingleThreadExecutor();
        Handler main = new Handler(Looper.getMainLooper());
        exec.execute(() -> {
            boolean success;
            if (!vaultExists) {
                success = NativeLib.nativeCreateVault(vaultPath, password);
                if (success) {
                    success = NativeLib.nativeUnlockVault(vaultPath, password);
                }
            } else {
                success = NativeLib.nativeUnlockVault(vaultPath, password);
            }
            final boolean ok = success;
            main.post(() -> {
                loader.dismiss();
                if (ok) {
                    listView.setVisibility(View.VISIBLE);
                    fabAdd.setVisibility(View.VISIBLE);
                    fabSearch.setVisibility(View.VISIBLE);
                    refreshCredentials();
                } else {
                    Toast.makeText(this, "Incorrect password or vault error", Toast.LENGTH_SHORT).show();
                    showMasterPasswordDialog();
                }
            });
            exec.shutdown();
        });
    }

    /** A small non-cancelable dialog with a spinner + message. */
    private AlertDialog buildLoaderDialog(String message) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        int pad = (int) (24 * getResources().getDisplayMetrics().density);
        row.setPadding(pad, pad, pad, pad);

        ProgressBar spinner = new ProgressBar(this);
        int sz = (int) (28 * getResources().getDisplayMetrics().density);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(sz, sz);
        sp.rightMargin = pad;
        row.addView(spinner, sp);

        TextView tv = new TextView(this);
        tv.setText(message);
        tv.setTextColor(0xFFCDD6F4);
        tv.setTextSize(16);
        row.addView(tv);

        return new AlertDialog.Builder(this)
                .setView(row)
                .setCancelable(false)
                .create();
    }

    /* ─── Credential Management ───────────────────────────────────────────── */

    private void refreshCredentials() {
        credentials.clear();
        String[] raw = NativeLib.nativeGetAllCredentials();
        if (raw != null) {
            parseCredentials(raw);
        }
        adapter.notifyDataSetChanged();
    }

    private void parseCredentials(String[] raw) {
        for (String entry : raw) {
            String[] parts = entry.split("\\|", 4);
            if (parts.length == 4) {
                CredentialEntry ce = new CredentialEntry();
                ce.id = Integer.parseInt(parts[0]);
                ce.url = parts[1];
                ce.username = parts[2];
                ce.password = parts[3];
                credentials.add(ce);
            }
        }
    }

    private void showAddDialog() {
        showCredentialDialog("Add Credential", "", "", "", (url, username, password) -> {
            boolean ok = NativeLib.nativeAddCredential(url, username, password);
            if (ok) {
                refreshCredentials();
            } else {
                Toast.makeText(this, "Failed to add credential", Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void showEditDialog(int position) {
        CredentialEntry ce = credentials.get(position);
        showCredentialDialog("Edit Credential", ce.url, ce.username, ce.password,
                (url, username, password) -> {
                    boolean ok = NativeLib.nativeEditCredential(ce.id, url, username, password);
                    if (ok) {
                        refreshCredentials();
                    } else {
                        Toast.makeText(this, "Failed to edit credential", Toast.LENGTH_SHORT).show();
                    }
                });
    }

    private void showDetailDialog(int position) {
        CredentialEntry ce = credentials.get(position);

        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_credential, null);
        EditText editUrl = dialogView.findViewById(R.id.edit_url);
        EditText editUsername = dialogView.findViewById(R.id.edit_username);
        EditText editPassword = dialogView.findViewById(R.id.edit_password);

        editUrl.setText(ce.url);
        editUsername.setText(ce.username);
        editPassword.setText(ce.password);
        editUrl.setEnabled(false);

        // Username: read-only, tap to copy (keeps a clean 3-button action row
        // while still offering "copy username").
        editUsername.setEnabled(true);
        editUsername.setFocusable(false);
        editUsername.setFocusableInTouchMode(false);
        editUsername.setCursorVisible(false);
        editUsername.setLongClickable(false);
        editUsername.setOnClickListener(v -> {
            copyToClipboard(ce.username);
            Toast.makeText(this, "Username copied", Toast.LENGTH_SHORT).show();
        });

        // Mask the password with dots by default. Applying the transformation
        // method explicitly (rather than relying on inputType alone) ensures the
        // field stays masked even though it is read-only here.
        editPassword.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        editPassword.setTransformationMethod(PasswordTransformationMethod.getInstance());

        // Password: read-only; tap toggles reveal/hide.
        editPassword.setEnabled(true);
        editPassword.setFocusable(false);
        editPassword.setFocusableInTouchMode(false);
        editPassword.setCursorVisible(false);
        editPassword.setLongClickable(false);
        final boolean[] revealed = { false };
        editPassword.setOnClickListener(v -> {
            revealed[0] = !revealed[0];
            editPassword.setTransformationMethod(revealed[0]
                    ? HideReturnsTransformationMethod.getInstance()
                    : PasswordTransformationMethod.getInstance());
        });

        new AlertDialog.Builder(this)
                .setTitle("Credential Details")
                .setMessage("Tap the username to copy it. Tap the password to reveal it.")
                .setView(dialogView)
                .setPositiveButton("Copy Password", (dialog, which) -> {
                    copyToClipboard(ce.password);
                    Toast.makeText(this, "Password copied", Toast.LENGTH_SHORT).show();
                })
                .setNeutralButton("Edit", (dialog, which) -> showEditDialog(position))
                .setNegativeButton("Delete", (dialog, which) -> {
                    NativeLib.nativeDeleteCredential(ce.id);
                    refreshCredentials();
                })
                .show();
    }

    private void showCredentialDialog(String title, String url, String username, String password,
                                      CredentialCallback callback) {
        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_credential, null);
        EditText editUrl = dialogView.findViewById(R.id.edit_url);
        EditText editUsername = dialogView.findViewById(R.id.edit_username);
        EditText editPassword = dialogView.findViewById(R.id.edit_password);

        editUrl.setText(url);
        editUsername.setText(username);
        editPassword.setText(password);

        new AlertDialog.Builder(this)
                .setTitle(title)
                .setView(dialogView)
                .setPositiveButton("Save", (dialog, which) -> {
                    String u = editUrl.getText().toString();
                    String un = editUsername.getText().toString();
                    String pw = editPassword.getText().toString();
                    callback.onSave(u, un, pw);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    /* ─── Clipboard ───────────────────────────────────────────────────────── */

    private void copyPassword(int position) {
        CredentialEntry ce = credentials.get(position);
        copyToClipboard(ce.password);
        Toast.makeText(this, "Password copied", Toast.LENGTH_SHORT).show();
    }

    private void copyToClipboard(String text) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null) {
            clipboard.setPrimaryClip(ClipData.newPlainText("credential", text));
        }
    }

    /* ─── Interfaces & Adapter ────────────────────────────────────────────── */

    private interface CredentialCallback {
        void onSave(String url, String username, String password);
    }

    private class CredentialAdapter extends BaseAdapter {
        @Override
        public int getCount() {
            return credentials.size();
        }

        @Override
        public Object getItem(int position) {
            return credentials.get(position);
        }

        @Override
        public long getItemId(int position) {
            return credentials.get(position).id;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null) {
                convertView = LayoutInflater.from(MainActivity.this)
                        .inflate(R.layout.item_credential, parent, false);
            }
            CredentialEntry ce = credentials.get(position);
            TextView textUrl = convertView.findViewById(R.id.text_url);
            TextView textUsername = convertView.findViewById(R.id.text_username);
            textUrl.setText(ce.url);
            textUsername.setText(ce.username);
            return convertView;
        }
    }
}