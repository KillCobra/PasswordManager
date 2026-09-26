@echo off
REM ============================================================
REM Cross-Platform Password Manager - Windows Build Script
REM Supports MSVC (cl.exe) and MinGW (gcc)
REM Usage: build.bat [msvc|mingw] [debug|release]
REM ============================================================

setlocal enabledelayedexpansion

set COMPILER=%1
set CONFIG=%2

if "%COMPILER%"=="" set COMPILER=msvc
if "%CONFIG%"=="" set CONFIG=release

REM --- Source files ---
set CORE_SOURCES=^
    src\encryption.c ^
    src\vault.c ^
    src\credential.c ^
    src\sync.c

set PLATFORM_SOURCES=^
    platform\platform_win32.c ^
    platform\win32_ui.c

set VENDOR_ARGON2=^
    vendor\argon2\argon2.c ^
    vendor\argon2\core.c ^
    vendor\argon2\ref.c ^
    vendor\argon2\blake2b.c ^
    vendor\argon2\encoding.c

set VENDOR_AESGCM=^
    vendor\aesgcm\aes.c ^
    vendor\aesgcm\gcm.c

set ALL_SOURCES=%CORE_SOURCES% %PLATFORM_SOURCES% %VENDOR_ARGON2% %VENDOR_AESGCM%

REM --- Include paths ---
set INCLUDES=/Iinclude /Ivendor\argon2 /Ivendor\aesgcm

REM --- Output ---
set OUTPUT=password_manager.exe

echo.
echo ============================================================
echo  Building Password Manager (%COMPILER% / %CONFIG%)
echo ============================================================
echo.

if /i "%COMPILER%"=="msvc" goto :build_msvc
if /i "%COMPILER%"=="mingw" goto :build_mingw
echo ERROR: Unknown compiler "%COMPILER%". Use "msvc" or "mingw".
exit /b 1

:build_msvc
REM --- MSVC Build ---
set CFLAGS=/nologo /std:c11 /W4 /D_CRT_SECURE_NO_WARNINGS /DUNICODE /D_UNICODE
if /i "%CONFIG%"=="debug" (
    set CFLAGS=%CFLAGS% /Zi /Od /DDEBUG
) else (
    set CFLAGS=%CFLAGS% /O2 /DNDEBUG
)
set LIBS=advapi32.lib ws2_32.lib user32.lib gdi32.lib bcrypt.lib comctl32.lib dwmapi.lib

REM --- Compile the icon resource (best-effort; skip if rc.exe unavailable) ---
set RES=
where rc.exe >nul 2>nul
if %errorlevel%==0 (
    echo Compiling resources with rc.exe...
    rc.exe /nologo /fo app.res app.rc
    if errorlevel 1 (
        echo WARNING: resource compile failed, building without icon.
    ) else (
        set RES=app.res
    )
) else (
    echo NOTE: rc.exe not found, building without embedded icon.
)

echo Compiling with MSVC (cl.exe)...
cl.exe %CFLAGS% %INCLUDES% %ALL_SOURCES% /Fe:%OUTPUT% /link %LIBS% %RES%
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)
echo.
echo BUILD SUCCEEDED: %OUTPUT%
goto :end

:build_mingw
REM --- MinGW Build ---
set CFLAGS=-std=c11 -Wall -Wextra -DUNICODE -D_UNICODE
set INCLUDES_GCC=-Iinclude -Ivendor/argon2 -Ivendor/aesgcm
if /i "%CONFIG%"=="debug" (
    set CFLAGS=%CFLAGS% -g -O0 -DDEBUG
) else (
    set CFLAGS=%CFLAGS% -O2 -DNDEBUG
)
set LIBS=-ladvapi32 -lws2_32 -luser32 -lgdi32 -lbcrypt -lcomctl32 -ldwmapi -mwindows

REM --- Compile the icon resource (best-effort; skip if windres unavailable) ---
set RES=
where windres >nul 2>nul
if %errorlevel%==0 (
    echo Compiling resources with windres...
    windres app.rc -O coff -o app_res.o
    if errorlevel 1 (
        echo WARNING: resource compile failed, building without icon.
    ) else (
        set RES=app_res.o
    )
) else (
    echo NOTE: windres not found, building without embedded icon.
)

echo Compiling with MinGW (gcc)...
gcc %CFLAGS% %INCLUDES_GCC% %ALL_SOURCES% %RES% -o %OUTPUT% %LIBS%
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)
echo.
echo BUILD SUCCEEDED: %OUTPUT%
goto :end

:end
endlocal
