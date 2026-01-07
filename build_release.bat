@echo off
color 0A
title Recapture Builder

echo ========================================================
echo        RECAPTURE V1.0 - GOLD MASTER BUILDER
echo ========================================================
echo.

:: 1. CLEANUP
echo [1/5] Cleaning up old files...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist __pycache__ rmdir /s /q __pycache__
del /q *.spec
if exist "maintest.py" del "maintest.py"

:: 2. CREATE DUMMY README/NOTICE IF MISSING
if not exist "README.md" echo # Recapture v1.0 > README.md
if not exist "NOTICE.txt" echo Legal Notice > NOTICE.txt

:: 3. BUILD GUI VERSION (With Recapture.png Splash)
echo.
echo [2/5] Compiling GUI (Recapture.exe)...

:: CHECK FOR SPLASH IMAGE (Recapture.png)
if exist "Recapture.png" (
    echo       - Found Recapture.png! Including splash screen...
    pyinstaller --noconfirm --onefile --windowed --name "Recapture" --icon="Recapture.ico" --splash "Recapture.png" --clean main.py
) else (
    echo       - WARNING: Recapture.png not found. Building without splash...
    pyinstaller --noconfirm --onefile --windowed --name "Recapture" --icon="Recapture.ico" --clean main.py
)

:: 4. BUILD CLI VERSION (No Splash, Console Mode)
echo.
echo [3/5] Compiling CLI (Recapture_CLI.exe)...
:: CHANGED: Using cli.py instead of recapture.py
pyinstaller --noconfirm --onefile --console --name "Recapture_CLI" --icon="Recapture.ico" cli.py

:: 5. ORGANIZE RELEASE FOLDER
echo.
echo [4/5] Packaging Release Folder...
set OUT_DIR="Recapture_v1.0_Gold"
if exist %OUT_DIR% rmdir /s /q %OUT_DIR%
mkdir %OUT_DIR%

move "dist\Recapture.exe" %OUT_DIR%
move "dist\Recapture_CLI.exe" %OUT_DIR%
:: CHANGED: Copying README.md instead of TXT
copy "README.md" %OUT_DIR%
copy "NOTICE.txt" %OUT_DIR%
if exist "bad_hashes.txt" copy "bad_hashes.txt" %OUT_DIR%

:: 6. FINAL CLEANUP
echo.
echo [5/5] Cleaning up build artifacts...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
del /q *.spec

echo.
echo ========================================================
echo    BUILD SUCCESSFUL!
echo    Output Location: %OUT_DIR%
echo ========================================================
pause