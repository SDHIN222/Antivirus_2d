@echo off
echo Compiling test files...
echo.

echo Compiling malware test...
csc /out:test_malware.exe test_malware.cs
if %errorlevel% neq 0 (
    echo Failed to compile malware test
    pause
    exit /b 1
)

echo Compiling installer test...
csc /out:test_installer.exe test_installer.cs
if %errorlevel% neq 0 (
    echo Failed to compile installer test
    pause
    exit /b 1
)

echo Compiling malicious exe...
csc /out:malicious_exe.exe malicious_exe.cs
if %errorlevel% neq 0 (
    echo Failed to compile malicious exe
    pause
    exit /b 1
)

echo Compiling installer exe...
csc /out:installer_exe.exe installer_exe.cs
if %errorlevel% neq 0 (
    echo Failed to compile installer exe
    pause
    exit /b 1
)

echo.
echo Test files compiled successfully!
echo ============================================
echo test_malware.exe - should be detected as malicious (source file)
echo test_installer.exe - should be detected as legitimate (source file)
echo malicious_exe.exe - should be detected as MALICIOUS (exe with bad patterns)
echo installer_exe.exe - should be detected as LEGITIMATE INSTALLER (exe with good patterns)
echo ============================================
echo.
pause
