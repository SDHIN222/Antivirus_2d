@echo off
echo Building Antivirus Solution...
dotnet build Antivirus.sln
if %errorlevel% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)
echo Build successful!
