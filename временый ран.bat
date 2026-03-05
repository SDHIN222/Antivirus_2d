@echo off
echo Building solution first...
dotnet build Antivirus.sln
if %errorlevel% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)
echo Build successful!

echo Compiling test files...
call compile_test.bat
if %errorlevel% neq 0 (
    echo Test compilation failed!
    pause
    exit /b 1
)

echo Testing scanner functionality...
cd TestMalware
dotnet run
if %errorlevel% neq 0 (
    echo Test failed!
    pause
    exit /b 1
)

echo Running Antivirus UI...
cd ..\Antivirus.UI
dotnet run
pause
