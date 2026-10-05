@echo off
setlocal
cd /d "%~dp0"
echo Building TorRoute...
where cl >nul 2>&1
if %errorlevel%==0 goto MSVC
where g++ >nul 2>&1
if %errorlevel%==0 goto GCC
echo ERROR: No C++ compiler found.
echo Use GitHub Actions to build the EXE, or install MinGW-w64.
pause
exit /b 1
:MSVC
cl /nologo /O2 /EHsc /std:c++17 TorRoute.cpp ws2_32.lib wininet.lib /Fe:TorRoute.exe
if errorlevel 1 exit /b 1
goto OK
:GCC
g++ -std=c++17 -O2 -s -o TorRoute.exe TorRoute.cpp -lws2_32 -lwininet
if errorlevel 1 exit /b 1
:OK
echo BUILD SUCCESSFUL: TorRoute.exe
endlocal
