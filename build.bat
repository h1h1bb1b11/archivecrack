@echo off
setlocal
set GXX=C:\Users\dell\.cache\mingw64\bin\g++.exe
if not exist "%GXX%" set GXX=g++
set WINDRES=C:\Users\dell\.cache\mingw64\bin\windres.exe
if not exist "%WINDRES%" set WINDRES=windres
set IMGUI=third_party\imgui-1.90.9
if not exist "%IMGUI%\imgui.cpp" set IMGUI=..\LogQuery\third_party\imgui-1.90.9
if not exist "%IMGUI%\imgui.cpp" (
  echo [ERROR] ImGui sources not found at %IMGUI%
  exit /b 1
)
echo [1/3] compiling resources...
"%WINDRES%" -i res.rc -o res.o
if errorlevel 1 (
  echo [FAILED] resource error
  exit /b 1
)
echo [2/3] compiling ArchiveCrack...
"%GXX%" -std=c++17 -O2 -municode -mwindows -finput-charset=UTF-8 -fexec-charset=UTF-8 ^
  -I"%IMGUI%" -I"%IMGUI%\backends" ^
  main.cpp res.o ^
  "%IMGUI%\imgui.cpp" "%IMGUI%\imgui_draw.cpp" "%IMGUI%\imgui_tables.cpp" "%IMGUI%\imgui_widgets.cpp" ^
  "%IMGUI%\backends\imgui_impl_win32.cpp" "%IMGUI%\backends\imgui_impl_dx11.cpp" ^
  -o ArchiveCrack.exe ^
  -ld3d11 -ldxgi -ld3dcompiler -ldwmapi -lgdi32 -lcomdlg32 -lshell32 -lole32 -static -s
if errorlevel 1 (
  echo [FAILED] build error
  exit /b 1
)
echo [3/3] done: ArchiveCrack.exe
