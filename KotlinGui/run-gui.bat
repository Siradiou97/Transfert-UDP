@echo off
cd /d "%~dp0"
set "KOTLIN_HOME=C:\Program Files\Android\Android Studio\plugins\Kotlin\kotlinc"
set "KOTLINC=%KOTLIN_HOME%\bin\kotlinc.bat"
set "STDLIB=%KOTLIN_HOME%\lib\kotlin-stdlib.jar"

if not exist "%KOTLINC%" (
  set "KOTLINC=kotlinc"
  set "STDLIB="
)

if "%KOTLINC%"=="kotlinc" (
  where kotlinc >nul 2>nul
  if errorlevel 1 (
    echo Kotlin compiler introuvable.
    echo Ouvre le dossier KotlinGui dans IntelliJ IDEA, ou installe Kotlin/Gradle.
    pause
    exit /b 1
  )
)

if not exist build mkdir build
if "%KOTLINC%"=="kotlinc" (
  kotlinc src\main\kotlin\TransferGui.kt -include-runtime -d build\TransferGui.jar
) else (
  call "%KOTLINC%" src\main\kotlin\TransferGui.kt -cp "%STDLIB%" -include-runtime -d build\TransferGui.jar
)
if errorlevel 1 (
  pause
  exit /b 1
)

java -jar build\TransferGui.jar
