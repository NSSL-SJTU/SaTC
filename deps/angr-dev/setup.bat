set TO_CHECKOUT=%1

if "%APPVEYOR%"=="True" (
    move %APPVEYOR_BUILD_FOLDER% .
    set TO_CHECKOUT=%APPVEYOR_REPO_BRANCH%

    if "%APPVEYOR_PULL_REQUEST_NUMBER%"=="" (
        set TO_CHECKOUT=
    )
)

if not exist angr git clone https://github.com/angr/angr.git || goto :error
if not exist claripy git clone https://github.com/angr/claripy.git || goto :error
if not exist cle git clone https://github.com/angr/cle.git || goto :error
if not exist pyvex git clone https://github.com/angr/pyvex.git || goto :error
if not exist vex git clone https://github.com/angr/vex.git || goto :error
if not exist archinfo git clone https://github.com/angr/archinfo.git || goto :error
if not exist angr-doc git clone https://github.com/angr/angr-doc.git || goto :error
if not exist binaries git clone https://github.com/angr/binaries.git || goto :error
if not exist wheels git clone https://github.com/angr/wheels.git || goto :error

if not "%TO_CHECKOUT%" == "" (
    call git_all.bat checkout %TO_CHECKOUT%
)

pip install wheels\capstone-4.0.0-py2-none-win32.whl
pip install unicorn

pip install -e .\archinfo || goto :error
pip install -e .\pyvex || goto :error
pip install -e .\cle || goto :error
pip install -e .\claripy || goto :error
pip install -e .\angr || goto :error

pip install nose flaky monkeyhex ipdb || goto :error

echo "Development install success!"
exit /b 0

:error
echo "Development install failed!"
exit /b 1
