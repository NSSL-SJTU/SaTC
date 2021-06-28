@echo off
for /f %%f in ('dir /B /AD') do (
  if exist %%f\.git (
    echo Working on %%f
    cd %%f
    git %* && echo SUCCESS || echo FAILURE
    echo --------------------------------------------------------
    cd ..
  )
)
exit /b 0
