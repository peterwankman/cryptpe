@echo off

pushd ..
echo Looking for mkbintable.exe...

FOR %%a IN (Win32 x64) DO (
 FOR %%b IN (debug release) DO (
  CALL :FINDBIN %%a %%b
 )
)

echo %BINARY%

echo Creating table...

%BINARY% bin\Win32\Release\testbin.exe > cryptpe\bintable.h
popd
echo done.

:FINDBIN
IF EXIST bin\%1\%2\mkbintable.exe SET BINARY="bin\%1\%2\mkbintable.exe"
EXIT /B