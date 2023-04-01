@echo off
echo Creating table...
pushd ..
bin\win32\debug\mkbintable bin\win32\Release\testbin.exe > cryptpe\bintable.h
popd
echo done.