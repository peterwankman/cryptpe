@echo off
echo Creating table...
cd ..
%1\mkbintable Release\testbin.exe > cryptpe\bintable.h
cd script
echo done.