@echo off

cd ..

attrib -h -s log.txt
attrib -h cryptpe.suo
del /q log.txt
del /q remotelog.txt
del /q memlog.txt
del /q cryptpe.suo
del /q cryptpe.sdf
del /q cryptpe.opensdf
rd /q /s debug
rd /q /s release
rd /q /s ipch

rd /q /s testbin\debug
rd /q /s testbin\release
del /q testbin\testbin.vcxproj.user
del /q testbin\testbin.sdf

rd /q /s mkbintable\debug
rd /q /s mkbintable\release
del /q mkbintable\mkbintable.vcxproj.user
del /q mkbintable\mkbintable.sdf

rd /q /s cryptpe\debug
rd /q /s cryptpe\release
del /q cryptpe\bintable.h
del /q cryptpe\cryptpe.aps
del /q cryptpe\cryptpe.vcxproj.user
del /q cryptpe\cryptpe.sdf

cd script