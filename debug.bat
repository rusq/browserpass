@echo off
set MINGW=C:\Program Files\CodeBlocks\MinGW\
set PATH=%MINGW%\bin;%PATH%
rem set GOARCH=386
rem set CGO_ENABLED=1
dlv debug . -- -b c