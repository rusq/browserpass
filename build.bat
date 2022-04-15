@echo off
rem set MINGW=C:\Program Files (x86)\CodeBlocks\MinGW\
rem set PATH=%MINGW%\bin;%PATH%
rem set GOARCH=386
rem set CGO_ENABLED=1
go build . -ldflags="-s -w"