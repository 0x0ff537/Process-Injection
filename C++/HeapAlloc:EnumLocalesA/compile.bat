@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:myDropper.exe /SUBSYSTEM:CONSOLE
del *.obj