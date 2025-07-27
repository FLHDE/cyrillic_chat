# VC6 makefile

PLUGIN_NAME = cyrillic_chat

C_FLAGS = /c /O2 /nologo /W3 /WX /LD /MD
LD_FLAGS = /DLL /FILEALIGN:512 /NOLOGO /RELEASE

$(PLUGIN_NAME).dll: $(PLUGIN_NAME).obj $(PLUGIN_NAME).res makefile
    link $(PLUGIN_NAME).obj $(PLUGIN_NAME).res $(LD_FLAGS) /OUT:$(PLUGIN_NAME).dll

$(PLUGIN_NAME).obj: $(PLUGIN_NAME).c makefile
    cl $(C_FLAGS) $(PLUGIN_NAME).c

$(PLUGIN_NAME).res: $(PLUGIN_NAME).rc makefile
    rc /fo $(PLUGIN_NAME).res $(PLUGIN_NAME).rc

clean:
    del *.dll *.obj *.RES *.lib
