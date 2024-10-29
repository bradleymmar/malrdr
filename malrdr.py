#!/usr/bin/env python3 

import pefile 
import capstone
import os 

#choice = input("Please enter the full path to your malware: ") 

choice = "/home/bradleymmar/Downloads/SRB2.exe" 

subj = pefile.PE(choice) 

  


impList = [] 
impAddrList = []
iocList = ["b'CreateThread'","b'CreateFile'","b'ConnectNamedPipe'","b'CreateFileMapping'","b'CreateProcess'" 

            ,"b'CreateRemoteThread'","b'EnumProcesses'","b'EnumProcessModules'","b'GetModuleFilename'","b'GetModuleHandle'","b'GetProcAddress'" 

            ,"b'IsWoW64Process'","b'LoadLibraryA'","b'LoadLibraryEx'","b'OpenProcess'","b'SetFileTime'","b'VirtualAllocEx'","b'WriteProcessMemory'" 

            ,"b'AdjustTokenPrivileges'","b'ControlService'","b'CreateService'","b'RegCreateKeyEx'","b'RegDeleteKey'","b'Accept'","b'Bind'","b'Connect'" 

            ,"b'inet_addr'","b'Recv'","b'Send'","b'WSAStartup'","b'FtpPutFile'","b'InternetOpen'","b'InternetOpenUrl'","b'InternetReadFile'","b'InternetWriteFile'"] 

matches = [] 

print ('\n', "====================", '\n', "====================", '\n') 

  
impAddrPos=[]
iocDict = {}
keyTrack = 0
impCounter = 0

for entry in subj.DIRECTORY_ENTRY_IMPORT: 

    print (entry.dll) 

    for imp in entry.imports: 

        impList.append(str(imp.name))
        impAddrList.append(str(imp.address))

#hex(imp.address)   

str(impList) 
for entry in impList: 

    if entry in iocList: 

        matches.append(entry)
        impAddrPos.append(impCounter)
    impCounter = impCounter + 1
for key in matches:
    addrPos = impAddrPos[keyTrack]
    addr = impAddrList[addrPos]
    
    iocDict[key] = {addr}
    keyTrack = keyTrack + 1

