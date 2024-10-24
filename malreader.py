#!/usr/bin/env python3

import pefile
choice = input("Please enter the full path to your malware: ")
subj = pefile.PE(choice)

for section in subj.sections:
    print (section.Name, hex(section.VirtualAddress),
        hex(section.Misc_VirtualSize), section.SizeOfRawData)
impList = []
iocList = ["b'CreateThread'"]
matches = []
print ('\n', "====================", "====================", '\n')

for entry in subj.DIRECTORY_ENTRY_IMPORT:
    print (entry.dll)
    for imp in entry.imports:
        #   print ('\t', hex(imp.address), imp.name)
        impList.append(str(imp.name))


str(impList)


for entry in impList:
    if entry in iocList:
        matches.append(entry)

print(matches)




#print("hi"#)
