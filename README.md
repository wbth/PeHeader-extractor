# Handles
EXE, DLL, SYS, OCX, SCR, CPL, DRV, EFI

# 56 Standard Features extracted
Basic Info (2):
Name, md5

PE Headers (30):
Machine, SizeOfOptionalHeader, Characteristics
MajorLinkerVersion, MinorLinkerVersion
SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData
AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase
SectionAlignment, FileAlignment
MajorOperatingSystemVersion, MinorOperatingSystemVersion
MajorImageVersion, MinorImageVersion
MajorSubsystemVersion, MinorSubsystemVersion
SizeOfImage, SizeOfHeaders, CheckSum
Subsystem, DllCharacteristics
SizeOfStackReserve, SizeOfStackCommit
SizeOfHeapReserve, SizeOfHeapCommit
LoaderFlags, NumberOfRvaAndSizes

Section Features (10):
SectionsNb, SectionsMeanEntropy, SectionsMinEntropy, SectionsMaxEntropy
SectionsMeanRawsize, SectionsMinRawsize, SectionsMaxRawsize
SectionsMeanVirtualsize, SectionsMinVirtualsize, SectionsMaxVirtualsize

Import/Export Features (4):
ImportsNbDLL, ImportsNb, ImportsNbOrdinal, ExportNb

Resource Features (7):
ResourcesNb, ResourcesMeanEntropy, ResourcesMinEntropy, ResourcesMaxEntropy
ResourcesMeanSize, ResourcesMinSize, ResourcesMaxSize

Misc Features (3):
LoadConfigurationSize, VersionInformationSize

# How to Use
- Install dependencies: pip install pefile pandas tqdm numpy

- Extract from single file: python pe_extractor.py malware.exe

- Extract from directory: python pe_extractor.py /path/to/malware/folder/

- Extract with validation: python pe_extractor.py malware.exe --validate

- Single file dengan custom output: python pe_extractor.py winrar-x64.exe -o winrar_features.csv

- Directory recursive: python pe_extractor.py /malware/samples/ -r -o all_samples.csv

- Batch processing: python pe_extractor.py /benign/software/ -o benign_features.csv --validate
