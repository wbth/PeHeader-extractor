# PeHeader-extractor

A Python script that reads Windows PE files and saves their header features to a CSV. It only reads the files and never runs them. I wrote it for my malware detection research to turn executables into a table machine learning models can use.

Each file becomes one row with 56 columns: the file name, the file's MD5 hash, and 54 numeric features.

# Handles

EXE, DLL, SYS, OCX, SCR, CPL, DRV, EFI

Files are picked up by extension, and case does not matter. PE files with any other extension, or none, are not read.

# 56 Standard Features extracted

**Basic Info (2)**
- `Name`, `md5`

**PE Headers (31)**
- `Machine`, `SizeOfOptionalHeader`, `Characteristics`
- `MajorLinkerVersion`, `MinorLinkerVersion`
- `SizeOfCode`, `SizeOfInitializedData`, `SizeOfUninitializedData`
- `AddressOfEntryPoint`, `BaseOfCode`, `BaseOfData`, `ImageBase`
- `SectionAlignment`, `FileAlignment`
- `MajorOperatingSystemVersion`, `MinorOperatingSystemVersion`
- `MajorImageVersion`, `MinorImageVersion`
- `MajorSubsystemVersion`, `MinorSubsystemVersion`
- `SizeOfImage`, `SizeOfHeaders`, `CheckSum`
- `Subsystem`, `DllCharacteristics`
- `SizeOfStackReserve`, `SizeOfStackCommit`
- `SizeOfHeapReserve`, `SizeOfHeapCommit`
- `LoaderFlags`, `NumberOfRvaAndSizes`

**Section Features (10)**
- `SectionsNb`, `SectionsMeanEntropy`, `SectionsMinEntropy`, `SectionsMaxEntropy`
- `SectionsMeanRawsize`, `SectionsMinRawsize`, `SectionMaxRawsize`
- `SectionsMeanVirtualsize`, `SectionsMinVirtualsize`, `SectionsMaxVirtualsize`

**Import/Export Features (4)**
- `ImportsNbDLL`, `ImportsNb`, `ImportsNbOrdinal`, `ExportNb`

**Resource Features (7)**
- `ResourcesNb`, `ResourcesMeanEntropy`, `ResourcesMinEntropy`, `ResourcesMaxEntropy`
- `ResourcesMeanSize`, `ResourcesMinSize`, `ResourcesMaxSize`

**Misc Features (2)**
- `LoadConfigurationSize`, `VersionInformationSize`

A few things worth knowing about the columns:

- Entropy is Shannon entropy over the byte values. For sections, it comes from the PE file. For resources, the script calculates it.
- `BaseOfData` is 0 for 64-bit files because the field does not exist there.
- `VersionInformationSize` is the number of entries in `FileInfo`, not a size in bytes.
- `SectionMaxRawsize` and `SectionMaxVirtualsize` have no "s" after "Section". That is how they appear in the CSV, so keep it in mind when matching against other datasets.

# How to Use

Install the dependencies:

```
pip install pefile pandas tqdm
```

Extract from a single file:

```
python extractor.py malware.exe
```

Single file with a custom output name:

```
python extractor.py winrar-x64.exe -o winrar_features.csv
```

Extract from a directory (top level only):

```
python extractor.py /path/to/malware/folder/
```

Directory with all subfolders, using `-r`:

```
python extractor.py /malware/samples/ -r -o all_samples.csv
```

Batch run with validation of the output:

```
python extractor.py /benign/software/ -o benign_features.csv --validate
```

Validation only runs when `-o` is given. If you leave `-o` out, the CSV is named `extracted_<name>_<timestamp>.csv`.

# Files that fail

A file that is not a valid PE prints `Invalid PE format` and is skipped. Any other error prints a message, and the file is skipped as well. A broken resource entry only drops that entry, not the whole file. At the end of a directory run, the script prints how many files were processed out of how many it found.

Skipped files are not in the CSV, so they never reach a training set. If you build a dataset with this, keep track of that number.

# Limitations

Header features describe how a file is built, not what it does. A packed or obfuscated sample can have an unusual header that says little about its behavior. Only the features listed above are extracted, so there are no opcode, string, or behavior features.

# Handling malware

The script does not run the files it reads, but the samples are still real malware. Keep them in an isolated environment.
