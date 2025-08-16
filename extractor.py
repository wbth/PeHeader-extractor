# PE FEATURES EXTRACTOR - LOCAL PYTHON
# Extract 56 standard features from PE files (EXE/DLL) to CSV
# For local Python environment

import os
import pefile
import pandas as pd
import math
import hashlib
import argparse
from tqdm import tqdm
import sys
from datetime import datetime

def calculate_entropy(data):
    """Calculate entropy of binary data"""
    if not data:
        return 0
    
    occurences = [0] * 256
    for byte in data:
        occurences[byte] += 1
    
    entropy = 0
    for count in occurences:
        if count == 0:
            continue
        p_x = count / len(data)
        entropy -= p_x * math.log2(p_x)
    
    return entropy

def get_md5_hash(file_path):
    """Get MD5 hash of file"""
    try:
        with open(file_path, "rb") as file:
            hash_md5 = hashlib.md5()
            for chunk in iter(lambda: file.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        print(f"Error calculating MD5 for {file_path}: {e}")
        return f"error_{hash(file_path)}"

def extract_pe_features(file_path):
    """Extract all 56 standard PE features from a single file"""
    try:
        pe = pefile.PE(file_path)
        
        # Initialize resource entries
        resource_entries = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                if hasattr(resource_lang, 'data'):
                                    try:
                                        data = pe.get_data(
                                            resource_lang.data.struct.OffsetToData, 
                                            resource_lang.data.struct.Size
                                        )
                                        entropy = calculate_entropy(data)
                                        resource_entries.append({
                                            'Size': resource_lang.data.struct.Size,
                                            'Entropy': entropy
                                        })
                                    except Exception as e:
                                        # Skip problematic resources
                                        continue
        
        # Extract all 56 features
        pe_features = {
            # Basic file info
            'Name': os.path.basename(file_path),
            'md5': get_md5_hash(file_path),
            
            # FILE_HEADER features
            'Machine': pe.FILE_HEADER.Machine,
            'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
            'Characteristics': pe.FILE_HEADER.Characteristics,
            
            # OPTIONAL_HEADER features
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
            'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
            'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
            'BaseOfData': getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0),  # Not present in 64-bit
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
            'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
            'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
            'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
            'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
            'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
            
            # Section features
            'SectionsNb': len(pe.sections),
            'SectionsMeanEntropy': sum(section.get_entropy() for section in pe.sections) / len(pe.sections) if pe.sections else 0,
            'SectionsMinEntropy': min(section.get_entropy() for section in pe.sections) if pe.sections else 0,
            'SectionsMaxEntropy': max(section.get_entropy() for section in pe.sections) if pe.sections else 0,
            'SectionsMeanRawsize': sum(section.SizeOfRawData for section in pe.sections) / len(pe.sections) if pe.sections else 0,
            'SectionsMinRawsize': min(section.SizeOfRawData for section in pe.sections) if pe.sections else 0,
            'SectionMaxRawsize': max(section.SizeOfRawData for section in pe.sections) if pe.sections else 0,
            'SectionsMeanVirtualsize': sum(section.Misc_VirtualSize for section in pe.sections) / len(pe.sections) if pe.sections else 0,
            'SectionsMinVirtualsize': min(section.Misc_VirtualSize for section in pe.sections) if pe.sections else 0,
            'SectionMaxVirtualsize': max(section.Misc_VirtualSize for section in pe.sections) if pe.sections else 0,
            
            # Import features
            'ImportsNbDLL': len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            'ImportsNb': sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            'ImportsNbOrdinal': sum(1 for entry in pe.DIRECTORY_ENTRY_IMPORT for imp in entry.imports if imp.ordinal) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            
            # Export features
            'ExportNb': len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
            
            # Resource features
            'ResourcesNb': len(resource_entries),
            'ResourcesMeanEntropy': sum(entry['Entropy'] for entry in resource_entries) / len(resource_entries) if resource_entries else 0,
            'ResourcesMinEntropy': min(entry['Entropy'] for entry in resource_entries) if resource_entries else 0,
            'ResourcesMaxEntropy': max(entry['Entropy'] for entry in resource_entries) if resource_entries else 0,
            'ResourcesMeanSize': sum(entry['Size'] for entry in resource_entries) / len(resource_entries) if resource_entries else 0,
            'ResourcesMinSize': min(entry['Size'] for entry in resource_entries) if resource_entries else 0,
            'ResourcesMaxSize': max(entry['Size'] for entry in resource_entries) if resource_entries else 0,
            
            # Load configuration features
            'LoadConfigurationSize': pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') else 0,
            'VersionInformationSize': len(pe.FileInfo) if hasattr(pe, 'FileInfo') else 0
        }
        
        pe.close()
        return pe_features
        
    except pefile.PEFormatError:
        print(f"Invalid PE format: {os.path.basename(file_path)}")
        return None
    except Exception as e:
        print(f"Error processing {os.path.basename(file_path)}: {e}")
        return None

def process_single_file(file_path, output_csv=None):
    """Process a single PE file and save to CSV"""
    print(f"Processing single file: {os.path.basename(file_path)}")
    
    if not os.path.exists(file_path):
        print(f"Error: File not found - {file_path}")
        return False
    
    # Extract features
    features = extract_pe_features(file_path)
    
    if features is None:
        print("Feature extraction failed")
        return False
    
    # Create DataFrame
    df = pd.DataFrame([features])
    
    # Generate output filename if not provided
    if output_csv is None:
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_csv = f"extracted_{base_name}_{timestamp}.csv"
    
    # Save to CSV
    try:
        df.to_csv(output_csv, index=False)
        print(f"Features saved to: {output_csv}")
        print(f"Features extracted: {len(features)}")
        return True
    except Exception as e:
        print(f"Error saving CSV: {e}")
        return False

def process_directory(directory_path, output_csv=None, recursive=True):
    """Process all PE files in a directory"""
    print(f"Processing directory: {directory_path}")
    
    if not os.path.exists(directory_path):
        print(f"Error: Directory not found - {directory_path}")
        return False
    
    # Find all PE files
    pe_extensions = ('.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.drv', '.efi')
    pe_files = []
    
    if recursive:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.lower().endswith(pe_extensions):
                    pe_files.append(os.path.join(root, file))
    else:
        for file in os.listdir(directory_path):
            if file.lower().endswith(pe_extensions):
                pe_files.append(os.path.join(directory_path, file))
    
    if not pe_files:
        print("No PE files found in directory")
        return False
    
    print(f"Found {len(pe_files)} PE files")
    
    # Process all files
    all_features = []
    successful = 0
    
    for file_path in tqdm(pe_files, desc="Extracting features"):
        features = extract_pe_features(file_path)
        if features is not None:
            all_features.append(features)
            successful += 1
    
    if not all_features:
        print("No files processed successfully")
        return False
    
    # Create DataFrame
    df = pd.DataFrame(all_features)
    
    # Generate output filename if not provided
    if output_csv is None:
        dir_name = os.path.basename(directory_path.rstrip('/\\'))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_csv = f"extracted_{dir_name}_{timestamp}.csv"
    
    # Save to CSV
    try:
        df.to_csv(output_csv, index=False)
        print(f"\nProcessing complete!")
        print(f"Successfully processed: {successful}/{len(pe_files)} files")
        print(f"Features saved to: {output_csv}")
        print(f"CSV shape: {df.shape}")
        return True
    except Exception as e:
        print(f"Error saving CSV: {e}")
        return False

def validate_features(csv_path):
    """Validate extracted features CSV"""
    print(f"Validating features in: {csv_path}")
    
    try:
        df = pd.read_csv(csv_path)
        print(f"CSV loaded successfully: {df.shape}")
        
        # Expected 56 features (including Name and md5)
        expected_columns = 56
        actual_columns = len(df.columns)
        
        print(f"Expected columns: {expected_columns}")
        print(f"Actual columns: {actual_columns}")
        
        if actual_columns == expected_columns:
            print("✓ Column count is correct")
        else:
            print(f"✗ Column count mismatch")
        
        # Check for missing values
        missing_counts = df.isnull().sum()
        total_missing = missing_counts.sum()
        
        print(f"Total missing values: {total_missing}")
        
        if total_missing > 0:
            print("Columns with missing values:")
            for col, count in missing_counts[missing_counts > 0].items():
                pct = count / len(df) * 100
                print(f"  {col}: {count} ({pct:.1f}%)")
        else:
            print("✓ No missing values found")
        
        # Check for suspicious values
        numeric_cols = df.select_dtypes(include=['number']).columns
        
        print(f"\nNumeric feature summary:")
        print(f"Numeric columns: {len(numeric_cols)}")
        
        # Check for zeros
        zero_counts = (df[numeric_cols] == 0).sum()
        high_zero_cols = zero_counts[zero_counts > len(df) * 0.5]
        
        if not high_zero_cols.empty:
            print("Columns with >50% zeros:")
            for col, count in high_zero_cols.items():
                pct = count / len(df) * 100
                print(f"  {col}: {count} ({pct:.1f}%)")
        
        return True
        
    except Exception as e:
        print(f"Error validating CSV: {e}")
        return False

def main():
    """Main function with command line interface"""
    parser = argparse.ArgumentParser(description='Extract PE features from EXE/DLL files to CSV')
    parser.add_argument('input', help='Input file or directory path')
    parser.add_argument('-o', '--output', help='Output CSV file path')
    parser.add_argument('-r', '--recursive', action='store_true', 
                       help='Process directories recursively (default: True)')
    parser.add_argument('--validate', action='store_true',
                       help='Validate the output CSV after processing')
    parser.add_argument('--single', action='store_true',
                       help='Force single file processing even if input is directory')
    
    args = parser.parse_args()
    
    print("PE FEATURES EXTRACTOR")
    print("=" * 50)
    print(f"Input: {args.input}")
    print(f"Output: {args.output or 'auto-generated'}")
    print()
    
    # Determine processing mode
    if os.path.isfile(args.input) or args.single:
        # Single file processing
        success = process_single_file(args.input, args.output)
    elif os.path.isdir(args.input):
        # Directory processing
        success = process_directory(args.input, args.output, args.recursive)
    else:
        print(f"Error: Input path does not exist - {args.input}")
        return 1
    
    if not success:
        print("Processing failed")
        return 1
    
    # Validate output if requested
    if args.validate and args.output:
        print("\n" + "=" * 50)
        validate_features(args.output)
    
    print("\nProcessing complete!")
    return 0

if __name__ == "__main__":
    # Example usage if run directly
    if len(sys.argv) == 1:
        print("PE FEATURES EXTRACTOR - USAGE EXAMPLES")
        print("=" * 50)
        print()
        print("Extract from single file:")
        print("  python pe_extractor.py malware.exe")
        print("  python pe_extractor.py malware.exe -o features.csv")
        print()
        print("Extract from directory:")
        print("  python pe_extractor.py /path/to/malware/folder/")
        print("  python pe_extractor.py /path/to/malware/folder/ -o batch_features.csv")
        print()
        print("Extract with validation:")
        print("  python pe_extractor.py malware.exe --validate")
        print()
        print("Recursive directory processing:")
        print("  python pe_extractor.py /path/to/malware/ -r")
        print()
        print("Non-recursive directory processing:")
        print("  python pe_extractor.py /path/to/malware/")
        print()
        
        # Interactive mode for testing
        test_input = input("\nEnter file/directory path to test (or press Enter to exit): ").strip()
        if test_input:
            sys.argv = ['pe_extractor.py', test_input, '--validate']
            main()
    else:
        sys.exit(main())
