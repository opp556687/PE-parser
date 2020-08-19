#include <iomanip>
#include <iostream>
#include <windows.h>
using namespace std;

int main()
{
    // open file
    string filename;
    cout << "Which file to parse?" << endl;
    cout << "filename: ";
    cin >> filename;
    HANDLE file = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        cout << "Can't not open " << filename << " !!";
        exit(0);
    }

    // allocate a heap to store the PE file
    DWORD filesize = GetFileSize(file, NULL);
    LPVOID filedata = HeapAlloc(GetProcessHeap(), 0, filesize);

    // read file to heap
    if (!ReadFile(file, filedata, filesize, NULL, NULL))
    {
        cout << "Read file error!!";
        exit(0);
    }

    // parse header to check if it is a PE file
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)filedata;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        cout << "Header not MZ";
        exit(0);
    }
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE *)filedata + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        cout << "Not a PE file!!";
        exit(0);
    }

    // parse file header
    cout << "******* File Header *******" << endl;
    cout << hex; // convert to hex format
    cout << "0x" << left << setw(12) << ntHeader->FileHeader.Machine << "Machine\n";
    cout << "0x" << left << setw(12) << ntHeader->FileHeader.NumberOfSections << "Number Of Sections\n";
    cout << "0x" << left << setw(12) << ntHeader->FileHeader.TimeDateStamp << "Time Stamp\n";
    cout << "0x" << left << setw(12) << ntHeader->FileHeader.PointerToSymbolTable << "Pointer To Stmbol Table\n";
    cout << "0x" << left << setw(12) << ntHeader->FileHeader.NumberOfSymbols << "Number Of Symbols\n";
    cout << "0x" << left << setw(12) << ntHeader->FileHeader.SizeOfOptionalHeader << "Size of Optional_Header\n";
    cout << "0x" << left << setw(12) << ntHeader->FileHeader.Characteristics << "Characteristics\n";
    cout << endl;

    // parse optional header
    cout << "******* Optional Header *******" << endl;
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.Magic << "Magic\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.MajorLinkerVersion << "Majot Linker Version\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.MinorLinkerVersion << "Minor Linker Version\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.SizeOfCode << "Size of Code\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.SizeOfInitializedData << "Size of Initialized Data\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.SizeOfUninitializedData << "Size of UnInitialized Data\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.AddressOfEntryPoint << "Address of Entry Point\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.BaseOfCode << "Base of Code\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.ImageBase << "Image Base\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.SectionAlignment << "Section Alignment\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.FileAlignment << "File Alignment\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.MajorOperatingSystemVersion << "Major Operating System Version\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.MinorOperatingSystemVersion << "Minor Operating System Version\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.MajorImageVersion << "Major Image Version\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.MinorImageVersion << "Minor Image Version\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.MajorSubsystemVersion << "Major Subsystem Version\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.MinorSubsystemVersion << "Minor Subsystem Version\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.Win32VersionValue << "Win32 Version Value\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.SizeOfImage << "Size of Image\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.SizeOfHeaders << "Size of Headers\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.CheckSum << "CheckSum\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.Subsystem << "Subsystem\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.DllCharacteristics << "DllCharacteristic\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.SizeOfStackReserve << "Size of Stack Reserve\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.SizeOfStackCommit << "Size of Stack Commit\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.SizeOfHeapReserve << "Size of Heap Reserve\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.SizeOfHeapCommit << "Size of Heap Commit\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.LoaderFlags << "Loader Flags\n";
    cout << "0x" << left << setw(12) << ntHeader->OptionalHeader.NumberOfRvaAndSizes << "Number of Rva And Sizes\n";
    cout << endl;

    // parse data directories
    cout << "******* Data Directories *******" << endl;
    string dataDirectories[16] =
        {"Export Table", "Import Table", "Resource Table", "Exception Table",
         "Security Table", "Base relocation Table", "Debug", "Copyright",
         "Global Ptr", "Thread local storage (TLS)", "Load configuration", "Bound Import",
         "Import Address Table (IAT)", "Delay Import", "COM descriptor", "Reserved"};
    cout << left << setw(30) << "Data Directory name" << left << setw(15) << "RVA" << left << setw(15) << " size" << endl;
    cout << "----------------------------------------------------" << endl;
    for (int i = 0; i < 16; i++)
    {
        cout << left << setw(30) << dataDirectories[i] << "0x" << left << setw(15) << ntHeader->OptionalHeader.DataDirectory[i].VirtualAddress;
        cout << "0x" << left << setw(15) << ntHeader->OptionalHeader.DataDirectory[i].Size << endl;
    }
    cout << endl;

    // parse section headers
    cout << "******* Section Headers *******" << endl;
    PIMAGE_SECTION_HEADER secHeader = IMAGE_FIRST_SECTION(ntHeader);
    DWORD importDirRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    PIMAGE_SECTION_HEADER importSection;
    cout << left << setw(10) << "Name" << left << setw(15) << "VirtualSize" << left << setw(15) << "VirtualAddress" << left << setw(15) << "SizeOfRawData";
    cout << left << setw(20) << "PointerToRawData" << left << setw(25) << "PointerToRelocations" << left << setw(25) << "PointerToLinenumbers";
    cout << left << setw(25) << "NumberOfRelocations" << left << setw(25) << "NumberOfLinenumbers" << left << setw(20) << "Characteristics" << endl;
    cout << "------------------------------------------------------------------------------------------------";
    cout << "----------------------------------------------------------------------------------------------" << endl;
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        cout << left << setw(12) << secHeader->Name;
        cout << "0x" << left << setw(13) << secHeader->Misc.VirtualSize;
        cout << "0x" << left << setw(13) << secHeader->VirtualAddress;
        cout << "0x" << left << setw(13) << secHeader->SizeOfRawData;
        cout << "0x" << left << setw(18) << secHeader->PointerToRawData;
        cout << "0x" << left << setw(23) << secHeader->PointerToRelocations;
        cout << "0x" << left << setw(23) << secHeader->PointerToLinenumbers;
        cout << "0x" << left << setw(23) << secHeader->NumberOfRelocations;
        cout << "0x" << left << setw(23) << secHeader->NumberOfLinenumbers;
        cout << "0x" << left << setw(18) << secHeader->Characteristics;
        cout << endl;
        // find import section
        if (importDirRVA >= secHeader->VirtualAddress && importDirRVA < secHeader->VirtualAddress + secHeader->Misc.VirtualSize)
        {
            importSection = secHeader;
        }
        secHeader++;
    }
    cout << endl;

    // import table
    cout << "******* Import Table *******" << endl;
    if (importDirRVA == 0)
    {
        cout << "Import Table is empty!!" << endl;
        system("pause");
        return 0;
    }
    DWORD rawOffset = (DWORD_PTR)filedata + importSection->PointerToRawData;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(rawOffset + (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));
    for (; importDesc->Name; importDesc++)
    {
        printf("%s:\n", rawOffset + (importDesc->Name - importSection->VirtualAddress));
        DWORD thunk = importDesc->OriginalFirstThunk == 0 ? importDesc->FirstThunk : importDesc->OriginalFirstThunk;
        PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)(rawOffset + (thunk - importSection->VirtualAddress));
        for (; thunkData->u1.AddressOfData != 0; thunkData++)
        {
            if (thunkData->u1.AddressOfData > 0x80000000)
            {
                cout << "Original: " << thunkData->u1.AddressOfData << endl;
            }
            else
            {
                printf("\t%s\n", (rawOffset + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2)));
            }
        }
    }
    cout << endl;
    system("pause");
    return 0;
}