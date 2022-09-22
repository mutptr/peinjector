#include <Windows.h>
#include <string>
#include <filesystem>
#include <iostream>
#include <fstream>

std::string import_name = "exploit";

std::unique_ptr<uint8_t[]> buffer;
IMAGE_DOS_HEADER* dos_header;
IMAGE_NT_HEADERS* nt_headers;
bool is_wow64;
IMAGE_OPTIONAL_HEADER32* optional_header32;
IMAGE_OPTIONAL_HEADER64* optional_header64;
IMAGE_DATA_DIRECTORY* import_directory;
IMAGE_SECTION_HEADER* section_header;

void parse()
{
	dos_header = (IMAGE_DOS_HEADER*)buffer.get();
	nt_headers = (IMAGE_NT_HEADERS*)(buffer.get() + dos_header->e_lfanew);
	is_wow64 = nt_headers->FileHeader.Machine == IMAGE_FILE_MACHINE_I386;
	optional_header32 = (IMAGE_OPTIONAL_HEADER32*)&nt_headers->OptionalHeader;
	optional_header64 = (IMAGE_OPTIONAL_HEADER64*)&nt_headers->OptionalHeader;

	import_directory = is_wow64 ?
		&optional_header32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] :
		&optional_header64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	section_header = is_wow64 ?
		(IMAGE_SECTION_HEADER*)(optional_header32 + 1) :
		(IMAGE_SECTION_HEADER*)(optional_header64 + 1);
}

int wmain()
{
	std::filesystem::path file_path;
	std::string dll_name;
	std::cout << "PATH: ";
	std::cin >> file_path;
	std::cout << "DLL: ";
	std::cin >> dll_name;

	std::ifstream in(file_path, std::ios::binary | std::ios::ate);
	if (in.is_open())
	{
		size_t size = (size_t)in.tellg();
		in.seekg(0, std::ios::beg);

		buffer = std::make_unique<uint8_t[]>(size);
		in.read((char*)buffer.get(), size);
		parse();

		uint32_t import_directory_raw = 0;
		uint32_t import_directory_rva = import_directory->VirtualAddress;

		for (uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
		{
			if (import_directory_rva > section_header[i].VirtualAddress &&
				import_directory_rva < section_header[i].VirtualAddress + section_header[i].SizeOfRawData)
			{
				import_directory_raw = import_directory_rva - section_header[i].VirtualAddress + section_header[i].PointerToRawData;
				break;
			}
		}

		uint32_t section_alignment = is_wow64 ?
			optional_header32->SectionAlignment :
			optional_header64->SectionAlignment;
		uint32_t file_alignment = is_wow64 ?
			optional_header32->FileAlignment :
			optional_header64->FileAlignment;


		uint32_t import_directory_size = import_directory->Size;
		uint32_t new_import_directory_size = import_directory_size + sizeof(IMAGE_IMPORT_DESCRIPTOR);
		uint32_t dll_name_size = (uint32_t)dll_name.length() + 1;
		uint32_t import_name_size = sizeof(IMAGE_IMPORT_BY_NAME::Hint) + (uint32_t)import_name.length() + 1;

		uint32_t new_section_size = new_import_directory_size;
		new_section_size += dll_name_size;
		new_section_size += import_name_size;
		new_section_size += is_wow64 ? sizeof(IMAGE_THUNK_DATA32) : sizeof(IMAGE_THUNK_DATA64); //import address table

		uint32_t file_start_padding = file_alignment - size % file_alignment;
		uint32_t file_padding = file_alignment - new_section_size % file_alignment;
		uint32_t section_padding = section_alignment - new_section_size % section_alignment;


		uint32_t section_raw = (DWORD)size + file_start_padding;
		uint32_t import_descriptor_raw = section_raw;
		uint32_t dll_name_raw = import_descriptor_raw + new_import_directory_size;
		uint32_t import_name_raw = dll_name_raw + dll_name_size;
		uint32_t thunk_data_raw = import_name_raw + import_name_size;


		uint32_t section_rva = is_wow64 ? optional_header32->SizeOfImage : optional_header64->SizeOfImage;
		uint32_t import_descriptor_rva = section_rva;
		uint32_t dll_name_rva = import_descriptor_rva + new_import_directory_size;
		uint32_t import_name_rva = dll_name_rva + dll_name_size;
		uint32_t thunk_data_rva = import_name_rva + import_name_size;

		uint32_t new_file_size = section_raw + new_section_size + file_padding;
		uint32_t new_image_size = section_rva + new_section_size + section_padding;

		std::unique_ptr<uint8_t[]> new_buffer = std::make_unique<uint8_t[]>(new_file_size);
		memcpy(new_buffer.get(), buffer.get(), size);
		buffer = std::move(new_buffer);
		parse();

		if (is_wow64)
		{
			optional_header32->SizeOfImage = new_image_size;
		}
		else
		{
			optional_header64->SizeOfImage = new_image_size;
		}
		size = new_file_size;

		IMAGE_SECTION_HEADER* new_section = section_header + nt_headers->FileHeader.NumberOfSections;
		memcpy(new_section->Name, ".idata", 7);
		new_section->VirtualAddress = section_rva;
		new_section->Misc.VirtualSize = new_section_size;
		new_section->PointerToRawData = section_raw;
		new_section->SizeOfRawData = new_section_size + file_padding;
		new_section->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

		nt_headers->FileHeader.NumberOfSections++;

		IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)(buffer.get() + section_raw);
		memcpy(import_descriptor, buffer.get() + import_directory_raw, import_directory_size);
		memcpy(buffer.get() + dll_name_raw, dll_name.c_str(), dll_name.length() + 1);
		memcpy(buffer.get() + import_name_raw + sizeof(IMAGE_IMPORT_BY_NAME::Hint), import_name.c_str(), import_name.length() + 1);

		while (import_descriptor->FirstThunk)
		{
			import_descriptor++;
		}
		import_descriptor->Name = dll_name_rva;
		import_descriptor->FirstThunk = thunk_data_rva;
		IMAGE_THUNK_DATA* firstThunk = (IMAGE_THUNK_DATA*)(buffer.get() + thunk_data_raw);
		firstThunk->u1.AddressOfData = import_name_rva;

		import_directory->VirtualAddress = section_rva;
		import_directory->Size = new_import_directory_size;

		wchar_t name[_MAX_FNAME];
		wchar_t ext[_MAX_EXT];
		_wsplitpath_s(file_path.native().c_str(), nullptr, 0, nullptr, 0, name, _MAX_FNAME, ext, _MAX_EXT);

		std::filesystem::path new_file_path = name;
		new_file_path += "_patched";
		new_file_path += ext;

		std::ofstream out(new_file_path, std::ios::binary);
		out.write((const char*)buffer.get(), size);
	}

	return EXIT_SUCCESS;
}