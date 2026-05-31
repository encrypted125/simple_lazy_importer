#pragma once
/**
 * @file simple_lazy.hpp
 * @brief stealthy single-header dynamic API resolver for Windows x64
 * * @author encrypted125
 * @date 1 June 2026
 * @version 1.0.0
 * * @see https://github.com/encrypted125/simple_lazy_importer
 * @license MIT License
 */

#define LAZY_CALLER
#ifdef LAZY_CALLER

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <cstdint>

namespace custom_lazy {
    // Custom structure bacause theese struct was in-accessible from normal user
    struct CUSTOM_UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    };

    // Only declare we really need
    struct CUSTOM_LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID      DllBase;
        PVOID      EntryPoint;
        ULONG      SizeOfImage;
        CUSTOM_UNICODE_STRING FullDllName;
        CUSTOM_UNICODE_STRING BaseDllName;
    };

    // On compile-time hash func (Fowler–Noll–Vo_hash_function)
    constexpr uint32_t hash_fnv1a(const char* str) {
        //FNV1A hash offset
        uint32_t hash = 2166136261u;

        while (*str) {
            char c = *str;

            // Convert function name to upper-case to avoid human error
            if (c >= 'A' && c <= 'Z') c += 32;

            // XOR the hash with converted string
            hash ^= static_cast<uint32_t>(c);

            // Multiply with FNV prime number
            hash *= 16777619u;

            str++;
        }

        return hash;
    }

    __forceinline uintptr_t get_export_address(uintptr_t module_base, uint32_t function_hash) {
        // Avoid access violations
        if (!module_base) return 0;

        // Check DOS Validity of that module by checking MZ (0x5A4D) At the base
        auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        // Check NT Header Validity is the Relative address of NT Header (0x4550) is valid or not
        auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(module_base + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return 0;

        // Find Entry of export function directory using OptionalHeader.DataDirectory
        auto export_dir_entry = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        // If there zero export then exit
        if (export_dir_entry.Size == 0) return 0;

        // Cast address by mod base + relative address of real export dir because windows ASLR security
        auto export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(module_base + export_dir_entry.VirtualAddress);

        // Grab the arrays that stored export data details
        auto names = reinterpret_cast<uint32_t*>(module_base + export_dir->AddressOfNames);
        auto functions = reinterpret_cast<uint32_t*>(module_base + export_dir->AddressOfFunctions);
        auto ordinals = reinterpret_cast<uint16_t*>(module_base + export_dir->AddressOfNameOrdinals);

        // Loop to finding target function address
        for (uint32_t i = 0; i < export_dir->NumberOfNames; ++i) {
            // Cast the address to string
            const char* func_name = reinterpret_cast<const char*>(module_base + names[i]);

            // Compare the hashed function name with target hashed function name
            if (hash_fnv1a(func_name) == function_hash) {
                uint16_t ordinal = ordinals[i];
                return module_base + functions[ordinal]; // Return real address of the target function
            }
        }

        // Returning defualt value as zero
        return 0;
    }


    // Declare the function name and struct of the functon and class preparing for create class (Primary template)
    template <uint32_t FunctionHash, typename T>
    class safe_invoker;

    // Declare the function code (Specialization)
    template <uint32_t FunctionHash, typename Ret, typename... Args>
    class safe_invoker<FunctionHash, Ret(__stdcall*)(Args...)> {
    public:
        // __forceinline force the complier to melt down the this code in to call point
        // operator() overload this to make can call through class with out func name
        __forceinline Ret operator()(Args... args) const {
            {
                // cached module base as static variables so its not need to heavy scan for the function everytime
                // because our function is force inline so will it will be perfectly cached in the code right there
                // its no way for conflinting and i choose to cached only module base because it risky for storing function addr in memory
                static uint64_t cached_module_base = 0x0;

#if defined(_M_X64)
                // Get PEB base address from GS Register offset 0x60
                auto peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
#else
#error Sorry simple importer was not support x32 Architecture i will do it supported soon!
#endif

                // Get PEB loader data get information about this process
                auto ldr = peb->Ldr;
                // Get address of the Loaded Module List Sort by address lower -> upper
                auto list_head = &ldr->InMemoryOrderModuleList;

                // fn_ptr declare the return value of the target function to make it ready to call function
                using fn_ptr = Ret(__stdcall*)(Args...);

                // is cached module base avaible
                if (!cached_module_base) {
                    // Looping Brute-Force way inside InMemoryOrderModuleList get target DLL base
                    // By continue go to next module (Flink or Forward-Link) uintil FLink match with the defualt Flink
                    // Because Linked-List was working in circular
                    for (auto it = list_head->Flink; it != list_head; it = it->Flink) {
                        // Get module entry from macro, Basically the it is always point to the next Module (Flink)
                        // So we need to resolve the entry by insert pointer it inside and insert big structure or our custom ldr data table
                        // Then insert the stucture of our it pointer (InMemoryOrderModuleList) into macro then we'll get the base address of current module
                        // Base = child_variables_pointer - child_structure_offset
                        auto entry = CONTAINING_RECORD(it, CUSTOM_LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);
                        if (!entry->BaseDllName.Buffer) continue;

                        // Convert windows wchar_t module name to char for converting
                        char dll_name[MAX_PATH] = { 0 };
                        for (USHORT i = 0; i < entry->BaseDllName.Length / sizeof(wchar_t); ++i) {
                            char c = static_cast<char>(entry->BaseDllName.Buffer[i]);

                            // Also convert to upper-case so when we compare with the hashed target module name it will be matched
                            if (c >= 'A' && c <= 'Z') c += 32;
                            dll_name[i] = c;
                        }

                        uintptr_t func_addr = get_export_address(reinterpret_cast<uint64_t>(entry->DllBase), FunctionHash);

                        // Is func pointer availible so its mean that function was found
                        if (func_addr) {
                            cached_module_base = reinterpret_cast<uint64_t>(entry->DllBase);

                            // Call the function with fn_ptr type and insert std::forward<Args>(args)... as arguments
                            // std::forward<Args>(args)... Why to need this function? We can just insert only args into function then call
                            // So the answer is forward function is parameter forwarding with no data loss or change anything
                            // Its mean the function recieve the same varaibles caller send everything not got change by compiler or anything
                            // I used for guarantee the defualt parameter in the coe does not get change on compile time for keep it still same same size same data
                            return reinterpret_cast<fn_ptr>(func_addr)(std::forward<Args>(args)...);
                        }
                    }
                }
                else {
                    uintptr_t func_addr = get_export_address(cached_module_base, FunctionHash);
                    if (func_addr) {
                        return reinterpret_cast<fn_ptr>(func_addr)(std::forward<Args>(args)...);
                    }
                }
            }
        }
    };
}

// Macro for more easier usage the lazy
// # means its will cover the func name with "" so if you call VirtualAlloc it will be custom_lazy::hash_fnv1a("VirtualAlloc")
// decltype(&func_name) mean? first decltype is vert useful data type it will dynamically change it self to target type definitions
// and how decltype(&func_name) its work the complier will goes to address &func_name and get type definitions and data type automatically
// and () this is for recieve arguments and being function if not have this complier gonna berate you 
#define SIMPLE_LAZY(func_name) \
    custom_lazy::safe_invoker<custom_lazy::hash_fnv1a(#func_name), decltype(&func_name)>()

#endif
