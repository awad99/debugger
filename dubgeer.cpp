#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include "include/capstone/capstone.h"
#include "include/keystone/keystone.h"
#include <string>
#include <map>
#include <vector>
#include <sstream>
#pragma comment(lib, "User32.lib")

MODULEENTRY32 me32;
PROCESSENTRY32 pe32 = { 0 };
#define START_ADDRESS 0x7ccd91
//0x012362ed
#define BP_SIZE 1
DWORD instruction_normal = 0xCC;
CONTEXT* context = { 0 };
const char modrm_value[8][4] = {
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"
};

int decode_operand(unsigned char* buffer, int location) {
    if (buffer[location] >= 0xC0 && buffer[location] <= 0xFF) {
        printf("%s, %s", modrm_value[(buffer[location] >> 3) & 7], modrm_value[buffer[location] & 7]);
        return 1;
    }
    else if (buffer[location] >= 0x80 && buffer[location] <= 0xBF)
    {
        DWORD displacement = buffer[location + 1] | buffer[location + 2] << 8 | buffer[location + 3] >> 16 | buffer[location + 4] >> 24;
        printf("[%s+%x]%s", modrm_value[buffer[location] % 8], displacement, modrm_value[(buffer[location] % 8)]);
        return 5;
    }
    else if (buffer[location] >= 0x40 && buffer[location] <= 0x79)
    {
        printf("[%s+%x], %s", modrm_value[buffer[location] % 8], buffer[location] + 1, modrm_value[buffer[location >> 3] % 8]);
        return 2;
    }
    return 0;
}

//void simpledisassmbler(unsigned char* buffer, unsigned int& i) {
//    DWORD loc = 0;
//    switch (buffer[i]) {
//        // Arithmetic instructions
//    case 0x01: case 0x83: case 0x81:
//        printf("ADD ");
//        i++;
//        i += decode_operand(buffer, i);
//        break;
//
//    case 0x29: case 0x2B:
//        printf("SUB ");
//        i++;
//        i += decode_operand(buffer, i);
//        break;
//
//    case 0x31: case 0x33:
//        printf("XOR ");
//        i++;
//        i += decode_operand(buffer, i);
//        break;
//
//        // Data transfer
//    case 0x89:
//        printf("MOV ");
//        i++;
//        i += decode_operand(buffer, i);
//        break;
//
//    case 0x8B:
//        printf("MOV ");
//        i++;
//        i += decode_operand(buffer, i);
//        break;
//
//    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
//    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
//        printf("MOV %s, 0x%X", modrm_value[buffer[i] - 0xB8], *(DWORD*)(buffer + i + 1));
//        i += 5;
//        break;
//
//        // Control flow
//    case 0x74:
//        printf("JE 0x%08X", me32.modBaseAddr + i + 2 + (signed char)buffer[i + 1]);
//        i += 2;
//        break;
//
//    case 0x75:
//        printf("JNE 0x%08X", me32.modBaseAddr + i + 2 + (signed char)buffer[i + 1]);
//        i += 2;
//        break;
//
//    case 0xE8:
//        loc = *(DWORD*)(buffer + i + 1);
//        printf("CALL 0x%08X", me32.modBaseAddr + i + 5 + loc);
//        i += 5;
//        break;
//
//    case 0xE9:
//        loc = *(DWORD*)(buffer + i + 1);
//        printf("JMP 0x%08X", me32.modBaseAddr + i + 5 + loc);
//        i += 5;
//        break;
//
//        // Stack operations
//    case 0x50: case 0x51: case 0x52: case 0x53:
//    case 0x54: case 0x55: case 0x56: case 0x57:
//        printf("PUSH %s", modrm_value[buffer[i] - 0x50]);
//        i++;
//        break;
//
//    case 0x58: case 0x59: case 0x5A: case 0x5B:
//    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
//        printf("POP %s", modrm_value[buffer[i] - 0x58]);
//        i++;
//        break;
//
//        // Miscellaneous
//    case 0x90:
//        printf("NOP");
//        i++;
//        break;
//
//    case 0xC3:
//        printf("RET");
//        i++;
//        break;
//
//    default:
//        printf("0x%02X", buffer[i]);
//        i++;
//        break;
//    }
//    printf("\n");
//}

// Capstone handle should be global for reuse
csh cs_handle;
bool cs_initialized = false;

typedef struct {
    DWORD base_address;
    DWORD module_size;
} ModuleInfo;

//void InitializeCapstone() {
//    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) == CS_ERR_OK) {
//        cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
//        cs_initialized = true;
//    }
//}

// Updated disassembler function with buffer size checking.
void disassembler(unsigned char* buffer, DWORD base_address, DWORD start_offset, DWORD buffer_size) {
    csh handle;
    cs_insn* insn = nullptr;

    // Initialize Capstone for x86 32-bit
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
        std::cerr << "Failed to initialize Capstone" << std::endl;
        return;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // Define how many bytes you want to disassemble.
    const DWORD region_size = 0x500; // adjust this value as needed

    // Validate that the disassembly region is within the module's memory.
    if (start_offset >= buffer_size || (start_offset + region_size) > buffer_size) {
        std::cerr << "Invalid disassembly region: start_offset or region_size exceeds module size" << std::endl;
        cs_close(&handle);
        return;
    }

    DWORD current_offset = start_offset;
    const DWORD end_offset = start_offset + region_size;

    // Loop through the memory range and disassemble instructions.
    while (current_offset < end_offset) {
        size_t count = cs_disasm(
            handle,
            buffer + current_offset,
            end_offset - current_offset,
            base_address + current_offset,
            1,  // Disassemble one instruction at a time.
            &insn
        );

        if (count > 0) {
            // Print the disassembled instruction.
            printf("0x%08X: %-8s %s\n",
                base_address + current_offset,
                insn[0].mnemonic,
                insn[0].op_str);
            current_offset += insn[0].size;
            cs_free(insn, count);
        }
        else {
            // If disassembly fails, print the raw byte.
            printf("0x%08X: 0x%02X\n",
                base_address + current_offset,
                buffer[current_offset]);
            current_offset++;
        }
    }
    cs_close(&handle);
}


void PrintRegisters(CONTEXT* context) {
    printf("\nRegisters:\n");
    printf("EAX: 0x%08X\n", context->Eax);
    printf("EBX: 0x%08X\n", context->Ebx);
    printf("ECX: 0x%08X\n", context->Ecx);
    printf("EDX: 0x%08X\n", context->Edx);
    printf("ESI: 0x%08X\n", context->Esi);
    printf("EDI: 0x%08X\n", context->Edi);
    printf("ESP: 0x%08X\n", context->Esp);
    printf("EBP: 0x%08X\n", context->Ebp);
    printf("EIP: 0x%08X\n", context->Eip);
}
std::string getLastErrorAsString()
{
    DWORD err = GetLastError();

    if (!err) { return ""; } //no error


    char* message = 0;

    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        0, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&message, 0, nullptr);

    std::string rez(message, size); //copy the data into a string

    LocalFree(message); //FORMAT_MESSAGE_ALLOCATE_BUFFER allocates memory for us so we need to clear it.

    return rez;
}
void Stepinto(HANDLE Process, HANDLE thread, CONTEXT* context)
{
    DEBUG_EVENT debugEvent = { 0 };

    // Enable single-step mode
    context->EFlags |= 0x100;
    if (!SetThreadContext(thread, context))
    {
        printf("SetThreadContext failed. Error: %lu\n", getLastErrorAsString());
        return;
    }

    // Resume execution
    if (!ContinueDebugEvent(GetProcessId(Process), GetThreadId(thread), DBG_CONTINUE))
    {
        printf("ContinueDebugEvent failed. Error: %lu\n", getLastErrorAsString());
        return;
    }

    // Wait for the next debug event
    if (!WaitForDebugEvent(&debugEvent, INFINITE))
    {
        printf("WaitForDebugEvent failed. Error: %lu\n", getLastErrorAsString());
        return;
    }

    // Handle single-step event
    if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
        debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        context->ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(thread, context))
        {
            printf("GetThreadContext failed. Error: %lu\n", getLastErrorAsString());
            return;
        }

        PrintRegisters(context);

        printf("Process stepped into the next instruction. Press Enter to continue...\n");
        while (true)
        {
            if (GetAsyncKeyState(VK_RETURN) & 0x8000) {
                break;
            }
            Sleep(100);
        }
    }
}



DWORD SetHardwareBreakpoint(HANDLE hProcess, DWORD address, BYTE& original) {
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, (LPVOID)address, BP_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect))
        return 0;

    if (!ReadProcessMemory(hProcess, (LPVOID)address, &original, BP_SIZE, NULL)) {
        VirtualProtectEx(hProcess, (LPVOID)address, BP_SIZE, oldProtect, &oldProtect);
        return 0;
    }

    BYTE int3 = 0xCC;
    if (!WriteProcessMemory(hProcess, (LPVOID)address, &int3, BP_SIZE, NULL)) {
        VirtualProtectEx(hProcess, (LPVOID)address, BP_SIZE, oldProtect, &oldProtect);
        return 0;
    }

    VirtualProtectEx(hProcess, (LPVOID)address, BP_SIZE, oldProtect, &oldProtect);
    return 1;
}
DEBUG_EVENT debugEvent;
void StepOut(HANDLE hProcess, HANDLE hThread, CONTEXT* context)
{
    if (!context) {
        printf("Error: Null context passed to StepOut\n");
        return;
    }

    DWORD returnAddress;
    if (!ReadProcessMemory(hProcess, (LPVOID)context->Esp, &returnAddress, sizeof(returnAddress), NULL)) {
        printf("ReadProcessMemory Failed. Error: %lu\n", GetLastError());
        return;
    }

    // Store original byte
    BYTE original_byte;
    if (!ReadProcessMemory(hProcess, (LPCVOID)returnAddress, &original_byte, 1, NULL)) {
        printf("ReadProcessMemory Failed. Error: %lu\n", GetLastError());
        return;
    }

    // Set software breakpoint (INT3 - 0xCC)
    BYTE int3 = 0xCC;
    if (!WriteProcessMemory(hProcess, (LPVOID)returnAddress, &int3, 1, NULL)) {
        printf("WriteProcessMemory Failed. Error: %lu\n", GetLastError());
        return;
    }

    // Continue execution
    if (!ContinueDebugEvent(GetCurrentProcessId(), GetCurrentThreadId(), DBG_CONTINUE)) {
        printf("ContinueDebugEvent Failed. Error: %lu\n", GetLastError());
        return;
    }

    // Wait for breakpoint hit
    DEBUG_EVENT debugEvent;
    while (true) {
        if (!WaitForDebugEvent(&debugEvent, INFINITE)) {
            printf("WaitForDebugEvent failed. Error: %lu\n", GetLastError());
            return;
        }

        if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            if (debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                if ((DWORD)debugEvent.u.Exception.ExceptionRecord.ExceptionAddress == returnAddress) {
                    // Restore original byte
                    if (!WriteProcessMemory(hProcess, (LPVOID)returnAddress, &original_byte, 1, NULL)) {
                        printf("WriteProcessMemory failed. Error %lu\n", GetLastError());
                        return;
                    }
                    break;
                }
            }
        }

        // Continue other debug events
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
    }

    // Refresh context
    context->ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(hThread, context)) {
        printf("GetThreadContext failed. Error %lu\n", GetLastError());
        return;
    }

    PrintRegisters(context);
}



void StepOver(HANDLE hProcess, HANDLE hThread) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;

    if (!GetThreadContext(hThread, &ctx)) {
        printf("GetThreadContexr falied: %lu\n", getLastErrorAsString());
        return;
    }

    DWORD retAddr;
    if (!ReadProcessMemory(hProcess, (LPVOID)(ctx.Esp), &retAddr, sizeof(DWORD), NULL)) {
        printf("Falied to read return address: %lu\n", getLastErrorAsString());
        return;
    }

    BYTE original;
    SetHardwareBreakpoint(hProcess, retAddr, original);

    ctx.EFlags &= ~0x100;
    SetThreadContext(hThread, &ctx);
    ContinueDebugEvent(GetCurrentProcessId(), GetCurrentThreadId(), DBG_CONTINUE);

    DEBUG_EVENT dbgEvent;
    while (WaitForDebugEvent(&dbgEvent, INFINITE)) {
        if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
            && dbgEvent.dwDebugEventCode == EXCEPTION_BREAKPOINT) {

            WriteProcessMemory(hProcess, (LPVOID)retAddr, &original, BP_SIZE, NULL);
            break;
        }
        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
    }
}
BYTE original_byte = 0;
CONTEXT global_context = { 0 };


void patchValue(HANDLE hProcess, DWORD baseAddress, DWORD offset, const std::string& assemblyCode) {
    ks_engine* ks;
    int err;
    size_t count;
    unsigned char* encoded = nullptr;
    size_t size = 0;

    // Open Keystone engine
    err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
    if (err != KS_ERR_OK) {
        printf("Failed to open Keystone engine. Error: %s\n", ks_strerror((ks_err)err));
        return;
    }

    // Assemble the code; the starting address is baseAddress + offset.
    DWORD patchAddress = baseAddress + offset;
    err = ks_asm(ks, assemblyCode.c_str(), patchAddress, &encoded, &size, &count);
    if (err != KS_ERR_OK) {
        printf("Failed to assemble instruction. Error: %s\n", ks_strerror((ks_err)err));
        ks_close(ks);
        return;
    }

    // Change the protection of the target memory to PAGE_EXECUTE_READWRITE
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, (LPVOID)patchAddress, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Failed to change memory protection. Error: %lu\n", GetLastError());
        ks_free(encoded);
        ks_close(ks);
        return;
    }

    // Write the patched code directly into the target process memory.
    DWORD bytesWritten;
    if (!WriteProcessMemory(hProcess, (LPVOID)patchAddress, encoded, size, &bytesWritten)) {
        printf("Failed to write process memory. Error: %lu\n", GetLastError());
    }
    else {
        printf("Patched 0x%08X with: %s\n", patchAddress, assemblyCode.c_str());
    }

    // Restore the original memory protection
    DWORD temp;
    VirtualProtectEx(hProcess, (LPVOID)patchAddress, size, oldProtect, &temp);

    ks_free(encoded);
    ks_close(ks);
}


std::map<std::string, unsigned char> opcodeMap = {
    {"ADD", 0x01}, {"SUB", 0x29}, {"MOV", 0x89},
    {"CMP", 0x80}, {"JE", 0x74}, {"CALL", 0xE8},
    {"LEA", 0x8D}, {"NOP", 0x90}
};

std::map<std::string, int> registerMap = {
    {"eax", 0}, {"ecx", 1}, {"edx", 2}, {"ebx", 3},
    {"esp", 4}, {"ebp", 5}, {"esi", 6}, {"edi", 7}
};

std::vector<unsigned char> assembleInstruction(const std::string& instruction, unsigned int& i, unsigned char* buffer) {
    std::vector<unsigned char> bytes;
    std::string op;
    std::vector<std::string> operands;

    // Parse instruction
    size_t space = instruction.find(' ');
    if (space == std::string::npos) {
        // Handle no-operand instructions
        op = instruction;
    }
    else {
        op = instruction.substr(0, space);
        std::string args = instruction.substr(space + 1);
        size_t comma = args.find(',');
        if (comma != std::string::npos) {
            operands.push_back(args.substr(0, comma));
            operands.push_back(args.substr(comma + 2));
        }
        else {
            operands.push_back(args);
        }
    }

    // Convert to opcode
    if (op == "MOV") {
        bytes.push_back(0x89);  // Default MOV r/m32, r32
        if (operands.size() == 2) {
            int mod = 0xC0;
            decode_operand(buffer, i);
        }
    }
    else if (op == "ADD") {
        bytes.push_back(0x01);
        if (operands.size() == 2) {
            int mod = 0xC0;
            decode_operand(buffer, i);
        }
    }
    else if (op == "NOP") {
        bytes.push_back(0x90);
    }
    else if (op == "JE") {
        bytes.push_back(0x74);
        // Relative address placeholder (needs calculation)
        bytes.push_back(0x00);
    }
    // Add more instructions here...

    return bytes;
}

void mypatchValue(unsigned char* mainBuffer) {  // Renamed parameter for clarity
    std::string readAddressStr, assemblyCode;
    std::cout << "Enter address to patch (hex): ";
    std::cin >> readAddressStr;
    DWORD patchAddress = strtoul(readAddressStr.c_str(), NULL, 16);

    std::cout << "Enter assembly instructions (e.g., 'MOV eax, ebx'):\n";
    std::cin.ignore();
    std::getline(std::cin, assemblyCode);

    // Split multiple instructions
    std::istringstream iss(assemblyCode);
    std::string instruction;
    std::vector<unsigned char> newBytes;

    while (std::getline(iss, instruction, ';')) {
        // Clean up instruction
        instruction.erase(std::remove_if(instruction.begin(), instruction.end(),
            [](unsigned char c) { return std::isspace(c) && c != ' '; }),
            instruction.end());

        // Trim leading/trailing spaces
        size_t start = instruction.find_first_not_of(" ");
        size_t end = instruction.find_last_not_of(" ");
        if (start != std::string::npos)
            instruction = instruction.substr(start, end - start + 1);

        if (!instruction.empty()) {
            unsigned int dummy_i = 0;  // Temporary variable if needed
            std::vector<unsigned char> bytes = assembleInstruction(instruction, dummy_i, mainBuffer);
            if (bytes.empty()) {
                std::cerr << "Failed to assemble: " << instruction << "\n";
                continue;
            }
            newBytes.insert(newBytes.end(), bytes.begin(), bytes.end());
        }
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
    if (hProcess) {
        DWORD oldProtect;
        if (VirtualProtectEx(hProcess, (LPVOID)patchAddress, newBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            DWORD bytesWritten;
            if (WriteProcessMemory(hProcess, (LPVOID)patchAddress, newBytes.data(), newBytes.size(), &bytesWritten)) {
                std::cout << "Patched " << bytesWritten << " bytes successfully!\n";

                // Verification buffer (local allocation)
                unsigned char* verificationBuffer = new unsigned char[newBytes.size()];
                if (ReadProcessMemory(hProcess, (LPCVOID)patchAddress, verificationBuffer, newBytes.size(), NULL)) {
                    unsigned int i = 0;
                    while (i < newBytes.size()) {
                        printf("%08X: ", patchAddress + i);
                        simpledisAssmbler(i, verificationBuffer);
                    }
                }
                delete[] verificationBuffer;  // Clean up verification buffer
            }
            else {
                std::cout << "Patch failed! Error: " << GetLastError() << "\n";
            }
            VirtualProtectEx(hProcess, (LPVOID)patchAddress, newBytes.size(), oldProtect, &oldProtect);
        }
        CloseHandle(hProcess);
    }
    else {
        std::cerr << "Failed to open process! Error: " << GetLastError() << "\n";
    }
}

void DebugLoop(DWORD pid, HANDLE hProcess)
{
    DEBUG_EVENT debugEvent = { 0 };
    bool first_break = true;

    if (!DebugActiveProcess(pid)) {
        std::cerr << "DebugActiveProcess failed: " << getLastErrorAsString() << std::endl;
        return;
    }

    while (WaitForDebugEvent(&debugEvent, INFINITE)) {
        DWORD continueStatus = DBG_EXCEPTION_NOT_HANDLED;

        switch (debugEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT: {
            if (debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
                if (hThread) {
                    // Initialize context properly
                    CONTEXT context = { 0 };
                    context.ContextFlags = CONTEXT_ALL;

                    if (!GetThreadContext(hThread, &context)) {
                        printf("GetThreadContext failed. Error: %lu\n", getLastErrorAsString());
                        CloseHandle(hThread);
                        break;
                    }

                    if (first_break) {
                        // Initial breakpoint setup
                        first_break = false;
                    }

                    PrintRegisters(&context);

                    // Use proper key handling
                    while (true) {
                        if (GetAsyncKeyState('S') & 0x8000) {
                            Stepinto(hProcess, hThread, &context);  // Pass actual context
                            break;
                        }
                        else if (GetAsyncKeyState('E') & 0x8000) {
                            StepOut(hProcess, hThread, &context);  // Pass actual context
                            break;
                        }
                        else if (GetAsyncKeyState('A') & 0x8000) {
                            StepOver(hProcess, hThread);  // Pass actual context
                            break;
                        }
                        else if (GetAsyncKeyState('Q') & 0x8000) {
                            DebugActiveProcessStop(pid);
                            CloseHandle(hThread);
                            return;
                        }
                        Sleep(100);
                    }
                    CloseHandle(hThread);
                }
                continueStatus = DBG_CONTINUE;
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            continueStatus = DBG_CONTINUE;
            break;
        default:
            break;
        }
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus);
    }
}

void ReadUserInput(DWORD& breakpointAddress) {
    std::string Readkey;
    std::cout << "Enter E to set a breakpoint and enter the address: " << std::endl;
    std::cin >> Readkey;

    if (Readkey == "e" || Readkey == "E") {
        std::cout << "Enter the address (in hexadecimal, e.g., 0x12345678): ";
        std::string addressInput;
        std::cin >> addressInput;

        // Convert address string from hexadecimal to DWORD (address type)
        breakpointAddress = strtoul(addressInput.c_str(), NULL, 16);

        std::cout << "Breakpoint set at address: 0x" << std::hex << breakpointAddress << std::endl;
    }
}

std::string readpatchvalue(DWORD& address) {
    char answer = 'n';
    do {
        std::cout << "Do you want to make a patch? [y/n]? ";
        std::cin >> answer;
    } while (answer != 'y' && answer != 'n');

    // If the answer is 'n', return an empty string.
    if (answer == 'n') {
        return "";
    }

    std::cout << "Enter the address you want to patch (hex): ";
    std::cin >> std::hex >> address;

    std::string assemblyCode;
    std::cout << "Enter new instructions: ";
    std::cin.ignore(); // Clear leftover newline.
    std::getline(std::cin, assemblyCode);

    return assemblyCode;
}


int main() {
    DWORD targetPid = 0;
    //   ModuleInfo moduleInfo = { 0 };
       // Process finding logic
    HANDLE process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

    if (Process32First(process_snapshot, &pe32)) {
        do {

            if (wcscmp(pe32.szExeFile, L"tru.exe") == 0) {
                HANDLE module_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    MODULEENTRY32 me32;
                    me32.dwSize = sizeof(MODULEENTRY32);

                    // Iterate through modules
                    do {
                        if (wcscmp(me32.szModule, L"tru.exe") == 0) {
                            // Read the module memory
                            unsigned char* buffer = new unsigned char[me32.modBaseSize];
                            DWORD bytesRead;
                            ReadProcessMemory(hProcess, me32.modBaseAddr, buffer, me32.modBaseSize, &bytesRead);
                            const DWORD base_address = (DWORD)me32.modBaseAddr;
                            const DWORD start_offset = START_ADDRESS - base_address;

                            // Optionally check if the requested disassembly region is within the module
                            //if (start_offset > me32.modBaseSize || (start_offset + 0x50) > me32.modBaseSize) {
                            //    std::cout << "Invalid memory range" << std::endl;
                            //    delete[] buffer;
                            //    continue;
                            //}
                            // Disassemble the block (this function loops internally)
                            disassembler(buffer, base_address, start_offset, me32.modBaseSize);


                            DWORD userAddress;
                            std::string assemblyCode = readpatchvalue(userAddress);
                            DWORD offset = userAddress - (DWORD)me32.modBaseAddr;
                            patchValue(hProcess, (DWORD)me32.modBaseAddr, offset, assemblyCode);

                            delete[] buffer;
                        }
                    } while (Module32Next(module_snapshot, &me32));
                    CloseHandle(hProcess);

                    // Wait for user input and possibly set a breakpoint
                    DWORD breakpointAddress = 0;
                    ReadUserInput(breakpointAddress);

                    if (breakpointAddress != 0) {
                        DebugLoop(pe32.th32ProcessID, hProcess);
                        printf("Breakpoint set at address: 0x%08X\n", breakpointAddress);

                        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                        if (hThread) {
                            CONTEXT context = { 0 };
                            context.ContextFlags = CONTEXT_ALL;
                            if (GetThreadContext(hThread, &context)) {
                                Stepinto(hProcess, hThread, &context);
                            }
                            CloseHandle(hThread);
                        }
                    }


                }
            }

        } while (Process32Next(process_snapshot, &pe32));
        CloseHandle(process_snapshot);

        return 0;
    }
}