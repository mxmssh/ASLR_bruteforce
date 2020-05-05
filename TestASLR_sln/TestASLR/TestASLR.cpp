#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <inttypes.h>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")
#define DEFAULT_BUFLEN 4096
#ifdef _WIN64
#define DEFAULT_PORT "27016"
#else
#define DEFAULT_PORT "27015"
#endif

void print_callback(const char* buf) {
    printf("%s\n", buf);
}

typedef struct vuln_structure {
    char buf[210];
    int offset;
} vuln_structure;

typedef struct overflown_structure {
    char buf[700]; // just to keep them adjusted
} overflown_structure;


uintptr_t GetModuleBaseAddresses(DWORD procId, const char* modName)
{
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
#ifndef _WIN64
                printf("Module %s base address is 0x%x\n", modEntry.szModule, modEntry.modBaseAddr);
#else
                printf("Module %s base address is 0x%llx\n", modEntry.szModule, modEntry.modBaseAddr);
#endif
                /*if (!_strcmpi(modEntry.szModule, modName))
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }*/
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}

int main()
{
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo* result = NULL;
    struct addrinfo hints;

    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    GetModuleBaseAddresses(GetCurrentProcessId(), "KERNEL32.DLL");
    //return 0; for ASLR entropy check experiment with rebooting
    HANDLE hDLL = LoadLibrary("KERNEL32.DLL");
    uintptr_t createproc_address = (uintptr_t)GetProcAddress((HMODULE)hDLL, "CreateProcessA");
#ifndef _WIN64
    union bytes_32 {
        unsigned char c[4];
        uint32_t l;
    } bytes32;
    printf("Kernel32.dll!CreateProcessA address = 0x%x\n", createproc_address);
#else
    union bytes_64 {
        unsigned char c[8];
        uint64_t l;
    } bytes64;
    printf("Kernel32.dll!CreateProcessA address = 0x%llx\n", createproc_address);
#endif
    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // No longer need server socket
    closesocket(ListenSocket);

    // Receive until the peer shuts down the connection
    do {

        iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0) {
            printf("Bytes received: %d\n", iResult);
            if (iResult == 8) {
                bool correct = FALSE;
#ifndef _WIN64
                for (int i = 0; i < 4; i++)
                    bytes32.c[i] = recvbuf[i];
                printf("Kernel32 predicted address = 0x%x\n", bytes32.l);
                /* Comparing base address of the current module with the one guessed by an attacker */
                if (bytes32.l == createproc_address)
                    correct = TRUE;
#else
                for (int i = 0; i < 8; i++)
                    bytes64.c[i] = recvbuf[i];
                printf("Kernel32 predicted address = 0x%llx\n", bytes64.l);
                if (bytes64.l == createproc_address)
                    correct = TRUE;
#endif
                if (correct) {
                    send(ClientSocket, "Correct", strlen("Correct"), 0);
                    return 2;
                }
                else {
                    send(ClientSocket, "Wrong", strlen("Wrong"), 0);
                }
            }
        }
        else if (iResult == 0)
            printf("Connection closing...\n");
        else {
            printf("recv failed with error: %d\n", WSAGetLastError());
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }

    } while (iResult > 0);

    // shutdown the connection since we're done
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(ClientSocket);
    WSACleanup();
}
