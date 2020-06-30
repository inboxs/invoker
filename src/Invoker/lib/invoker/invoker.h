// Copyright (c) 2019 Ivan Šincek

#ifndef INVOKER
#define INVOKER

#include <windows.h>
#include <string>

void print(std::string msg);

std::string trim(std::string str);

std::string input(std::string msg);

bool isPositiveNumber(std::string str);

void psExec(std::string encoded);

bool createFile(std::string file, std::string data = "");

std::string readFile(std::string file);

bool copyFile(std::string original, std::string copy);

bool downloadFile(std::string url, std::string out);

bool createRegKey(PHKEY hKey, std::string subkey, std::string name, std::string data);

bool scheduleTask(std::string name, std::string user, std::string file, std::string args = "");

bool reverseTcp(std::string ip, int port);

int getProcessId();

bool terminateProcess(int pid);

bool runProcess(std::string file, std::string args = "", PHANDLE hToken = NULL);

std::string getWebContent(std::string url, int port);

std::string extractPayload(std::string data, std::string element, std::string placeholder);

bool injectBytecode(int pid, std::string bytecode);

bool injectDll(int pid, std::string file);

void listDlls(int pid);

void enableAccessTokenPrivs();

HANDLE duplicateAccessToken(int pid);

std::string getUnquotedServiceName();

bool manipulateService(std::string name, int mode);

bool replaceStickyKeys();

struct hook {
	std::string file;
	HANDLE hThread;
	bool active;
};

void hookJob(struct hook* data);

HANDLE createHookThread(struct hook* data);

#endif

