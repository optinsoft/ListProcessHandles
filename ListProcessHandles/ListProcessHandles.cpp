////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ListProcessHandles.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
// Author: vitaly (optinsoft), https://github.com/optinsoft
// Created: 2025-01-21
// License: MIT
// Dependency: phnt from https://github.com/winsiderss/systeminformer/tree/master/phnt
// 
////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <iostream>
#include "SysInfo.h"
#include <tchar.h>
#include <vector>
#include <cstdlib>

_tstring format_file_time(FILETIME& ft, const LPCTSTR lpPrefix, BOOL bConvertToLocal = TRUE)
{
	const TCHAR* day[] = { _T("Sunday"),_T("Monday"),_T("Tuesday"),_T("Wednesday"),_T("Thursday"),_T("Friday"),_T("Saturday") };
	const TCHAR* month[] = { _T("January"),_T("February"),_T("March"),_T("April"),_T("May"),_T("June"),_T("July"),_T("August"),_T("September"),_T("October"),_T("November"),_T("December") };
	FILETIME* pFt = &ft;
	FILETIME local_ft;
	if (bConvertToLocal) {
		if (!FileTimeToLocalFileTime(&ft, &local_ft))
		{
			DWORD err = GetLastError();
			return SysInfoUtils::StringFormat(_T("FileTimeToLocalFileTime() failed with error %lu"), err);
		}
		pFt = &local_ft;
	}
	SYSTEMTIME sys = { 0 };
	if (FileTimeToSystemTime(pFt, &sys)) {
		//return SysInfoUtils::StringFormat(_T("%s%s, %s %hu, %hu %.2hu:%.2hu:%.2hu.%.3huZ"), lpPrefix, day[sys.wDayOfWeek], month[sys.wMonth - 1], sys.wDay, sys.wYear, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds);
		return SysInfoUtils::StringFormat(_T("%s%.4hu-%.2hu-%2hu %.2hu:%.2hu:%.2hu.%.3huZ"), lpPrefix, sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds);
	}
	else {
		DWORD err = GetLastError();
		return SysInfoUtils::StringFormat(_T("FileTimeToSystemTime() failed with error %lu"), err);
	}
}

std::uint64_t get_running_time(FILETIME* pStartTime, FILETIME* pCurrentTime)
{
	auto u64CreationTime = (static_cast<std::uint64_t>(pStartTime->dwHighDateTime) << 32) | pStartTime->dwLowDateTime;
	auto u64CurrentTime = (static_cast<std::uint64_t>(pCurrentTime->dwHighDateTime) << 32) | pCurrentTime->dwLowDateTime;
	auto u64RunningTime = u64CurrentTime - u64CreationTime;
	return u64RunningTime;
}

_tstring format_running_time(FILETIME* pStartTime, FILETIME* pCurrentTime)
{
	auto u64RunningTime = get_running_time(pStartTime, pCurrentTime);
	auto u64RunningMilliSeconds = u64RunningTime / 10000;
	auto u64RunningSeconds = u64RunningMilliSeconds / 1000;
	DWORD dwRunningMilliSeconds = (DWORD)(u64RunningMilliSeconds % 1000);
	auto u64RunningMinutes = u64RunningSeconds / 60;
	DWORD dwRunningSeconds = (DWORD)(u64RunningSeconds % 60);
	auto u64RunningHours = u64RunningMinutes / 60;
	DWORD dwRunningMinutes = (DWORD)(u64RunningMinutes % 60);
	DWORD dwRunningDays = (DWORD)(u64RunningHours / 24);
	DWORD dwRunningHours = (DWORD)(u64RunningHours % 24);
	_tstring result = _T("");
	if (dwRunningDays > 0) {
		result = result + SysInfoUtils::StringFormat(_T("%lu day%s, "), dwRunningDays, (dwRunningDays == 1 ? _T("") : _T("s")));
	}
	/*
	if (dwRunningHours > 0 || dwRunningDays > 0) {
		result = result + SysInfoUtils::StringFormat(_T("%lu hour%s, "), dwRunningHours, (dwRunningHours == 1 ? _T("") : _T("s")));
	}
	if (dwRunningMinutes > 0 || dwRunningHours > 0 || dwRunningDays > 0) {
		result = result + SysInfoUtils::StringFormat(_T("%lu minute%s, "), dwRunningMinutes, (dwRunningMinutes == 1 ? _T("") : _T("s")));
	}
	result = result + SysInfoUtils::StringFormat(_T("%lu second%s, %lu millisecond%s"), 
		dwRunningSeconds, (dwRunningSeconds == 1 ? _T("") : _T("s")),
		dwRunningMilliSeconds, (dwRunningMilliSeconds == 1 ? _T("") : _T("s")));
	*/
	result = result + SysInfoUtils::StringFormat(_T("%.2lu:%.2lu:%.2lu.%.3luZ"), dwRunningHours, dwRunningMinutes, dwRunningSeconds, dwRunningMilliSeconds);
	return result;
}

void print_process_info(DWORD dwProcessID, SYSTEM_PROCESS_INFORMATION* pSysProcess, SysHandleInformation* pHi, FILETIME* pCurrentTime, BOOL bTerminate)
{
	_tstring strName = pSysProcess->ImageName.Length > 0 ? SysInfoUtils::Unicode2String(&pSysProcess->ImageName) : _T("");
	auto u64MemSize = pSysProcess->WorkingSetPrivateSize.QuadPart;
	DWORD dwMemSizeMB = (DWORD)(u64MemSize >> 20);
	DWORD dwMemSizeDP = (DWORD)(u64MemSize & 0xFFFFF) * 10 / 0x100000;
	FILETIME CreationTime, ExitTime, KernelTime, UserTime;
	BOOL bProcessTimes = pHi->GetProcessTimes((HANDLE)-1, &CreationTime, &ExitTime, &KernelTime, &UserTime, dwProcessID);
	_tstring sTimeInfo = _T("");
	if (bProcessTimes) {
		sTimeInfo = format_file_time(CreationTime, _T("Started at: "));
		if (pCurrentTime != NULL) {
			sTimeInfo = sTimeInfo + _T(", Running: ") + format_running_time(&CreationTime, pCurrentTime);
		}
	}
	else {
		DWORD err = GetLastError();
		sTimeInfo = SysInfoUtils::StringFormat(_T("GetProcessTimes() failed with error %lu"), err);
	}
	_tprintf(_T("PID: %lu, Name: %s, Mem. Used: %lu.%lu MB, %s%s\n"), dwProcessID, strName.c_str(), dwMemSizeMB, dwMemSizeDP, sTimeInfo.c_str(), (bTerminate ? _T(" [T]") : _T("")));
}

void list_processes_and_handles(LPCTSTR lpProcessNameFilter, LPCTSTR lpHandleTypeFilter, LPCTSTR lpFsPathFilter, BOOL bHandleProcessFilter = TRUE, 
	BOOL bTerminateFilteredProcesses = FALSE, DWORD dwTerminateMemSizeMB = 0, DWORD dwTerminateRunningTime = 0, BOOL bSilentTerminate = FALSE,
	BOOL bPrintProcessFilterInfo = FALSE, BOOL bPrintFileHandleName = FALSE, BOOL bPrintFilteredProcesses = TRUE)
{
	FILETIME CurrentTime;
	GetSystemTimeAsFileTime(&CurrentTime);

	SysProcessInformation pi;
	SysHandleInformation hi(bHandleProcessFilter, FALSE);

	if (!pi.SetNameFilter(lpProcessNameFilter, TRUE))
	{
		_tprintf(_T("SysProcessInformation::SetNameFilter() failed.\n"));
		return;
	}

	if (pi.m_ProcessInfos.size() == 0)
	{
		_tprintf(_T("No processes found.\n"));
		return;
	}

	for (auto it = pi.m_ProcessInfos.begin(); it != pi.m_ProcessInfos.end(); ++it)
	{
		DWORD dwProcessID = it->first;
		if (bPrintProcessFilterInfo) {
			SYSTEM_PROCESS_INFORMATION* pSysProcess = it->second;
			print_process_info(dwProcessID, pSysProcess, &hi, &CurrentTime, FALSE);
		}
		if (bHandleProcessFilter) {
			hi.AddProcessFilter(dwProcessID);
		}
	}

	if (!hi.SetTypeFilter(lpHandleTypeFilter, TRUE))
	{
		_tprintf(_T("SysHandleInformation::SetTypeFilter() failed.\n"));
		return;
	}

	if (hi.m_HandleInfos.size() == 0)
	{
		_tprintf(_T("No handles found.\n"));
		return;
	}

	_tstring name;
	_tstring typeName;
	WORD type = SysHandleInformation::OB_TYPE_UNKNOWN;
	std::set<DWORD> filteredProcesses;
	std::set<DWORD> terminateProcesses;

	for (auto it = hi.m_HandleInfos.begin(); it != hi.m_HandleInfos.end(); ++it)
	{
		const SYSTEM_HANDLE_TABLE_ENTRY_INFO& h = *it;

		DWORD dwProcessID = (DWORD)h.UniqueProcessId;

		hi.GetName((HANDLE)h.HandleValue, name, dwProcessID);

		hi.GetTypeToken((HANDLE)h.HandleValue, typeName, dwProcessID);

		hi.GetTypeFromTypeToken(typeName.c_str(), type);

		_tstring fsPath = _T("");

		BOOL bFilterOut = lpFsPathFilter != NULL && *lpFsPathFilter;

		if (type == SysHandleInformation::OB_TYPE_FILE) {
			SysInfoUtils::GetFsFileName(name.c_str(), fsPath);
			bFilterOut = bFilterOut && _tcsstr(fsPath.c_str(), lpFsPathFilter) == NULL;
		}

		if (!bFilterOut) {
			if (bPrintFileHandleName) {
				_tprintf(_T("%s Handle: %hu, PID: %lu, Name: %s\n"), typeName.c_str(), h.HandleValue, dwProcessID, name.c_str());
			} 
			else {
				_tprintf(_T("%s Handle: %hu, PID: %lu\n"), typeName.c_str(), h.HandleValue, dwProcessID);
			}
			if (fsPath != _T("")) {
				_tprintf(_T("File Path: %s\n"), fsPath.c_str());
			}
			auto inserted = filteredProcesses.insert(dwProcessID);
 			if (bTerminateFilteredProcesses && inserted.second)
			{
				BOOL bTerminateProcess = TRUE;
				if (dwTerminateMemSizeMB > 0 && bTerminateProcess)
				{
					auto processInfo = pi.m_ProcessInfos.find(dwProcessID);
					if (processInfo != pi.m_ProcessInfos.end())
					{
						SYSTEM_PROCESS_INFORMATION* pSysProcess = processInfo->second;
						auto u64MemSize = pSysProcess->WorkingSetPrivateSize.QuadPart;
						DWORD dwMemSizeMB = (DWORD)(u64MemSize >> 20);
						if (dwMemSizeMB < dwTerminateMemSizeMB) {
							bTerminateProcess = FALSE;
						}
					}
					else {
						_tprintf(_T("PID: %lu, process info not found.\n"), dwProcessID);
						bTerminateProcess = FALSE;
					}
				}
				if (dwTerminateRunningTime > 0 && bTerminateProcess)
				{
					FILETIME CreationTime, ExitTime, KernelTime, UserTime;
					BOOL bProcessTimes = hi.GetProcessTimes((HANDLE)-1, &CreationTime, &ExitTime, &KernelTime, &UserTime, dwProcessID);
					if (bProcessTimes) {
						auto u64RunningTime = get_running_time(&CreationTime, &CurrentTime);
						auto u64RunningMilliSeconds = u64RunningTime / 10000;
						auto u64RunningSeconds = u64RunningMilliSeconds / 1000;
						if (u64RunningSeconds < static_cast<std::uint64_t>(dwTerminateRunningTime)) {
							bTerminateProcess = FALSE;
						}
					}
					else {
						DWORD err = GetLastError();
						_tprintf(_T("GetProcessTimes() failed with error %lu.\n"), err);
						bTerminateProcess = FALSE;
					}
				}
				if (bTerminateProcess) {
					terminateProcesses.insert(dwProcessID);
				}
			}
		}
	}

	if (bPrintFilteredProcesses) 
	{
		_tstring sCurrentTime = format_file_time(CurrentTime, _T("Current time: "));
		_tprintf(_T("\n%s\n"), sCurrentTime.c_str());

		DWORD filteredCount = static_cast<DWORD>(filteredProcesses.size());
		_tprintf(_T("\n%lu processes found.\n\n"), filteredCount);
		for (auto it = filteredProcesses.begin(); it != filteredProcesses.end(); ++it)
		{
			DWORD dwProcessID = *it;
			auto processInfo = pi.m_ProcessInfos.find(dwProcessID);
			if (processInfo != pi.m_ProcessInfos.end()) 
			{
				BOOL bTerminateProcess = bTerminateFilteredProcesses && (terminateProcesses.find(dwProcessID) != terminateProcesses.end());
				SYSTEM_PROCESS_INFORMATION* pSysProcess = processInfo->second;
				print_process_info(dwProcessID, pSysProcess, &hi, &CurrentTime, bTerminateProcess);
			}
			else {
				_tprintf(_T("PID: %lu, process info not found.\n"), dwProcessID);
			}
		}
	}

	if (bTerminateFilteredProcesses) {
		for (auto it = terminateProcesses.begin(); it != terminateProcesses.end(); ++it)
		{
			DWORD dwProcessID = *it;
			BOOL bTerminate = bSilentTerminate;
			if (!bTerminate) {
				_tprintf(_T("Are you sure you want to terminate process %lu ([Y]es, [N]o or [Q]uit)?"), dwProcessID);
				std::string line;
				std::getline(std::cin, line);
				if ("y" == line || "Y" == line) {
					bTerminate = TRUE;
				}
				if ("q" == line || "Q" == line) {
					return;
				}
			}
			if (bTerminate) {
				auto hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessID);
				if (hProcess != NULL) {
					UINT uExitCode = 1;
					if (!TerminateProcess(hProcess, uExitCode)) {
						DWORD err = GetLastError();
						_tprintf(_T("PID: %lu, TerminateProcess() failed with error %lu.\n"), dwProcessID, err);
					}
					else {
						_tprintf(_T("PID: %lu, process has been terminated with exit code %lu.\n"), dwProcessID, uExitCode);
					}
					CloseHandle(hProcess);
				}
				else {
					DWORD err = GetLastError();
					_tprintf(_T("PID: %lu, OpenProcess() failed with error %lu.\n"), dwProcessID, err);
				}
			}
		}

	}
}

void ShowUsage(BOOL bHelp)
{
	_tprintf(_T("usage: listph.exe [-h] (-p NAME | -t TYPE) [-f PATH] [--terminate] [--mem-size MEM_SIZE] [--running-time TIME] [--silent]\n"));
	if (bHelp)
	{
		_tprintf(_T("\n"));
		_tprintf(_T("List Process Handles v1.0\n"));
		_tprintf(_T("Opt-In Software, https://github.com/optinsoft/ListProcessHandles\n"));
		_tprintf(_T("\n"));
		_tprintf(_T("options:\n"));
		_tprintf(_T("  -h, --help                        show this help message and exit\n"));
		_tprintf(_T("  -p [NAME], --process-name [NAME]  filter processes whose name is NAME\n"));
		_tprintf(_T("  -t [TYPE], --handle-type [TYPE]   filter handles whose type is TYPE\n"));
		_tprintf(_T("  -f [PATH], --file-path [PATH]     filter file handles that contain PATH in their path\n"));
		_tprintf(_T("  --terminate                       terminate filtered processes\n"));
		_tprintf(_T("  --mem-size [MEM_SIZE]             terminate filtered processes that consume more memory than MEM_SIZE (in megabytes)\n"));
		_tprintf(_T("  --running-time [TIME]             terminate filtered processes that run longer than TIME (in seconds)\n"));
		_tprintf(_T("  --silent                          silent terminate mode\n"));
		_tprintf(_T("\n"));
		_tprintf(_T("handle types:\n"));
		_tprintf(_T("  Directory\n"));
		_tprintf(_T("  SymbolicLink\n"));
		_tprintf(_T("  Token\n"));
		_tprintf(_T("  Process\n"));
		_tprintf(_T("  Thread\n"));
		_tprintf(_T("  Event\n"));
		_tprintf(_T("  EventPair\n"));
		_tprintf(_T("  Mutant\n"));
		_tprintf(_T("  Semaphore\n"));
		_tprintf(_T("  Timer\n"));
		_tprintf(_T("  Profile\n"));
		_tprintf(_T("  WindowStation\n"));
		_tprintf(_T("  Desktop\n"));
		_tprintf(_T("  Section\n"));
		_tprintf(_T("  Key\n"));
		_tprintf(_T("  Port\n"));
		_tprintf(_T("  WaitablePort\n"));
		_tprintf(_T("  IoCompletion\n"));
		_tprintf(_T("  File\n"));
	}
}

int _tmain(int argc, TCHAR** argv)
{
	std::vector<_tstring> args(argv + 1, argv + argc);

	_tstring processName = _T("");
	_tstring handleType = _T("");
	_tstring filePath = _T("");
	BOOL terminateFilteredProcesses = FALSE;
	DWORD terminateMemSizeMB = 0;
	DWORD terminateRunningTime = 0;
	BOOL silentTerminate = FALSE;

	for (auto i = args.begin(); i != args.end(); ++i)
	{
		_tstring argname = *i;
		if (argname == _T("-h") || argname == _T("--help")) {
			ShowUsage(TRUE);
			return 0;
		}
		else if (argname == _T("-p") || argname == _T("--process-name"))
		{
			if (++i == args.end()) {
				_tprintf(_T("error: argument %s value is missing\n"), argname.c_str());
				return 1;
			}
			processName = *i;
		}
		else if (argname == _T("-t") || argname == _T("--handle-type"))
		{
			if (++i == args.end()) {
				_tprintf(_T("error: argument %s value is missing\n"), argname.c_str());
				return 1;
			}
			handleType = *i;
		}
		else if (argname == _T("-f") || *i == _T("--file-path"))
		{
			if (++i == args.end()) {
				_tprintf(_T("error: argument %s value is missing\n"), argname.c_str());
				return 1;
			}
			filePath = *i;
		}
		else if (argname == _T("--terminate"))
		{
			terminateFilteredProcesses = TRUE;
		}
		else if (argname == _T("--mem-size"))
		{
			if (++i == args.end()) {
				_tprintf(_T("error: argument %s value is missing\n"), argname.c_str());
				return 1;
			}
			_set_errno(0);
			terminateMemSizeMB = _tcstoul((*i).c_str(), NULL, 10);
			if (errno != 0) {
				_tprintf(_T("error: invalid argument %s value\n"), argname.c_str());
			}
		}
		else if (argname == _T("--running-time"))
		{
			if (++i == args.end()) {
				_tprintf(_T("error: argument %s value is missing\n"), argname.c_str());
				return 1;
			}
			_set_errno(0);
			terminateRunningTime = _tcstoul((*i).c_str(), NULL, 10);
			if (errno != 0) {
				_tprintf(_T("error: invalid argument %s value\n"), argname.c_str());
			}
		}
		else if (argname == _T("--silent"))
		{
			silentTerminate = TRUE;
		}
		else {
			ShowUsage(FALSE);
			_tprintf(_T("error: unknown argument %s\n"), argname.c_str());
			return 1;
		}
	}

	if (!processName.length() && !handleType.length() && !filePath.length()) 
	{
		ShowUsage(FALSE);
		_tprintf(_T("error: at least one of arguments required: -p/--process-name, -t/--handle-type\n"));
		return 1;
	}

	list_processes_and_handles(processName.c_str(), handleType.c_str(), filePath.c_str(), TRUE, 
		terminateFilteredProcesses, terminateMemSizeMB, terminateRunningTime, silentTerminate);
}
