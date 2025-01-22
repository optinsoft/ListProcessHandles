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

int main()
{
	list_processes_and_handles(_T("firefox.exe"), _T("File"), _T("\\Profiles\\"), TRUE, TRUE, 100, 300);
}
