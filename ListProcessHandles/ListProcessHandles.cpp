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

void list_processes_and_handles(LPCTSTR lpProcessNameFilter, LPCTSTR lpHandleTypeFilter, LPCTSTR lpFsPathFilter, BOOL bHandleProcessFilter, 
	BOOL bPrintProcessFilterInfo = FALSE, BOOL bPrintFileHandleName = FALSE, BOOL bPrintFilteredProcesses = TRUE)
{
	SysProcessInformation pi;
	SysHandleInformation hi(bHandleProcessFilter, FALSE);

	if (!pi.SetNameFilter(lpProcessNameFilter, TRUE))
	{
		_tprintf(_T("SysProcessInformation::SetNameFilter() failed.\n"));
		return;
	}

	if (pi.m_ProcessInfos.size() == 0)
	{
		_tprintf(_T("No process information\n"));
		return;
	}

	for (auto it = pi.m_ProcessInfos.begin(); it != pi.m_ProcessInfos.end(); ++it)
	{
		DWORD dwProcessID = it->first;
		if (bPrintProcessFilterInfo) {
			SYSTEM_PROCESS_INFORMATION* pSysProcess = it->second;
			_tstring strName = pSysProcess->ImageName.Length > 0 ? SysInfoUtils::Unicode2String(&pSysProcess->ImageName) : _T("");
			_tstring str = SysInfoUtils::StringFormat(_T("Process ID: %lu, Name: %s\n"), dwProcessID, strName.c_str());
			_tprintf(str.c_str());
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
		_tprintf(_T("No handle information\n"));
		return;
	}

	_tstring name;
	_tstring typeName;
	WORD type = SysHandleInformation::OB_TYPE_UNKNOWN;
	std::set<DWORD> filteredProcesses;

	for (auto it = hi.m_HandleInfos.begin(); it != hi.m_HandleInfos.end(); ++it)
	{
		const SYSTEM_HANDLE_TABLE_ENTRY_INFO& h = *it;

		hi.GetName((HANDLE)h.HandleValue, name, (DWORD)h.UniqueProcessId);

		hi.GetTypeToken((HANDLE)h.HandleValue, typeName, (DWORD)h.UniqueProcessId);

		hi.GetTypeFromTypeToken(typeName.c_str(), type);

		_tstring fsPath = _T("");

		BOOL bFilterOut = lpFsPathFilter != NULL && *lpFsPathFilter;

		if (type == SysHandleInformation::OB_TYPE_FILE) {
			SysInfoUtils::GetFsFileName(name.c_str(), fsPath);
			bFilterOut = bFilterOut && _tcsstr(fsPath.c_str(), lpFsPathFilter) == NULL;
		}

		if (!bFilterOut) {
			_tstring str = bPrintFileHandleName 
				? SysInfoUtils::StringFormat(_T("%s Handle: %hu, Process ID: %lu, Name: %s\n"), typeName.c_str(), h.HandleValue, (DWORD)h.UniqueProcessId, name.c_str())
				: SysInfoUtils::StringFormat(_T("%s Handle: %hu, Process ID: %lu\n"), typeName.c_str(), h.HandleValue, (DWORD)h.UniqueProcessId);
			_tprintf(str.c_str());

			if (fsPath != _T("")) {
				str = SysInfoUtils::StringFormat(_T("File Path: %s\n"), fsPath.c_str());
				_tprintf(str.c_str());
			}

			filteredProcesses.insert((DWORD)h.UniqueProcessId);
		}
	}

	if (bPrintFilteredProcesses) 
	{
		for (auto it = filteredProcesses.begin(); it != filteredProcesses.end(); ++it)
		{
			DWORD dwProcessID = *it;
			auto processInfo = pi.m_ProcessInfos.find(dwProcessID);
			if (processInfo != pi.m_ProcessInfos.end()) {
				SYSTEM_PROCESS_INFORMATION* pSysProcess = processInfo->second;
				_tstring strName = pSysProcess->ImageName.Length > 0 ? SysInfoUtils::Unicode2String(&pSysProcess->ImageName) : _T("");
				_tstring str = SysInfoUtils::StringFormat(_T("Process ID: %lu, Name: %s\n"), dwProcessID, strName.c_str());
				_tprintf(str.c_str());
			}
			else {
				_tstring str = SysInfoUtils::StringFormat(_T("Process ID: %lu, Process info not found!\n"), dwProcessID);
				_tprintf(str.c_str());
			}
		}
	}
}

int main()
{
	list_processes_and_handles(_T("firefox.exe"), _T("File"), _T("\\Profiles\\"), TRUE);
}
