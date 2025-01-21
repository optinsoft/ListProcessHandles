// ListProcessHandles.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "SysInfo.h"
#include <tchar.h>

void list_processes_and_handles(LPCTSTR lpProcessNameFilter, LPCTSTR lpHandleTypeFilter, BOOL bHandleProcessFilter, BOOL bPrintProcessFilterInfo = FALSE)
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

	for (std::unordered_map<DWORD, SYSTEM_PROCESS_INFORMATION*>::const_iterator it = pi.m_ProcessInfos.begin(); it != pi.m_ProcessInfos.end(); ++it) 
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
	_tstring type;

	for (std::list<SYSTEM_HANDLE_TABLE_ENTRY_INFO >::const_iterator it = hi.m_HandleInfos.begin(); it != hi.m_HandleInfos.end(); ++it) 
	{
		const SYSTEM_HANDLE_TABLE_ENTRY_INFO& h = *it;
		
		hi.GetName((HANDLE)h.HandleValue, name, (DWORD)h.UniqueProcessId);

		hi.GetTypeToken((HANDLE)h.HandleValue, type, (DWORD)h.UniqueProcessId);

		_tstring str = SysInfoUtils::StringFormat(_T("%s Handle: %hu, Process ID: %lu, Name: %s\n"), type.c_str(), h.HandleValue, (DWORD)h.UniqueProcessId, name.c_str());
		_tprintf(str.c_str());
	}
}

int main()
{
	list_processes_and_handles(_T("firefox.exe"), _T("File"), TRUE);
}
