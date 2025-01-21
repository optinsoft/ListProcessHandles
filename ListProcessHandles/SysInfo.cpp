#define UMDF_USING_NTSTATUS

#include "SysInfo.h"
#include <tchar.h>
#include <process.h>
#include <memory>
#include <ntstatus.h>
#include <algorithm>

//////////////////////////////////////////////////////////////////////////////////////
//
// SysInfoUtils
//
//////////////////////////////////////////////////////////////////////////////////////

_tstring SysInfoUtils::LPCWSTR2String(LPCWSTR strW)
{
#if defined(UNICODE)
	return strW;
#else
	int strLength = WideCharToMultiByte(CP_UTF8, 0, strW, -1, nullptr, 0, nullptr, nullptr);

	// Create a _tstring with the determined length 
	_tstring str(strLength, 0);

	// Perform the conversion from LPCWSTR to _tstring 
	WideCharToMultiByte(CP_UTF8, 0, strW, -1, &str[0],	strLength, nullptr, nullptr);

	return str;
#endif
}

_tstring SysInfoUtils::Unicode2String(UNICODE_STRING* strU)
{
	if (*(DWORD*)strU != 0)
		return LPCWSTR2String((LPCWSTR)strU->Buffer);
	else
		return _T("");
}

_tstring SysInfoUtils::StringFormat(const TCHAR* format, ...)
{
	va_list args;
	va_start(args, format);
	int size_s = _vsctprintf(format, args) + 1; // Extra space for '\0'
	if (size_s <= 0) 
	{
		va_end(args);
		throw std::runtime_error("Error during formatting."); 
	}
	auto size = static_cast<size_t>(size_s);
	std::unique_ptr<TCHAR[]> buffer(new TCHAR[size + 1]{ '\0' });
	auto lpBuffer = buffer.get();
	_vstprintf_s(lpBuffer, size, format, args);
	va_end(args);
	return _tstring(lpBuffer, lpBuffer + size - 1); // We don't want the '\0' inside
}

TCHAR SysInfoUtils::ToLower(TCHAR c)
{
#if defined(UNICODE)
	return static_cast<TCHAR>(::towlower(c));
#else
	return ::tolower(c);
#endif
}

// From device file name to DOS filename
BOOL SysInfoUtils::GetFsFileName(LPCTSTR lpDeviceFileName, _tstring& fsFileName)
{
	BOOL rc = FALSE;

	unsigned uDeviceNameSize = 0x1000;
	std::unique_ptr<TCHAR[]> bufDeviceName(new TCHAR[uDeviceNameSize + 1]{ '\0' });
	auto lpDeviceName = bufDeviceName.get();

	TCHAR lpDrive[3] = _T("A:");

	// Iterating through the drive letters
	for (TCHAR actDrive = _T('A'); actDrive <= _T('Z'); actDrive++)
	{
		lpDrive[0] = actDrive;

		// Query the device for the drive letter
		if (QueryDosDevice(lpDrive, lpDeviceName, 0x1000) != 0)
		{
			// Network drive?
			if (_tcsnicmp(_T("\\Device\\LanmanRedirector\\"), lpDeviceName, 25) == 0)
			{
				//Mapped network drive 

				TCHAR cDriveLetter;
				DWORD dwParam;

				unsigned uSharedNameSize = 0x1000;
				std::unique_ptr<TCHAR[]> bufSharedName(new TCHAR[uSharedNameSize + 1]{ '\0' });
				auto lpSharedName = bufSharedName.get();

				if (_stscanf_s(lpDeviceName,
					_T("\\Device\\LanmanRedirector\\;%c:%d\\%s"),
					&cDriveLetter,
					(unsigned)sizeof(cDriveLetter),
					&dwParam,
					lpSharedName,
					uSharedNameSize) != 3)
					continue;

				_tcscpy_s(lpDeviceName, uDeviceNameSize, _T("\\Device\\LanmanRedirector\\"));
				_tcscat_s(lpDeviceName, uDeviceNameSize, lpSharedName);
			}

			// Is this the drive letter we are looking for?
			if (_tcsnicmp(lpDeviceName, lpDeviceFileName, _tcslen(lpDeviceName)) == 0)
			{
				fsFileName = lpDrive;
				fsFileName += (LPCTSTR)(lpDeviceFileName + _tcslen(lpDeviceName));

				rc = TRUE;

				break;
			}
		}
	}

	return rc;
}

// From DOS file name to device file name
BOOL SysInfoUtils::GetDeviceFileName(LPCTSTR lpFsFileName, _tstring& deviceFileName)
{
	BOOL rc = FALSE;
	TCHAR lpDrive[3];

	// Get the drive letter 
	// unfortunetaly it works only with DOS file names
	_tcsncpy_s(lpDrive, lpFsFileName, 2);
	lpDrive[2] = _T('\0');

	unsigned uDeviceNameSize = 0x1000;
	std::unique_ptr<TCHAR[]> bufDeviceName(new TCHAR[uDeviceNameSize + 1]{ '\0' });
	auto lpDeviceName = bufDeviceName.get();

	// Query the device for the drive letter
	if (QueryDosDevice(lpDrive, lpDeviceName, 0x1000) != 0)
	{
		// Subst drive?
		if (_tcsnicmp(_T("\\??\\"), lpDeviceName, 4) == 0)
		{
			deviceFileName = lpDeviceName + 4;
			deviceFileName += lpFsFileName + 2;

			return TRUE;
		}
		else {
			// Network drive?
			if (_tcsnicmp(_T("\\Device\\LanmanRedirector\\"), lpDeviceName, 25) == 0)
			{
				//Mapped network drive 

				TCHAR cDriveLetter;
				DWORD dwParam;

				unsigned uSharedNameSize = 0x1000;
				std::unique_ptr<TCHAR[]> bufSharedName(new TCHAR[uSharedNameSize + 1]{ '\0' });
				auto lpSharedName = bufSharedName.get();

				if (_stscanf_s(lpDeviceName,
					_T("\\Device\\LanmanRedirector\\;%c:%d\\%s"),
					&cDriveLetter,
					(unsigned)sizeof(cDriveLetter),
					&dwParam,
					lpSharedName,
					uSharedNameSize) != 3)
					return FALSE;

				_tcscpy_s(lpDeviceName, uDeviceNameSize, _T("\\Device\\LanmanRedirector\\"));
				_tcscat_s(lpDeviceName, uDeviceNameSize, bufSharedName.get());
			}
		}

		_tcscat_s(lpDeviceName, uDeviceNameSize, lpFsFileName + 2);

		deviceFileName = lpDeviceName;

		rc = TRUE;
	}

	return rc;
}

//////////////////////////////////////////////////////////////////////////////////////
//
// INtDll
//
//////////////////////////////////////////////////////////////////////////////////////
INtDll::PNtQuerySystemInformation INtDll::NtQuerySystemInformation = NULL;
INtDll::PNtQueryObject INtDll::NtQueryObject = NULL;
INtDll::PNtQueryInformationThread	INtDll::NtQueryInformationThread = NULL;
INtDll::PNtQueryInformationFile	INtDll::NtQueryInformationFile = NULL;
INtDll::PNtQueryInformationProcess INtDll::NtQueryInformationProcess = NULL;

BOOL INtDll::NtDllStatus = INtDll::Init();

BOOL INtDll::Init()
{
	// Get the NtDll function pointers
	NtQuerySystemInformation = (PNtQuerySystemInformation)
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")),
			"NtQuerySystemInformation");

	NtQueryObject = (PNtQueryObject)
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")),
			"NtQueryObject");

	NtQueryInformationThread = (PNtQueryInformationThread)
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")),
			"NtQueryInformationThread");

	NtQueryInformationFile = (PNtQueryInformationFile)
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")),
			"NtQueryInformationFile");

	NtQueryInformationProcess = (PNtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")),
			"NtQueryInformationProcess");

	return  NtQuerySystemInformation != NULL &&
		NtQueryObject != NULL &&
		NtQueryInformationThread != NULL &&
		NtQueryInformationFile != NULL &&
		NtQueryInformationProcess != NULL;
}

//////////////////////////////////////////////////////////////////////////////////////
//
// SysProcessInformation
//
//////////////////////////////////////////////////////////////////////////////////////

SysProcessInformation::SysProcessInformation(BOOL bRefresh, LPCTSTR lpNameFilter)
	: m_pCurrentProcessInfo(NULL)
{
	m_nBufferSize = 0x10000;
	m_pBuffer = (UCHAR*)VirtualAlloc(NULL, m_nBufferSize, MEM_COMMIT, PAGE_READWRITE);

	// Set the filter
	SetNameFilter(lpNameFilter, bRefresh);
}

SysProcessInformation::~SysProcessInformation()
{
	VirtualFree(m_pBuffer, 0, MEM_RELEASE);
}

BOOL SysProcessInformation::SetNameFilter(LPCTSTR lpNameFilter, BOOL bRefresh)
{
	// Set the filter (default = all filters)
	m_strNameFilter = lpNameFilter == NULL ? _T("") : lpNameFilter;

	std::transform(m_strNameFilter.begin(), m_strNameFilter.end(), m_strNameFilter.begin(), SysInfoUtils::ToLower);

	return bRefresh ? Refresh() : TRUE;
}

const _tstring& SysProcessInformation::GetNameFilter()
{
	return m_strNameFilter;
}

BOOL SysProcessInformation::Refresh()
{
	m_ProcessInfos.clear();
	m_pCurrentProcessInfo = NULL;

	if (!NtDllStatus || m_pBuffer == NULL) {
		return FALSE;
	}

	NTSTATUS status;
	DWORD needed = 0;

	// query the process information
	while ((status = INtDll::NtQuerySystemInformation(SystemProcessInformation, m_pBuffer, m_nBufferSize, &needed)) != 0) {
		if (status != STATUS_INFO_LENGTH_MISMATCH || needed == 0)
		{
			return FALSE;
		}

		if (m_pBuffer == NULL) {
			return FALSE;
		}

		VirtualFree(m_pBuffer, 0, MEM_RELEASE);

		m_nBufferSize = needed;
		m_pBuffer = (UCHAR*)VirtualAlloc(NULL, m_nBufferSize, MEM_COMMIT, PAGE_READWRITE);
	}

	if (m_pBuffer == NULL) {
		return FALSE;
	}

	DWORD currentProcessID = GetCurrentProcessId(); //Current Process ID
	_tstring strName;

	SYSTEM_PROCESS_INFORMATION* pSysProcess = (SYSTEM_PROCESS_INFORMATION*)m_pBuffer;
	do
	{
		BOOL bAdd = FALSE;

		if (m_strNameFilter == _T("")) {
			bAdd = TRUE;
		}
		else if (pSysProcess->ImageName.Length > 0) {
			strName = SysInfoUtils::Unicode2String(&pSysProcess->ImageName);

			std::transform(strName.begin(), strName.end(), strName.begin(), SysInfoUtils::ToLower);

			bAdd = strName == m_strNameFilter;
		}

		if (bAdd) {
			// fill the process information map
			m_ProcessInfos.insert(std::make_pair((DWORD)pSysProcess->UniqueProcessId, pSysProcess));
		}

		// we found this process
		if ((DWORD)pSysProcess->UniqueProcessId == currentProcessID) {
			m_pCurrentProcessInfo = pSysProcess;
		}

		// get the next process information block
		if (pSysProcess->NextEntryOffset != 0)
			pSysProcess = (SYSTEM_PROCESS_INFORMATION*)((UCHAR*)pSysProcess + pSysProcess->NextEntryOffset);
		else
			pSysProcess = NULL;

	} while (pSysProcess != NULL);

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////////////////
//
// SysThreadInformation
//
//////////////////////////////////////////////////////////////////////////////////////

SysThreadInformation::SysThreadInformation(DWORD pID, BOOL bRefresh)
{
	m_processId = pID;

	if (bRefresh) {
		Refresh();
	}
}

BOOL SysThreadInformation::Refresh()
{
	// Get the Thread objects ( set the filter to "Thread" )
	SysHandleInformation hi(TRUE);
	hi.AddProcessFilter(m_processId);
	BOOL rc = hi.SetTypeFilter(_T("Thread"), TRUE);

	m_ThreadInfos.clear();

	if (!rc) {
		return FALSE;
	}

	THREAD_INFORMATION ti;

	// Iterating through the found Thread objects
	for (std::list<SYSTEM_HANDLE_TABLE_ENTRY_INFO >::const_iterator it = hi.m_HandleInfos.begin(); it != hi.m_HandleInfos.end(); ++it)
	{
		const SYSTEM_HANDLE_TABLE_ENTRY_INFO& h = *it;

		ti.ProcessId = h.UniqueProcessId;
		ti.ThreadHandle = (HANDLE)h.HandleValue;

		// This is one of the threads we are looking for
		if (SysHandleInformation::GetThreadId(ti.ThreadHandle, ti.ThreadId, ti.ProcessId)) {
			m_ThreadInfos.push_back(ti);
		}
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////////////////
//
// SysHandleInformation
//
//////////////////////////////////////////////////////////////////////////////////////

SysHandleInformation::SysHandleInformation(BOOL bUseProcessFilters, BOOL bRefresh, LPCTSTR lpTypeFilter)
{
	m_UseProcessFilters = bUseProcessFilters;

	// Set the filter
	SetTypeFilter(lpTypeFilter, bRefresh);
}

SysHandleInformation::~SysHandleInformation()
{
}

void SysHandleInformation::AddProcessFilter(DWORD dwProcessID)
{
	m_ProcessFilters.insert(dwProcessID);
}

void SysHandleInformation::ResetProcessFilters()
{
	m_ProcessFilters.clear();
}

BOOL SysHandleInformation::SetTypeFilter(LPCTSTR lpTypeFilter, BOOL bRefresh)
{
	// Set the filter ( default = all objects )
	m_strTypeFilter = lpTypeFilter == NULL ? _T("") : lpTypeFilter;

	std::transform(m_strTypeFilter.begin(), m_strTypeFilter.end(), m_strTypeFilter.begin(), SysInfoUtils::ToLower);

	return bRefresh ? Refresh() : TRUE;
}

const _tstring& SysHandleInformation::GetTypeFilter()
{
	return m_strTypeFilter;
}

BOOL SysHandleInformation::Refresh()
{
	DWORD size = 0x2000;
	DWORD needed = 0;
	DWORD i = 0;
	BOOL  ret = TRUE;
	_tstring strType;

	m_HandleInfos.clear();

	if (!INtDll::NtDllStatus) {
		return FALSE;
	}

	// Allocate the memory for the buffer
	SYSTEM_HANDLE_INFORMATION* pSysHandleInformation = (SYSTEM_HANDLE_INFORMATION*)
		VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);

	if (pSysHandleInformation == NULL) {
		return FALSE;
	}

	NTSTATUS status;

	// Query the needed buffer size for the objects ( system wide )
	while ((status = INtDll::NtQuerySystemInformation(SystemHandleInformation, pSysHandleInformation, size, &needed)) != 0)
	{
		if (status != STATUS_INFO_LENGTH_MISMATCH || needed == 0)
		{
			ret = FALSE;
			goto cleanup;
		}

		if (pSysHandleInformation == NULL) {
			return FALSE;
		}

		// The size was not enough
		VirtualFree(pSysHandleInformation, 0, MEM_RELEASE);

		pSysHandleInformation = (SYSTEM_HANDLE_INFORMATION*)
			VirtualAlloc(NULL, size = needed + 256, MEM_COMMIT, PAGE_READWRITE);
	}

	if (pSysHandleInformation == NULL) {
		return FALSE;
	}

	// Iterating through the objects
	for (i = 0; i < pSysHandleInformation->NumberOfHandles; i++)
	{
		// ProcessId filtering check
		if (!m_UseProcessFilters || m_ProcessFilters.find((DWORD)pSysHandleInformation->Handles[i].UniqueProcessId) != m_ProcessFilters.end())
		{
			BOOL bAdd = FALSE;

			if (m_strTypeFilter == _T("")) {
				bAdd = TRUE;
			}
			else {
				strType = _T("");

				// Type filtering
				GetTypeToken((HANDLE)pSysHandleInformation->Handles[i].HandleValue, strType, pSysHandleInformation->Handles[i].UniqueProcessId);

				std::transform(strType.begin(), strType.end(), strType.begin(), SysInfoUtils::ToLower);

				bAdd = strType == m_strTypeFilter;
			}

			// That's it. We found one.
			if (bAdd)
			{
				//pSysHandleInformation->Handles[i].HandleType = (WORD)(pSysHandleInformation->Handles[i].HandleType % 256);

				m_HandleInfos.push_back(pSysHandleInformation->Handles[i]);

			}
		}
	}

cleanup:

	if (pSysHandleInformation != NULL) {
		VirtualFree(pSysHandleInformation, 0, MEM_RELEASE);
	}

	return ret;
}

HANDLE SysHandleInformation::OpenProcess(DWORD processId)
{
	// Open the process for handle duplication
	return ::OpenProcess(PROCESS_DUP_HANDLE, TRUE, processId);
}

HANDLE SysHandleInformation::DuplicateHandle(HANDLE hProcess, HANDLE hRemote)
{
	HANDLE hDup = NULL;

	// Duplicate the remote handle for our process
	::DuplicateHandle(hProcess, hRemote, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS);

	return hDup;
}

//Information functions
BOOL SysHandleInformation::GetTypeToken(HANDLE h, _tstring& str, DWORD processId)
{
	ULONG size = 0; //0x2000;
	BOOL ret = FALSE;

	HANDLE handle;
	HANDLE hRemoteProcess = NULL;
	BOOL remote = processId != GetCurrentProcessId();

	if (!NtDllStatus) {
		return FALSE;
	}

	if (remote)
	{
		// Open the remote process
		hRemoteProcess = OpenProcess(processId);

		if (hRemoteProcess == NULL)
			return FALSE;

		// Duplicate the handle
		handle = DuplicateHandle(hRemoteProcess, h);
	}
	else {
		handle = h;
	}

	// Query the info size
	NTSTATUS status = INtDll::NtQueryObject(handle, ObjectTypeInformation, NULL, 0, &size);

	if (STATUS_INFO_LENGTH_MISMATCH == status && size > 0) 
	{
		std::unique_ptr<UCHAR[]> buffer(new UCHAR[size]);
		auto lpBuffer = buffer.get();

		// Query the info size ( type )
		if (INtDll::NtQueryObject(handle, ObjectTypeInformation, lpBuffer, size, NULL) == 0)
		{
			POBJECT_TYPE_INFORMATION pTypeInfo = (POBJECT_TYPE_INFORMATION)lpBuffer;
			if (pTypeInfo->TypeName.Length > 0 && pTypeInfo->TypeName.Buffer != NULL) {
				str = SysInfoUtils::LPCWSTR2String((LPCWSTR)(pTypeInfo->TypeName.Buffer));
				ret = TRUE;
			}
		}

		if (remote)
		{
			if (hRemoteProcess != NULL) {
				CloseHandle(hRemoteProcess);
			}

			if (handle != NULL) {
				CloseHandle(handle);
			}
		}
	}

	return ret;
}

BOOL SysHandleInformation::GetType(HANDLE h, WORD& type, DWORD processId)
{
	_tstring strType;

	type = OB_TYPE_UNKNOWN;

	if (!GetTypeToken(h, strType, processId)) {
		return FALSE;
	}

	return GetTypeFromTypeToken(strType.c_str(), type);
}

BOOL SysHandleInformation::GetTypeFromTypeToken(LPCTSTR typeToken, WORD& type)
{
	const WORD count = 27;
	_tstring constStrTypes[count] = {
		_T(""), _T(""), _T("Directory"), _T("SymbolicLink"), _T("Token"),
		_T("Process"), _T("Thread"), _T("Unknown7"), _T("Event"), _T("EventPair"), _T("Mutant"),
		_T("Unknown11"), _T("Semaphore"), _T("Timer"), _T("Profile"), _T("WindowStation"),
		_T("Desktop"), _T("Section"), _T("Key"), _T("Port"), _T("WaitablePort"),
		_T("Unknown21"), _T("Unknown22"), _T("Unknown23"), _T("Unknown24"),
		_T("IoCompletion"), _T("File") };

	type = OB_TYPE_UNKNOWN;

	for (WORD i = 1; i < count; i++) {
		if (constStrTypes[i] == typeToken)
		{
			type = i;
			return TRUE;
		}
	}

	return FALSE;
}

BOOL SysHandleInformation::GetName(HANDLE handle, _tstring& str, DWORD processId)
{
	WORD type = 0;

	if (!GetType(handle, type, processId)) {
		return FALSE;
	}

	return GetNameByType(handle, type, str, processId);
}

BOOL SysHandleInformation::GetNameByType(HANDLE h, WORD type, _tstring& str, DWORD processId)
{
	ULONG size = 0x2000;
	BOOL ret = FALSE;

	HANDLE handle;
	HANDLE hRemoteProcess = NULL;
	BOOL remote = processId != GetCurrentProcessId();
	DWORD dwId = 0;

	if (!NtDllStatus) {
		return FALSE;
	}

	if (remote)
	{
		hRemoteProcess = OpenProcess(processId);

		if (hRemoteProcess == NULL) {
			return FALSE;
		}

		handle = DuplicateHandle(hRemoteProcess, h);
	}
	else {
		handle = h;
	}

	// let's be happy, handle is in our process space, so query the infos :)
	switch (type)
	{
		case OB_TYPE_PROCESS:
			GetProcessId(handle, dwId);

			str = SysInfoUtils::StringFormat(_T("PID: 0x%X"), dwId);

			ret = TRUE;
			goto cleanup;
			break;

		case OB_TYPE_THREAD:
			GetThreadId(handle, dwId);

			str = SysInfoUtils::StringFormat(_T("TID: 0x%X"), dwId);

			ret = TRUE;
			goto cleanup;
			break;

		case OB_TYPE_FILE:
			ret = GetFileName(handle, str);

			// access denied :(
			if (ret && str == _T("")) {
				goto cleanup;
			}
			break;
	};

	INtDll::NtQueryObject(handle, ObjectNameInformation, NULL, 0, &size);

	// let's try to use the default
	if (size == 0) {
		size = 0x2000;
	}

	{
		std::unique_ptr<UCHAR[]> buffer(new UCHAR[size]);
		auto lpBuffer = buffer.get();

		if (INtDll::NtQueryObject(handle, ObjectNameInformation, lpBuffer, size, NULL) == 0)
		{
			str = SysInfoUtils::Unicode2String((UNICODE_STRING*)lpBuffer);
			ret = TRUE;
		}
	}

cleanup:

	if (remote)
	{
		if (hRemoteProcess != NULL) {
			CloseHandle(hRemoteProcess);
		}

		if (handle != NULL) {
			CloseHandle(handle);
		}
	}

	return ret;
}

//Thread related functions
BOOL SysHandleInformation::GetThreadId(HANDLE h, DWORD& threadID, DWORD processId)
{
	THREAD_BASIC_INFORMATION ti;
	HANDLE handle;
	HANDLE hRemoteProcess = NULL;
	BOOL remote = processId != GetCurrentProcessId();

	if (!NtDllStatus) {
		return FALSE;
	}

	if (remote)
	{
		// Open process
		hRemoteProcess = OpenProcess(processId);

		if (hRemoteProcess == NULL) {
			return FALSE;
		}

		// Duplicate handle
		handle = DuplicateHandle(hRemoteProcess, h);
	}
	else {
		handle = h;
	}

	// Get the thread information
	if (INtDll::NtQueryInformationThread(handle, 0, &ti, sizeof(ti), NULL) == 0) {
		threadID = (DWORD)ti.ClientId.UniqueThread;
	}

	if (remote)
	{
		if (hRemoteProcess != NULL) {
			CloseHandle(hRemoteProcess);
		}

		if (handle != NULL) {
			CloseHandle(handle);
		}
	}

	return TRUE;
}

//Process related functions
BOOL SysHandleInformation::GetProcessPath(HANDLE h, _tstring& strPath, DWORD remoteProcessId)
{
	h; strPath; remoteProcessId;

	strPath =SysInfoUtils::StringFormat(_T("%d"), remoteProcessId);

	return TRUE;
}

BOOL SysHandleInformation::GetProcessId(HANDLE h, DWORD& processId, DWORD remoteProcessId)
{
	BOOL ret = FALSE;
	HANDLE handle;
	HANDLE hRemoteProcess = NULL;
	BOOL remote = remoteProcessId != GetCurrentProcessId();
	PROCESS_BASIC_INFORMATION pi;

	ZeroMemory(&pi, sizeof(pi));
	processId = 0;

	if (!NtDllStatus) {
		return FALSE;
	}

	if (remote)
	{
		// Open process
		hRemoteProcess = OpenProcess(remoteProcessId);

		if (hRemoteProcess == NULL) {
			return FALSE;
		}

		// Duplicate handle
		handle = DuplicateHandle(hRemoteProcess, h);
	}
	else {
		handle = h;
	}

	// Get the process information
	if (INtDll::NtQueryInformationProcess(handle, 0, &pi, sizeof(pi), NULL) == 0)
	{
		processId = (DWORD)pi.UniqueProcessId;
		ret = TRUE;
	}

	if (remote)
	{
		if (hRemoteProcess != NULL) {
			CloseHandle(hRemoteProcess);
		}

		if (handle != NULL) {
			CloseHandle(handle);
		}
	}

	return ret;
}

//File related functions
void SysHandleInformation::GetFileNameThread(PVOID pParam)
{
	// This thread function for getting the filename
	// if access denied, we hang up in this function, 
	// so if it times out we just kill this thread
	GetFileNameThreadParam* p = (GetFileNameThreadParam*)pParam;

	DWORD bufferSize = 0x1000;
	std::unique_ptr<TCHAR[]> buffer(new TCHAR[bufferSize + 1]{ '\0' });
	auto lpBuffer = buffer.get();

	IO_STATUS_BLOCK iob;

	p->rc = INtDll::NtQueryInformationFile(p->hFile, &iob, lpBuffer, bufferSize, 9);

	if (p->rc == 0) {
		p->pName->assign(lpBuffer);
	}
}

BOOL SysHandleInformation::GetFileName(HANDLE h, _tstring& str, DWORD processId)
{
	BOOL ret = FALSE;
	HANDLE hThread = NULL;
	GetFileNameThreadParam tp;
	HANDLE handle;
	HANDLE hRemoteProcess = NULL;
	BOOL remote = processId != GetCurrentProcessId();

	if (!NtDllStatus) {
		return FALSE;
	}

	if (remote)
	{
		// Open process
		hRemoteProcess = OpenProcess(processId);

		if (hRemoteProcess == NULL) {
			return FALSE;
		}

		// Duplicate handle
		handle = DuplicateHandle(hRemoteProcess, h);
	}
	else {
		handle = h;
	}

	tp.hFile = handle;
	tp.pName = &str;
	tp.rc = 0;

	// Let's start the thread to get the file name
	hThread = (HANDLE)_beginthread(GetFileNameThread, 0, &tp);

	if (hThread == NULL)
	{
		ret = FALSE;
		goto cleanup;
	}

	// Wait for finishing the thread
	if (WaitForSingleObject(hThread, 100) == WAIT_TIMEOUT)
	{
		// Access denied
		// Terminate the thread
		TerminateThread(hThread, 0);

		str = _T("");

		ret = TRUE;
	}
	else {
		ret = (tp.rc == 0);
	}

cleanup:

	if (remote)
	{
		if (hRemoteProcess != NULL) {
			CloseHandle(hRemoteProcess);
		}

		if (handle != NULL) {
			CloseHandle(handle);
		}
	}

	return ret;
}
