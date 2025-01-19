#define UMDF_USING_NTSTATUS

#include "SysInfo.h"
#include <tchar.h>
#include <process.h>
#include <memory>
#include <stdexcept>
#include <ntstatus.h>

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

template<typename ... Args >
_tstring SysInfoUtils::StringFormat(const _tstring& format, Args ... args)
{
	int size_s = _sntprintf_s(nullptr, 0, 0, format.c_str(), args ...) + 1; // Extra space for '\0'
	if (size_s <= 0) { throw std::runtime_error("Error during formatting."); }
	auto size = static_cast<size_t>(size_s);
	std::unique_ptr<TCHAR[]> buf(new TCHAR[size]);
	_sntprintf_s(buf.get(), size, size, format.c_str(), args ...);
	return _tstring(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
}

// From device file name to DOS filename
BOOL SysInfoUtils::GetFsFileName(LPCTSTR lpDeviceFileName, _tstring& fsFileName)
{
	BOOL rc = FALSE;

	TCHAR lpDeviceName[0x1000];
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

				TCHAR lpSharedName[0x1000];

				if (_stscanf_s(lpDeviceName,
					_T("\\Device\\LanmanRedirector\\;%c:%d\\%s"),
					&cDriveLetter,
					(unsigned)sizeof(cDriveLetter),
					&dwParam,
					lpSharedName,
					(unsigned)sizeof(lpSharedName)) != 3)
					continue;

				_tcscpy_s(lpDeviceName, _T("\\Device\\LanmanRedirector\\"));
				_tcscat_s(lpDeviceName, lpSharedName);
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

	TCHAR lpDeviceName[0x1000];

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
		else
			// Network drive?
			if (_tcsnicmp(_T("\\Device\\LanmanRedirector\\"), lpDeviceName, 25) == 0)
			{
				//Mapped network drive 

				TCHAR cDriveLetter;
				DWORD dwParam;

				TCHAR lpSharedName[0x1000];

				if (_stscanf_s(lpDeviceName,
					_T("\\Device\\LanmanRedirector\\;%c:%d\\%s"),
					&cDriveLetter,
					(unsigned)sizeof(cDriveLetter),
					&dwParam,
					lpSharedName,
					(unsigned)sizeof(lpSharedName)) != 3)
					return FALSE;

				_tcscpy_s(lpDeviceName, _T("\\Device\\LanmanRedirector\\"));
				_tcscat_s(lpDeviceName, lpSharedName);
			}

		_tcscat_s(lpDeviceName, lpFsFileName + 2);

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

SysProcessInformation::SysProcessInformation(BOOL bRefresh)
{
	m_pBuffer = (UCHAR*)VirtualAlloc((void*)0x100000,
		BufferSize,
		MEM_COMMIT,
		PAGE_READWRITE);

	if (bRefresh)
		Refresh();
}

SysProcessInformation::~SysProcessInformation()
{
	VirtualFree(m_pBuffer, 0, MEM_RELEASE);
}

BOOL SysProcessInformation::Refresh()
{
	m_ProcessInfos.clear();
	m_pCurrentProcessInfo = NULL;

	if (!NtDllStatus || m_pBuffer == NULL)
		return FALSE;

	// query the process information
	if (INtDll::NtQuerySystemInformation(5, m_pBuffer, BufferSize, NULL) != 0)
		return FALSE;

	DWORD currentProcessID = GetCurrentProcessId(); //Current Process ID

	SYSTEM_PROCESS_INFORMATION* pSysProcess = (SYSTEM_PROCESS_INFORMATION*)m_pBuffer;
	do
	{
		// fill the process information map
		m_ProcessInfos.insert(std::make_pair(pSysProcess->dUniqueProcessId, pSysProcess));

		// we found this process
		if (pSysProcess->dUniqueProcessId == currentProcessID)
			m_pCurrentProcessInfo = pSysProcess;

		// get the next process information block
		if (pSysProcess->dNext != 0)
			pSysProcess = (SYSTEM_PROCESS_INFORMATION*)((UCHAR*)pSysProcess + pSysProcess->dNext);
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

	if (bRefresh)
		Refresh();
}

BOOL SysThreadInformation::Refresh()
{
	// Get the Thread objects ( set the filter to "Thread" )
	SysHandleInformation hi(m_processId);
	BOOL rc = hi.SetTypeFilter(_T("Thread"), TRUE);

	m_ThreadInfos.clear();

	if (!rc)
		return FALSE;

	THREAD_INFORMATION ti;

	// Iterating through the found Thread objects
	for (std::list<SysHandleInformation::SYSTEM_HANDLE >::const_iterator it = hi.m_HandleInfos.begin(); it != hi.m_HandleInfos.end(); ++it)
	{
		const SysHandleInformation::SYSTEM_HANDLE& h = *it;

		ti.ProcessId = h.ProcessID;
		ti.ThreadHandle = (HANDLE)h.HandleNumber;

		// This is one of the threads we are lokking for
		if (SysHandleInformation::GetThreadId(ti.ThreadHandle, ti.ThreadId, ti.ProcessId))
			m_ThreadInfos.push_back(ti);
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////////////////
//
// SysHandleInformation
//
//////////////////////////////////////////////////////////////////////////////////////

SysHandleInformation::SysHandleInformation(DWORD pID, BOOL bRefresh, LPCTSTR lpTypeFilter)
{
	m_processId = pID;

	// Set the filter
	SetTypeFilter(lpTypeFilter, bRefresh);
}

SysHandleInformation::~SysHandleInformation()
{
}

BOOL SysHandleInformation::SetTypeFilter(LPCTSTR lpTypeFilter, BOOL bRefresh)
{
	// Set the filter ( default = all objects )
	m_strTypeFilter = lpTypeFilter == NULL ? _T("") : lpTypeFilter;

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

	if (!INtDll::NtDllStatus)
		return FALSE;

	// Allocate the memory for the buffer
	SYSTEM_HANDLE_INFORMATION* pSysHandleInformation = (SYSTEM_HANDLE_INFORMATION*)
		VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);

	if (pSysHandleInformation == NULL)
		return FALSE;

	// Query the needed buffer size for the objects ( system wide )
	if (INtDll::NtQuerySystemInformation(16, pSysHandleInformation, size, &needed) != 0)
	{
		if (needed == 0)
		{
			ret = FALSE;
			goto cleanup;
		}

		// The size was not enough
		VirtualFree(pSysHandleInformation, 0, MEM_RELEASE);

		pSysHandleInformation = (SYSTEM_HANDLE_INFORMATION*)
			VirtualAlloc(NULL, size = needed + 256, MEM_COMMIT, PAGE_READWRITE);
	}

	if (pSysHandleInformation == NULL)
		return FALSE;

	// Query the objects ( system wide )
	if (INtDll::NtQuerySystemInformation(16, pSysHandleInformation, size, NULL) != 0)
	{
		ret = FALSE;
		goto cleanup;
	}

	// Iterating through the objects
	for (i = 0; i < pSysHandleInformation->Count; i++)
	{
		// ProcessId filtering check
		if (pSysHandleInformation->Handles[i].ProcessID == m_processId || m_processId == (DWORD)-1)
		{
			BOOL bAdd = FALSE;

			if (m_strTypeFilter == _T(""))
				bAdd = TRUE;
			else
			{
				strType = _T("");

				// Type filtering
				GetTypeToken((HANDLE)pSysHandleInformation->Handles[i].HandleNumber, strType, pSysHandleInformation->Handles[i].ProcessID);

				if (strType.length() > 0) {
					_tprintf(_T("Type: %s\n"), strType.c_str());
				}

				bAdd = strType == m_strTypeFilter;
			}

			// That's it. We found one.
			if (bAdd)
			{
				pSysHandleInformation->Handles[i].HandleType = (WORD)(pSysHandleInformation->Handles[i].HandleType % 256);

				m_HandleInfos.push_back(pSysHandleInformation->Handles[i]);

			}
		}
	}

cleanup:

	if (pSysHandleInformation != NULL)
		VirtualFree(pSysHandleInformation, 0, MEM_RELEASE);

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
	UCHAR* lpBuffer = NULL;
	BOOL ret = FALSE;

	HANDLE handle;
	HANDLE hRemoteProcess = NULL;
	BOOL remote = processId != GetCurrentProcessId();

	if (!NtDllStatus)
		return FALSE;

	if (remote)
	{
		// Open the remote process
		hRemoteProcess = OpenProcess(processId);

		if (hRemoteProcess == NULL)
			return FALSE;

		// Duplicate the handle
		handle = DuplicateHandle(hRemoteProcess, h);
	}
	else
		handle = h;

	// Query the info size
	NTSTATUS status = INtDll::NtQueryObject(handle, 2, NULL, 0, &size);

	if (STATUS_INFO_LENGTH_MISMATCH == status && size > 0) {
		lpBuffer = new UCHAR[size];

		// Query the info size ( type )
		if (INtDll::NtQueryObject(handle, 2, lpBuffer, size, NULL) == 0)
		{
			str = SysInfoUtils::LPCWSTR2String((LPCWSTR)(lpBuffer + 0x60));

			ret = TRUE;
		}

		if (remote)
		{
			if (hRemoteProcess != NULL)
				CloseHandle(hRemoteProcess);

			if (handle != NULL)
				CloseHandle(handle);
		}

		if (lpBuffer != NULL)
			delete[] lpBuffer;
	}

	return ret;
}

BOOL SysHandleInformation::GetType(HANDLE h, WORD& type, DWORD processId)
{
	_tstring strType;

	type = OB_TYPE_UNKNOWN;

	if (!GetTypeToken(h, strType, processId))
		return FALSE;

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

	for (WORD i = 1; i < count; i++)
		if (constStrTypes[i] == typeToken)
		{
			type = i;
			return TRUE;
		}

	return FALSE;
}

BOOL SysHandleInformation::GetName(HANDLE handle, _tstring& str, DWORD processId)
{
	WORD type = 0;

	if (!GetType(handle, type, processId))
		return FALSE;

	return GetNameByType(handle, type, str, processId);
}

BOOL SysHandleInformation::GetNameByType(HANDLE h, WORD type, _tstring& str, DWORD processId)
{
	ULONG size = 0x2000;
	UCHAR* lpBuffer = NULL;
	BOOL ret = FALSE;

	HANDLE handle;
	HANDLE hRemoteProcess = NULL;
	BOOL remote = processId != GetCurrentProcessId();
	DWORD dwId = 0;

	if (!NtDllStatus)
		return FALSE;

	if (remote)
	{
		hRemoteProcess = OpenProcess(processId);

		if (hRemoteProcess == NULL)
			return FALSE;

		handle = DuplicateHandle(hRemoteProcess, h);
	}
	else
		handle = h;

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
		if (ret && str == _T(""))
			goto cleanup;
		break;

	};

	INtDll::NtQueryObject(handle, 1, NULL, 0, &size);

	// let's try to use the default
	if (size == 0)
		size = 0x2000;

	lpBuffer = new UCHAR[size];

	if (INtDll::NtQueryObject(handle, 1, lpBuffer, size, NULL) == 0)
	{
		str = SysInfoUtils::Unicode2String((UNICODE_STRING*)lpBuffer);
		ret = TRUE;
	}

cleanup:

	if (remote)
	{
		if (hRemoteProcess != NULL)
			CloseHandle(hRemoteProcess);

		if (handle != NULL)
			CloseHandle(handle);
	}

	if (lpBuffer != NULL)
		delete[] lpBuffer;

	return ret;
}

//Thread related functions
BOOL SysHandleInformation::GetThreadId(HANDLE h, DWORD& threadID, DWORD processId)
{
	SysThreadInformation::BASIC_THREAD_INFORMATION ti;
	HANDLE handle;
	HANDLE hRemoteProcess = NULL;
	BOOL remote = processId != GetCurrentProcessId();

	if (!NtDllStatus)
		return FALSE;

	if (remote)
	{
		// Open process
		hRemoteProcess = OpenProcess(processId);

		if (hRemoteProcess == NULL)
			return FALSE;

		// Duplicate handle
		handle = DuplicateHandle(hRemoteProcess, h);
	}
	else
		handle = h;

	// Get the thread information
	if (INtDll::NtQueryInformationThread(handle, 0, &ti, sizeof(ti), NULL) == 0)
		threadID = ti.ThreadId;

	if (remote)
	{
		if (hRemoteProcess != NULL)
			CloseHandle(hRemoteProcess);

		if (handle != NULL)
			CloseHandle(handle);
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
	SysProcessInformation::PROCESS_BASIC_INFORMATION pi;

	ZeroMemory(&pi, sizeof(pi));
	processId = 0;

	if (!NtDllStatus)
		return FALSE;

	if (remote)
	{
		// Open process
		hRemoteProcess = OpenProcess(remoteProcessId);

		if (hRemoteProcess == NULL)
			return FALSE;

		// Duplicate handle
		handle = DuplicateHandle(hRemoteProcess, h);
	}
	else
		handle = h;

	// Get the process information
	if (INtDll::NtQueryInformationProcess(handle, 0, &pi, sizeof(pi), NULL) == 0)
	{
		processId = pi.UniqueProcessId;
		ret = TRUE;
	}

	if (remote)
	{
		if (hRemoteProcess != NULL)
			CloseHandle(hRemoteProcess);

		if (handle != NULL)
			CloseHandle(handle);
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

	WCHAR lpBuffer[0x1000];
	DWORD iob[2];

	p->rc = INtDll::NtQueryInformationFile(p->hFile, iob, lpBuffer, sizeof(lpBuffer), 9);

	if (p->rc == 0)
		p->pName->assign(lpBuffer);
}

BOOL SysHandleInformation::GetFileName(HANDLE h, _tstring& str, DWORD processId)
{
	BOOL ret = FALSE;
	HANDLE hThread = NULL;
	GetFileNameThreadParam tp;
	HANDLE handle;
	HANDLE hRemoteProcess = NULL;
	BOOL remote = processId != GetCurrentProcessId();

	if (!NtDllStatus)
		return FALSE;

	if (remote)
	{
		// Open process
		hRemoteProcess = OpenProcess(processId);

		if (hRemoteProcess == NULL)
			return FALSE;

		// Duplicate handle
		handle = DuplicateHandle(hRemoteProcess, h);
	}
	else
		handle = h;

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
	else
		ret = (tp.rc == 0);

cleanup:

	if (remote)
	{
		if (hRemoteProcess != NULL)
			CloseHandle(hRemoteProcess);

		if (handle != NULL)
			CloseHandle(handle);
	}

	return ret;
}
