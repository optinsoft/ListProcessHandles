////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Author: vitaly (optinsoft), https://github.com/optinsoft
// Created: 2025-01-21
// License: MIT
// Dependency: phnt from https://github.com/winsiderss/systeminformer/tree/master/phnt
// 
// This code based on SystemInfo.h written by Zoltan Csizmadia, zoltan_csizmadia@yahoo.com
// 
////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma once

#define PHNT_VERSION PHNT_THRESHOLD

#include <phnt_windows.h>
#include <phnt.h>

#include <string>
#include <list>
#include <unordered_map>
#include <set>

#include <tchar.h>
#include <memory>
#include <stdexcept>

#if defined(UNICODE)
#define _tstring std::wstring
#else
#define _tstring std::string
#endif

class SysInfoUtils
{
public:

	//////////////////////////////////////////////////////////////////////////////////
	// String conversion functions

	// From wide char string to CString
	static _tstring LPCWSTR2String(LPCWSTR strW);
	// From unicode string to CString
	static _tstring Unicode2String(UNICODE_STRING* strU);
	//
	static _tstring StringFormat(const TCHAR* format, ...);
	//
	static TCHAR ToLower(TCHAR c);

	//////////////////////////////////////////////////////////////////////////////////
	// File name conversion functions

	static BOOL GetDeviceFileName(LPCTSTR, _tstring&);
	static BOOL GetFsFileName(LPCTSTR, _tstring&);

	//////////////////////////////////////////////////////////////////////////////////
	// Information functions
};

class INtDll
{
public:
	typedef DWORD(WINAPI* PNtQueryObject)(HANDLE, DWORD, VOID*, DWORD, VOID*);
	typedef DWORD(WINAPI* PNtQuerySystemInformation)(DWORD, VOID*, DWORD, ULONG*);
	typedef DWORD(WINAPI* PNtQueryInformationThread)(HANDLE, ULONG, PVOID, DWORD, DWORD*);
	typedef DWORD(WINAPI* PNtQueryInformationFile)(HANDLE, PVOID, PVOID, DWORD, DWORD);
	typedef DWORD(WINAPI* PNtQueryInformationProcess)(HANDLE, DWORD, PVOID, DWORD, PVOID);

public:
	static PNtQuerySystemInformation	NtQuerySystemInformation;
	static PNtQueryObject				NtQueryObject;
	static PNtQueryInformationThread	NtQueryInformationThread;
	static PNtQueryInformationFile		NtQueryInformationFile;
	static PNtQueryInformationProcess	NtQueryInformationProcess;

	static BOOL							NtDllStatus;

protected:
	static BOOL Init();
};

class SysProcessInformation : public INtDll
{
public:
	SysProcessInformation(BOOL bRefresh = FALSE, LPCTSTR lpNameFilter = NULL);
	virtual ~SysProcessInformation();

	BOOL SetNameFilter(LPCTSTR lpNameFilter, BOOL bRefresh = TRUE);
	const _tstring& GetNameFilter();

	BOOL Refresh();

public:
	std::unordered_map<DWORD, SYSTEM_PROCESS_INFORMATION*> m_ProcessInfos;
	SYSTEM_PROCESS_INFORMATION* m_pCurrentProcessInfo;

protected:
	_tstring m_strNameFilter;

protected:
	UCHAR* m_pBuffer;
	DWORD m_nBufferSize;
};

class SysThreadInformation : public INtDll
{
public:
	typedef struct _THREAD_INFORMATION
	{
		DWORD		ProcessId;
		DWORD		ThreadId;
		HANDLE		ThreadHandle;
	} THREAD_INFORMATION;

public:
	SysThreadInformation(DWORD pID = (DWORD)-1, BOOL bRefresh = FALSE);

	BOOL Refresh();

public:
	std::list<THREAD_INFORMATION> m_ThreadInfos;
	DWORD m_processId;
};

class SysHandleInformation : public INtDll
{
public:
	enum {
		OB_TYPE_UNKNOWN = 0,
		OB_TYPE_TYPE = 1,
		OB_TYPE_DIRECTORY,
		OB_TYPE_SYMBOLIC_LINK,
		OB_TYPE_TOKEN,
		OB_TYPE_PROCESS,
		OB_TYPE_THREAD,
		OB_TYPE_UNKNOWN_7,
		OB_TYPE_EVENT,
		OB_TYPE_EVENT_PAIR,
		OB_TYPE_MUTANT,
		OB_TYPE_UNKNOWN_11,
		OB_TYPE_SEMAPHORE,
		OB_TYPE_TIMER,
		OB_TYPE_PROFILE,
		OB_TYPE_WINDOW_STATION,
		OB_TYPE_DESKTOP,
		OB_TYPE_SECTION,
		OB_TYPE_KEY,
		OB_TYPE_PORT,
		OB_TYPE_WAITABLE_PORT,
		OB_TYPE_UNKNOWN_21,
		OB_TYPE_UNKNOWN_22,
		OB_TYPE_UNKNOWN_23,
		OB_TYPE_UNKNOWN_24,
		OB_TYPE_IO_COMPLETION,
		OB_TYPE_FILE
	} SystemHandleType;

protected:
	typedef struct _GetFileNameThreadParam
	{
		HANDLE			hFile;
		_tstring		*pName;
		ULONG			rc;
	} GetFileNameThreadParam;

public:
	SysHandleInformation(BOOL bUseProcessFilters = FALSE, BOOL bRefresh = FALSE, LPCTSTR lpTypeFilter = NULL);
	~SysHandleInformation();

	void AddProcessFilter(DWORD dwProcessID);
	void ResetProcessFilters();
	BOOL SetTypeFilter(LPCTSTR lpTypeFilter, BOOL bRefresh = TRUE);
	const _tstring& GetTypeFilter();

	BOOL Refresh();

public:
	//Information functions
	static BOOL GetType(HANDLE, WORD&, DWORD processId = GetCurrentProcessId());
	static BOOL GetTypeToken(HANDLE, _tstring&, DWORD processId = GetCurrentProcessId());
	static BOOL GetTypeFromTypeToken(LPCTSTR typeToken, WORD& type);
	static BOOL GetNameByType(HANDLE, WORD, _tstring& str, DWORD processId = GetCurrentProcessId());
	static BOOL GetName(HANDLE, _tstring&, DWORD processId = GetCurrentProcessId());

	//Thread related functions
	static BOOL GetThreadId(HANDLE, DWORD&, DWORD processId = GetCurrentProcessId());

	//Process related functions
	static BOOL GetProcessId(HANDLE, DWORD&, DWORD processId = GetCurrentProcessId());
	static BOOL GetProcessTimes(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME, DWORD processId = GetCurrentProcessId());

	//File related functions
	static BOOL GetFileName(HANDLE, _tstring&, DWORD processId = GetCurrentProcessId());

public:
	//For remote handle support
	static HANDLE OpenProcess(DWORD processId);
	static HANDLE DuplicateHandle(HANDLE hProcess, HANDLE hRemote);

protected:
	static void GetFileNameThread(PVOID /* GetFileNameThreadParam* */);

public:
	std::list<SYSTEM_HANDLE_TABLE_ENTRY_INFO> m_HandleInfos;

protected:
	_tstring m_strTypeFilter;
	std::set<DWORD> m_ProcessFilters;
	BOOL m_UseProcessFilters;
};
