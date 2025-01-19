#pragma once

#include <Windows.h>
#include <string>
#include <list>
#include <unordered_map>

#if defined(UNICODE)
#define _tstring std::wstring
#else
#define _tstring std::string
#endif

typedef struct _UNICODE_STRING
{
	WORD  Length;
	WORD  MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING;

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
	template<typename ... Args>
	static _tstring StringFormat(const _tstring& format, Args ... args);

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
	typedef LARGE_INTEGER   QWORD;

	typedef struct _PROCESS_BASIC_INFORMATION {
		DWORD ExitStatus;
		PVOID PebBaseAddress;
		DWORD AffinityMask;
		DWORD BasePriority;
		DWORD UniqueProcessId;
		DWORD InheritedFromUniqueProcessId;
	} PROCESS_BASIC_INFORMATION;

	typedef struct _VM_COUNTERS
	{
		DWORD PeakVirtualSize;
		DWORD VirtualSize;
		DWORD PageFaultCount;
		DWORD PeakWorkingSetSize;
		DWORD WorkingSetSize;
		DWORD QuotaPeakPagedPoolUsage;
		DWORD QuotaPagedPoolUsage;
		DWORD QuotaPeakNonPagedPoolUsage;
		DWORD QuotaNonPagedPoolUsage;
		DWORD PagefileUsage;
		DWORD PeakPagefileUsage;
	} VM_COUNTERS;

	typedef struct _SYSTEM_THREAD
	{
		DWORD        u1;
		DWORD        u2;
		DWORD        u3;
		DWORD        u4;
		DWORD        ProcessId;
		DWORD        ThreadId;
		DWORD        dPriority;
		DWORD        dBasePriority;
		DWORD        dContextSwitches;
		DWORD        dThreadState;      // 2=running, 5=waiting
		DWORD        WaitReason;
		DWORD        u5;
		DWORD        u6;
		DWORD        u7;
		DWORD        u8;
		DWORD        u9;
	} SYSTEM_THREAD;

	typedef struct _SYSTEM_PROCESS_INFORMATION
	{
		DWORD          dNext;
		DWORD          dThreadCount;
		DWORD          dReserved01;
		DWORD          dReserved02;
		DWORD          dReserved03;
		DWORD          dReserved04;
		DWORD          dReserved05;
		DWORD          dReserved06;
		QWORD          qCreateTime;
		QWORD          qUserTime;
		QWORD          qKernelTime;
		UNICODE_STRING usName;
		DWORD	       BasePriority;
		DWORD          dUniqueProcessId;
		DWORD          dInheritedFromUniqueProcessId;
		DWORD          dHandleCount;
		DWORD          dReserved07;
		DWORD          dReserved08;
		VM_COUNTERS    VmCounters;
		DWORD          dCommitCharge;
		SYSTEM_THREAD  Threads[1];
	} SYSTEM_PROCESS_INFORMATION;

	enum { BufferSize = 0x10000 };

public:
	SysProcessInformation(BOOL bRefresh = FALSE);
	virtual ~SysProcessInformation();

	BOOL Refresh();

public:
	std::unordered_map< DWORD, SYSTEM_PROCESS_INFORMATION*> m_ProcessInfos;
	SYSTEM_PROCESS_INFORMATION* m_pCurrentProcessInfo;

protected:
	UCHAR* m_pBuffer;
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


	typedef struct _BASIC_THREAD_INFORMATION {
		DWORD u1;
		DWORD u2;
		DWORD u3;
		DWORD ThreadId;
		DWORD u5;
		DWORD u6;
		DWORD u7;
	} BASIC_THREAD_INFORMATION;

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

public:
	typedef struct _SYSTEM_HANDLE
	{
		DWORD	ProcessID;
		WORD	HandleType;
		WORD	HandleNumber;
		DWORD	KernelAddress;
		DWORD	Flags;
	} SYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION
	{
		DWORD			Count;
		SYSTEM_HANDLE	Handles[1];
	} SYSTEM_HANDLE_INFORMATION;

protected:
	typedef struct _GetFileNameThreadParam
	{
		HANDLE			hFile;
		_tstring		*pName;
		ULONG			rc;
	} GetFileNameThreadParam;

public:
	SysHandleInformation(DWORD pID = (DWORD)-1, BOOL bRefresh = FALSE, LPCTSTR lpTypeFilter = NULL);
	~SysHandleInformation();

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
	static BOOL GetProcessPath(HANDLE h, _tstring& strPath, DWORD processId = GetCurrentProcessId());

	//File related functions
	static BOOL GetFileName(HANDLE, _tstring&, DWORD processId = GetCurrentProcessId());

public:
	//For remote handle support
	static HANDLE OpenProcess(DWORD processId);
	static HANDLE DuplicateHandle(HANDLE hProcess, HANDLE hRemote);

protected:
	static void GetFileNameThread(PVOID /* GetFileNameThreadParam* */);

public:
	std::list<SYSTEM_HANDLE> m_HandleInfos;
	DWORD	m_processId;

protected:
	_tstring m_strTypeFilter;
};
