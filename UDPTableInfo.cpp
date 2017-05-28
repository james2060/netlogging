#include "StdAfx.h"
#include "UDPTableInfo.h"
#include "Base.h"
#include "ProcessModules.h"

CUDPTableInfo::CUDPTableInfo(void)
{
}

CUDPTableInfo::~CUDPTableInfo(void)
{
}

int CUDPTableInfo::GetNetStat(UdpTableList& tblList)
{
	return ( IsVista() ) ? NetStatVista(tblList) : NetStatNT(tblList);    
}
//vista
int CUDPTableInfo::NetStatVista(UdpTableList& tblList)
{
    DWORD i = 0, dwRet = 0;
    DWORD dwUdpSize = 0, dwUdp6Size = 0;
    
    MIB_UDPTABLE_OWNER_PID  *pUdp  = NULL;
    MIB_UDP6TABLE_OWNER_PID *pUdp6 = NULL;

    GetExtendedUdpTable_t GetExtendedUdpTable;

    HMODULE hDLL = NULL;
    
    if ( (hDLL = LoadLibrary("Iphlpapi.dll")) == NULL )
    {
        printf("fail to LoadLibrary 'Iphlpapi.dll'\n");
        return -1;
    }

    GetExtendedUdpTable = (GetExtendedUdpTable_t)GetProcAddress(hDLL, "GetExtendedUdpTable");
    
    dwRet = GetExtendedUdpTable(NULL, &dwUdpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    dwRet = GetExtendedUdpTable(NULL, &dwUdp6Size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        
    pUdp  = (MIB_UDPTABLE_OWNER_PID  *)malloc(dwUdpSize);
    pUdp6 = (MIB_UDP6TABLE_OWNER_PID *)malloc(dwUdp6Size);

    dwRet = GetExtendedUdpTable(pUdp, &dwUdpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    dwRet = GetExtendedUdpTable(pUdp6, &dwUdp6Size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);

	

	CBase *pBase = new CBase();
	in_addr stAddr;

	
	
	/* IPV4 UDP TABLE INFO */
    for ( i = 0; i < pUdp->dwNumEntries; i++ )
    {

		_UDPTABLE *Table;
		Table = new _UDPTABLE;

		Table->nIndex = i+1;	//index 
		Table->nTotalEntries = pUdp->dwNumEntries;//Total Entries

		u_long ulLocalAddress = static_cast<u_long>(pUdp->table[i].dwLocalAddr);
		stAddr.s_addr = ulLocalAddress;

		Table->strLocalAddress = inet_ntoa(stAddr); //local addr 

		CString strProcName = pBase->GetProcById(pUdp->table[i].dwOwningPid);

		Table->strProcessName = strProcName;
	
		Table->ulLocalPort = ntohs( (u_short)pUdp->table[i].dwLocalPort);

		Table->dwProcessId = pUdp->table[i].dwOwningPid;

		Table->bIpv6 = FALSE;

		if( pUdp->table[i].dwOwningPid > 10)
		{
			CProcessModules pl(pUdp->table[i].dwOwningPid);
			Table->strProcessFullPath = pl.GetProcFilePath();
		}
		else
		{
			Table->strProcessFullPath ="[SYSTEM PROCESS]";
		}


		tblList.AddTail(_PUDPTABLE(Table));

    }

	/* UDP IPV6 TABLE INFO */
    for ( i = 0; i < pUdp6->dwNumEntries; i++ )
    {
		_UDPTABLE *Table;
		Table = new _UDPTABLE;

		CString strProcName = pBase->GetProcById(pUdp6->table[i].dwOwningPid);

		Table->nIndex = i+1;	//index 
		Table->nTotalEntries = pUdp6->dwNumEntries;//Total Entries

		Table->strLocalAddress = pUdp6->table[i].ucLocalAddr;//inet_ntoa(stAddr); //local addr 

		Table->strProcessName = strProcName;
	
		Table->ulLocalPort = ntohs( (u_short)pUdp6->table[i].dwLocalPort);

		Table->dwProcessId = pUdp6->table[i].dwOwningPid;

		Table->bIpv6 = TRUE;

		if(pUdp6->table[i].dwOwningPid > 10)
		{
			CProcessModules pl(pUdp6->table[i].dwOwningPid);

			Table->strProcessFullPath = pl.GetProcFilePath();
		}
		else
		{
			Table->strProcessFullPath ="[SYSTEM PROCESS]";
		}

		tblList.AddTail(_PUDPTABLE(Table));
    }

    if ( pUdp )
        free(pUdp);

    if ( pUdp6 )
        free(pUdp6);

	if(pBase)
		delete pBase;

    FreeLibrary(hDLL);

    return 0;   
}
//windows xp/2000
int CUDPTableInfo::NetStatNT(UdpTableList& tblList)
{
    DWORD i = 0;
    HMODULE hDLL = NULL;
    HANDLE hHeap = NULL;

    PMIB_UDPTABLE_EX pUdp = NULL;
    PMIB_UDP6TABLE_EX pUdp6 = NULL;
        
    AllocateAndGetUdpExTableFromStack_t AllocateAndGetUdpExTableFromStack = NULL;

	CBase *pBase = new CBase();


	in_addr stAddr;

	CString strProcName;

    hHeap = GetProcessHeap();

    if ( (hDLL = LoadLibrary("iphlpapi.dll")) == NULL )
        return -1;

    if ( (AllocateAndGetUdpExTableFromStack = (AllocateAndGetUdpExTableFromStack_t)GetProcAddress(hDLL,"AllocateAndGetUdpExTableFromStack")) == NULL )
        return -1;

    if ( AllocateAndGetUdpExTableFromStack((PVOID *)&pUdp, TRUE, hHeap, 0, AF_INET) == NO_ERROR )
    {
        for ( i = 0; i < pUdp->dwNumEntries; i++ )
        {
			_UDPTABLE *Table;
			Table = new _UDPTABLE;

			Table->nIndex = i+1;	//index 
			Table->nTotalEntries = pUdp->dwNumEntries;//Total Entries

			u_long ulLocalAddress = static_cast<u_long>(pUdp->table[i].dwLocalAddr);
			stAddr.s_addr = ulLocalAddress;

			Table->strLocalAddress = inet_ntoa(stAddr); //local addr 

			CString strProcName = pBase->GetProcById(pUdp->table[i].dwProcessId);

			Table->strProcessName = strProcName;
		
			Table->ulLocalPort = ntohs( (u_short)pUdp->table[i].dwLocalPort);

			Table->dwProcessId = pUdp->table[i].dwProcessId;

			Table->bIpv6 = FALSE;

			tblList.AddTail(_PUDPTABLE(Table));
        }
    }

    if ( AllocateAndGetUdpExTableFromStack((PVOID *)&pUdp6, TRUE, hHeap, 0, AF_INET6) == NO_ERROR )
    {
        for ( i = 0; i < pUdp6->dwNumEntries; i++ )
        {

			_UDPTABLE *Table;
			Table = new _UDPTABLE;

			Table->nIndex = i+1;	//index 
			Table->nTotalEntries = pUdp6->dwNumEntries;//Total Entries

			Table->strLocalAddress = pUdp6->table[i].ucLocalAddr;

			CString strProcName = pBase->GetProcById(pUdp6->table[i].dwProcessId);

			Table->strProcessName = strProcName;
		
			Table->ulLocalPort = ntohs( (u_short)pUdp6->table[i].dwLocalPort);

			Table->dwProcessId = pUdp6->table[i].dwProcessId;

			Table->bIpv6 = TRUE;

			tblList.AddTail(_PUDPTABLE(Table));			
        }
    }
        
    if ( pUdp )
        HeapFree(hHeap, 0, pUdp);
    
    
    if ( pUdp6 )
        HeapFree(hHeap, 0, pUdp6);

	if(pBase)
		delete pBase;
    
    FreeLibrary(hDLL);
    
    return 0;
}
