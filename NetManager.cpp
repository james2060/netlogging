#include "StdAfx.h"
#include "NetManager.h"

CNetManager::CNetManager(void)
{
	InitCS();
}

CNetManager::~CNetManager(void)
{
	CleanUP();
}
void CNetManager::CleanUP()
{
	DeleteCS();

	if(CTCPTableInfo::isAllocated())
		CTCPTableInfo::releaseInstance();
	if(CUDPTableInfo::isAllocated())
		CUDPTableInfo::releaseInstance();

}
//caller 에서 메모리 free , remove list all 
BOOL CNetManager::GetTcpTable(TcpTableList& tblList)
{
	BOOL bRet = FALSE;

	EnterCS();

	int nRet = CTCPTableInfo::getInstance()->GetNetStat(tblList);

	LeaveCS();

	if(nRet != -1 )
		bRet = TRUE;

	return bRet;
}
//caller 에서 메모리 free , remove list all 
BOOL CNetManager::GetUdpTable(UdpTableList& tblList)
{
	BOOL bRet = FALSE;

	EnterCS();

	int nRet = CUDPTableInfo::getInstance()->GetNetStat(tblList);

	LeaveCS();

	if(nRet != -1 )
		bRet = TRUE;

	return bRet;
}
BOOL CNetManager::UDPLogRecord(UdpTableList* tblList)
{
	BOOL bRet = FALSE;

	_PUDPTABLE pTable = NULL;

	CStdioFile file;

	CString strLog = _T("");

	if(!file.Open("C:\\udptable.log",CFile::modeCreate | CFile::modeReadWrite))
		return FALSE;

	EnterCS();

	for (POSITION Pos = tblList->GetHeadPosition(); Pos;)
	{
		pTable = tblList->GetNext(Pos);	

		if (pTable == NULL) continue;	

		strLog.Format("%d\t%s\t%d\t%d\t%s\t%u\t%s\n",
		pTable->bIpv6,
		pTable->strProcessName,
		pTable->dwProcessId,
		pTable->nTotalEntries,
		pTable->strLocalAddress,
		pTable->ulLocalPort,
		pTable->strProcessFullPath);

		file.WriteString(strLog);
	
	}
	LeaveCS();


	file.Close();

	return bRet;
}
BOOL CNetManager::TCPLogRecord(TcpTableList* tblList)
{
	BOOL bRet = FALSE;

	CStdioFile file;

	CString strLog = _T("");

	if(!file.Open("C:\\tcptable.log",CFile::modeCreate | CFile::modeReadWrite))
		return FALSE;


	_PTCPTABLE pTable = NULL;

	EnterCS();

	for (POSITION Pos = tblList->GetHeadPosition(); Pos;)
	{
		pTable = tblList->GetNext(Pos);	

		if (pTable == NULL) continue;	

		strLog.Format("%d\t%s\t%d\t%d\t%s\t%s\t%s\t%u\t%u\t%s\n",
		pTable->bIpv6,
		pTable->strProcessName,
		pTable->dwProcessId,
		pTable->nEntryCount,
		pTable->strConnectionState,
		pTable->strLocalAddress,
		pTable->strRemoteAddress,
		pTable->ulLocalPort,
		pTable->ulRemotePort,
		pTable->strProcessFullPath);

		file.WriteString(strLog);

		pTable = NULL;
	}
	LeaveCS();

	file.Close();

	return bRet;
}
void CNetManager::CleanUpTcpList(TcpTableList& tblList)
{

	_PTCPTABLE pTable = NULL;

	EnterCS();

	for (POSITION Pos = tblList.GetHeadPosition(); Pos;)
	{
		pTable = tblList.GetNext(Pos);	

		if (pTable == NULL) continue;	

		delete pTable;
	}
	tblList.RemoveAll();

	LeaveCS();

}
void CNetManager::CleanUpUdpList(UdpTableList& tblList)
{
	_PUDPTABLE pTable = NULL;

	EnterCS();

	for (POSITION Pos = tblList.GetHeadPosition(); Pos;)
	{
		pTable = tblList.GetNext(Pos);	

		if (pTable == NULL) continue;	

		delete pTable;
	}

	tblList.RemoveAll();

	LeaveCS();
}
CString CNetManager::GetProcessNameByMatchingUDPSession(UdpTableList* tblList,_PSEARCH_UDP pSearch)
{
	CString strRet = _T("");
	_PUDPTABLE pTable = NULL;
	CString strProcessInfo = _T("");

	EnterCS();

	for (POSITION Pos = tblList->GetHeadPosition(); Pos;)
	{
		pTable = tblList->GetNext(Pos);	

		if (pTable == NULL) continue;	

		//UDP 는 Local 및 remote IP 주소가 정확하지 않다. UDP TABLE 에는 DEST IP를 알수 없기 때문이다.
		//따라서 PORT 로 검색한다. 공격시점에 LOCAL PORT 는 하나일테니까 ADDED BY KKS 20110629
		if(  pSearch->ulLocalPort == pTable->ulLocalPort  /*&& (pSearch->strLocalAddr == pTable->strLocalAddress)*/ )
		{
			//검색과 일치하면 해당 프로세스 정보를 리턴 한다.
			strProcessInfo.Format("|%s|%d|%s|",pTable->strProcessName,pTable->dwProcessId,pTable->strProcessFullPath);

			return strProcessInfo;
		}	
	}
	LeaveCS();

	return strRet;
}
CString	CNetManager::GetProcessNameByMatchingTCPSession(TcpTableList* tblList,_PSEARCH_TCP pSearch)
{
	CString strRet = _T("");
	_PTCPTABLE pTable = NULL;
	CString strProcessInfo = _T("");

	EnterCS();

	for (POSITION Pos = tblList->GetHeadPosition(); Pos;)
	{
		pTable = tblList->GetNext(Pos);	

		if (pTable == NULL) continue;	

		if( ( pSearch->ulRemotePort == pTable->ulRemotePort ) && (pSearch->strRemoteAddr == pTable->strRemoteAddress) )
		{
			//검색과 일치하면 해당 프로세스 정보를 리턴 한다.
			strProcessInfo.Format("|%s|%d|%s|",pTable->strProcessName,pTable->dwProcessId,pTable->strProcessFullPath);

			return strProcessInfo;
		}	
	}
	for (POSITION Pos = tblList->GetHeadPosition(); Pos;)
	{
		pTable = tblList->GetNext(Pos);	

		if (pTable == NULL) continue;	

		if( pSearch->ulLocalPort == pTable->ulLocalPort )
		{
			//검색과 일치하면 해당 프로세스 정보를 리턴 한다.
			strProcessInfo.Format("|%s|%d|%s|",pTable->strProcessName,pTable->dwProcessId,pTable->strProcessFullPath);

			return strProcessInfo;
		}	
	}
	LeaveCS();

	return strRet;
}
CString CNetManager::GetSessionInfoByProcessName(TcpTableList* tblList, CString strProcessName )
{
	int nCount = 0;
	CString strProc = _T("");
	CString strRet = _T(""),strTemp=_T(""),strPort=_T("");
	_PTCPTABLE pTable = NULL;

	EnterCS();

	for (POSITION Pos = tblList->GetHeadPosition(); Pos;)
	{
		pTable = tblList->GetNext(Pos);	

		if (pTable == NULL) continue;	

		strProc = pTable->strProcessName;
		
		if(strProc.IsEmpty()) continue;

		strProcessName.MakeLower();
		strProc.MakeLower();

		if(strProcessName == strProc)
		{
			nCount++;				
			strTemp+=pTable->strRemoteAddress;
			strTemp+="&";
			strPort.Format("%d",pTable->ulRemotePort);
			strTemp+=strPort;
			strTemp+="&";
			strTemp+=pTable->strLocalAddress;
			strTemp+="&";
			strPort.Format("%d",pTable->ulLocalPort);
			strTemp+=strPort;
			strTemp+="&";
			strTemp+=pTable->strConnectionState;
			strTemp+="&";

			strTemp+="|";
		}
		strProc = _T("");
	}

	LeaveCS();

	strRet.Format("%s%d|",strTemp,nCount);

	return strRet;

}
bool CNetManager::CloseTCPSessionConn(TcpTableList* tblList,_PSEARCH_TCP pSearch)
{
	
	u_long ulLocIP;
	u_long ulRemIP;
	u_short usLocalPort;
	u_short usRemPort;

	if(IsExistTCPSession(tblList,pSearch))
	{
		ulLocIP = inet_addr((LPCTSTR)pSearch->strLocalAddr);
		ulRemIP = inet_addr((LPCTSTR)pSearch->strRemoteAddr);
		usLocalPort = pSearch->ulLocalPort;
		usRemPort = pSearch->ulRemotePort;

		return CTCPTableInfo::getInstance()->CloseTcpSession(ulLocIP,ulRemIP,usLocalPort,usRemPort);
	}

	return false;
}
bool CNetManager::IsExistTCPSession(TcpTableList* tblList,_PSEARCH_TCP pSearch)
{
	_PTCPTABLE pTable = NULL;

	EnterCS();

	for (POSITION Pos = tblList->GetHeadPosition(); Pos;)
	{
		pTable = tblList->GetNext(Pos);	

		if (pTable == NULL) continue;	

		if( ( pSearch->ulRemotePort == pTable->ulRemotePort ) && (pSearch->strRemoteAddr == pTable->strRemoteAddress) )
		{
			return true;
		}	
	}
	LeaveCS();

	return false;
}
void CNetManager::InitCS()
{
	InitializeCriticalSection(&m_cs);
}
void CNetManager::EnterCS()
{
	EnterCriticalSection(&m_cs);
}
void CNetManager::LeaveCS()
{
	LeaveCriticalSection(&m_cs);
}
void CNetManager::DeleteCS()
{
	DeleteCriticalSection(&m_cs);
}