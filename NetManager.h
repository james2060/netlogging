#pragma once

/**
	@brief	각 프로토콜 별 네트워크 상태 정보를 리스트로 가져 온다. 
			해당 리스트 정보를 출력 방식에 의해 출력 한다.

	@author	최초 작성자       : 강기수
	@author 마지막 수정자   : 강기수
	@email	idelsoo@empal.com

	@date 최초 작성일    : 2010.09.01
	@date 마지막 수정일 : 2010.09.01

	각 프로토콜 별 네트워크 상태 정보를 리스트로 가져 온다. 
	해당 리스트 정보를 출력 방식에 의해 출력 한다.
*/
#include "../JDK/pattern/JKSingleton.h"

class CNetManager : public JDK::pattern::JKSingleton< CNetManager > 
{
public:
	CNetManager(void);
	~CNetManager(void);

private:

	void CleanUP();


public:
	BOOL GetTcpTable(TcpTableList& tblList);
	BOOL GetUdpTable(UdpTableList& tblList);

	BOOL TCPLogRecord(TcpTableList* tblList);
	BOOL UDPLogRecord(UdpTableList* tblList);

	void CleanUpTcpList(TcpTableList& tblList);
	void CleanUpUdpList(UdpTableList& tblList);
	bool CloseTCPSessionConn(TcpTableList* tblList,_PSEARCH_TCP pSearch);
	bool IsExistTCPSession(TcpTableList* tblList,_PSEARCH_TCP pSearch);

	CString GetProcessNameByMatchingUDPSession(UdpTableList* tblList,_PSEARCH_UDP pSearch);

	CString	GetProcessNameByMatchingTCPSession(TcpTableList* tblList,_PSEARCH_TCP pSearch);
	CString	GetSessionInfoByProcessName(TcpTableList* tblList, CString strProcessName );

private :
	CRITICAL_SECTION m_cs;	
	void InitCS();
	void EnterCS();
	void LeaveCS();
	void DeleteCS();
};
