#pragma once

/**
	@brief	�� �������� �� ��Ʈ��ũ ���� ������ ����Ʈ�� ���� �´�. 
			�ش� ����Ʈ ������ ��� ��Ŀ� ���� ��� �Ѵ�.

	@author	���� �ۼ���       : �����
	@author ������ ������   : �����
	@email	idelsoo@empal.com

	@date ���� �ۼ���    : 2010.09.01
	@date ������ ������ : 2010.09.01

	�� �������� �� ��Ʈ��ũ ���� ������ ����Ʈ�� ���� �´�. 
	�ش� ����Ʈ ������ ��� ��Ŀ� ���� ��� �Ѵ�.
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
