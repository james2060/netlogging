#pragma once
/**
	@brief	TableInfo class �� ���� Ŭ���� 

	@author	���� �ۼ���       : �����
	@author ������ ������   : �����
	@email	idelsoo@empal.com

	@date ���� �ۼ���    : 2010.09.01
	@date ������ ������ : 2010.09.01

	TableInfo class �� ���� Ŭ���� 
*/


class CNetTableInfo
{
public:
	CNetTableInfo(void);
	~CNetTableInfo(void);

	bool KillConnection(u_long ulLocIP,u_long ulRemIP,u_short usLocalPort, u_short usRemPort);
	CString Convert2State(DWORD dwState);
	BOOL IsVista();
};
