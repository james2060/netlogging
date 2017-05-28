#pragma once
/**
	@brief	TableInfo class 의 공통 클래스 

	@author	최초 작성자       : 강기수
	@author 마지막 수정자   : 강기수
	@email	idelsoo@empal.com

	@date 최초 작성일    : 2010.09.01
	@date 마지막 수정일 : 2010.09.01

	TableInfo class 의 공통 클래스 
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
