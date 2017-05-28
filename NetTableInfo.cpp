#include "StdAfx.h"
#include "NetTableInfo.h"

CNetTableInfo::CNetTableInfo(void)
{
}

CNetTableInfo::~CNetTableInfo(void)
{
}
bool CNetTableInfo::KillConnection(u_long ulLocIP,u_long ulRemIP,u_short usLocalPort, u_short usRemPort)
{


	MIB_TCPROW sKillConn;

	sKillConn.dwLocalAddr	= (DWORD)ulLocIP;
	sKillConn.dwLocalPort	= (DWORD)usLocalPort;
	sKillConn.dwRemoteAddr	= (DWORD)ulRemIP;
	sKillConn.dwRemotePort	= (DWORD)usRemPort;
	sKillConn.dwState = MIB_TCP_STATE_DELETE_TCB;
	
	DWORD dwRez = SetTcpEntry(&sKillConn);
	if(dwRez != NO_ERROR)
	{
		dwRez = ::GetLastError();
		return false;
	}

	return true;
}
CString CNetTableInfo::Convert2State(DWORD dwState)
{
	switch(dwState)
	{
		case MIB_TCP_STATE_CLOSED:
			return "CLOSED";
		
		case MIB_TCP_STATE_LISTEN:
			return "LISTEN";

		case MIB_TCP_STATE_SYN_SENT:
			return "SYN_SENT";

		case MIB_TCP_STATE_SYN_RCVD:
			return "SYN_RCVD";

		case MIB_TCP_STATE_ESTAB:
			return "ESTAB";

		case MIB_TCP_STATE_FIN_WAIT1:
			return "FIN_WAIT1";

		case MIB_TCP_STATE_FIN_WAIT2:
			return "FIN_WAIT2";

		case MIB_TCP_STATE_CLOSE_WAIT:
			return "CLOSE_WAIT";

		case MIB_TCP_STATE_CLOSING:
			return "CLOSING";

		case MIB_TCP_STATE_LAST_ACK:
			return "LAST_ACK";

		case MIB_TCP_STATE_TIME_WAIT:
			return "TIME_WAIT";

		case MIB_TCP_STATE_DELETE_TCB:
			return "DELETE_TCB";

		default:
			return "UNKNOWN";
	}
}
BOOL CNetTableInfo::IsVista()
{
    OSVERSIONINFO osver;

    osver.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );
    
    if ( GetVersionEx (&osver) )
    {
        if ( osver.dwPlatformId == VER_PLATFORM_WIN32_NT && (osver.dwMajorVersion >= 6 ) )
            return TRUE;
    }

    return FALSE;
}