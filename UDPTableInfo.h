#pragma once

/*
 * FILE: UDPTableInfo.h
 * DESCRIPTION: ��Ʈ��ũ UDP ���� ���� 
 * DESIGN: James Kang (kisoo kang)
 * E-Mail: idelsoo@empal.com
 * DATE: 2010. 9. 01
 * LAST UPDATE: 2010. 9. 01
 */

#include "../JDK/pattern/JKSingleton.h"
#include "NetTableInfo.h"

class CUDPTableInfo : public JDK::pattern::JKSingleton< CUDPTableInfo > , public CNetTableInfo
{
public:
	CUDPTableInfo(void);
	~CUDPTableInfo(void);

public:
	int	GetNetStat(UdpTableList& tblList);
	int	NetStatVista(UdpTableList& tblList);
	int	NetStatNT(UdpTableList& tblList);
};
