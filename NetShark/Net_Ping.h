#pragma once


// Net_Ping �Ի���




#include <winsock2.h>

#pragma comment(lib, "WS2_32")    // ���ӵ�WS2_32.lib

#define DEF_PACKET_SIZE 32
#define ECHO_REQUEST 8
#define ECHO_REPLY 0

struct IPHeader
{
	BYTE m_byVerHLen; //4λ�汾+4λ�ײ�����
	BYTE m_byTOS; //��������
	USHORT m_usTotalLen; //�ܳ���
	USHORT m_usID; //��ʶ
	USHORT m_usFlagFragOffset; //3λ��־+13λƬƫ��
	BYTE m_byTTL; //TTL
	BYTE m_byProtocol; //Э��
	USHORT m_usHChecksum; //�ײ������
	ULONG m_ulSrcIP; //ԴIP��ַ
	ULONG m_ulDestIP; //Ŀ��IP��ַ
};

struct ICMPHeader
{
	BYTE m_byType; //����
	BYTE m_byCode; //����
	USHORT m_usChecksum; //����� 
	USHORT m_usID; //��ʶ��
	USHORT m_usSeq; //���
	ULONG m_ulTimeStamp; //ʱ������Ǳ�׼ICMPͷ����
};

struct PingReply
{
	USHORT m_usSeq;
	DWORD m_dwRoundTripTime;
	DWORD m_dwBytes;
	DWORD m_dwTTL;
};



class Net_Ping : public CDialogEx
{
	DECLARE_DYNAMIC(Net_Ping)

public:
	//Net_Ping(CWnd* pParent = NULL);
	Net_Ping(CWnd* pParent = NULL);
	
	// ��׼���캯��
	virtual ~Net_Ping();

	// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_PING };
#endif

protected:
	
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	
	afx_msg void OnLbnSelchangeList1();
	

};