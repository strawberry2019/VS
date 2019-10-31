

#include "stdafx.h"
#include "NetShark.h"
#include "Net_Ping.h"
#include "afxdialogex.h"


// Net_Ping 对话框

IMPLEMENT_DYNAMIC(Net_Ping, CDialogEx)

 Net_Ping::Net_Ping(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_PING, pParent)
{
	
}

Net_Ping::~Net_Ping()
{
}

void Net_Ping::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(Net_Ping, CDialogEx)
	
	ON_LBN_SELCHANGE(IDC_LIST1, &Net_Ping::OnLbnSelchangeList1)
END_MESSAGE_MAP()


// Net_Ping 消息处理程序





void Net_Ping::OnLbnSelchangeList1()
{
	// TODO: 在此添加控件通知处理程序代码
}



