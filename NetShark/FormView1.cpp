// FormView1.cpp : 实现文件
//

#include "stdafx.h"
#include "NetShark.h"
#include "FormView1.h"


// CFormView1

IMPLEMENT_DYNCREATE(CFormView1, CFormView)

CFormView1::CFormView1()
	: CFormView(IDD_FORMVIEW1)
{

}

CFormView1::~CFormView1()
{
}

void CFormView1::DoDataExchange(CDataExchange* pDX)
{
	CFormView::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CFormView1, CFormView)
END_MESSAGE_MAP()


// CFormView1 诊断

#ifdef _DEBUG
void CFormView1::AssertValid() const
{
	CFormView::AssertValid();
}

#ifndef _WIN32_WCE
void CFormView1::Dump(CDumpContext& dc) const
{
	CFormView::Dump(dc);
}
#endif
#endif //_DEBUG


// CFormView1 消息处理程序

//BOOL CFormView1::OnInitDialog()
//{
//	CFormView1::OnInitDialog();
//
//
//	//此处代码
//	CRect rect;
//	GetClientRect(&rect);     //取客户区大小  
//	old.x = rect.right - rect.left;
//	old.y = rect.bottom - rect.top;
//	int cx = GetSystemMetrics(SM_CXFULLSCREEN);
//	int cy = GetSystemMetrics(SM_CYFULLSCREEN);
//	CRect rt;
//	SystemParametersInfo(SPI_GETWORKAREA, 0, &rt, 0);
//	cy = rt.bottom;
//	MoveWindow(0, 0, cx, cy);
//
//
//
//
//	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
//}
//void CFormView1::ReSize(void)
//{
//	float fsp[2];
//	POINT Newp; //获取现在对话框的大小
//	CRect recta;
//	GetClientRect(&recta);     //取客户区大小  
//	Newp.x = recta.right - recta.left;
//	Newp.y = recta.bottom - recta.top;
//	fsp[0] = (float)Newp.x / old.x;
//	fsp[1] = (float)Newp.y / old.y;
//	CRect Rect;
//	int woc;
//	CPoint OldTLPoint, TLPoint; //左上角
//	CPoint OldBRPoint, BRPoint; //右下角
//	HWND  hwndChild = ::GetWindow(m_hWnd, GW_CHILD);  //列出所有控件  
//	while (hwndChild)
//	{
//		woc = ::GetDlgCtrlID(hwndChild);//取得ID
//		GetDlgItem(woc)->GetWindowRect(Rect);
//		ScreenToClient(Rect);
//		OldTLPoint = Rect.TopLeft();
//		TLPoint.x = long(OldTLPoint.x*fsp[0]);
//		TLPoint.y = long(OldTLPoint.y*fsp[1]);
//		OldBRPoint = Rect.BottomRight();
//		BRPoint.x = long(OldBRPoint.x *fsp[0]);
//		BRPoint.y = long(OldBRPoint.y *fsp[1]);
//		Rect.SetRect(TLPoint, BRPoint);
//		GetDlgItem(woc)->MoveWindow(Rect, TRUE);
//		hwndChild = ::GetWindow(hwndChild, GW_HWNDNEXT);
//	}
//	old = Newp;
//}