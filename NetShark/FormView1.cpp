// FormView1.cpp : ʵ���ļ�
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


// CFormView1 ���

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


// CFormView1 ��Ϣ�������

//BOOL CFormView1::OnInitDialog()
//{
//	CFormView1::OnInitDialog();
//
//
//	//�˴�����
//	CRect rect;
//	GetClientRect(&rect);     //ȡ�ͻ�����С  
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
//	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
//}
//void CFormView1::ReSize(void)
//{
//	float fsp[2];
//	POINT Newp; //��ȡ���ڶԻ���Ĵ�С
//	CRect recta;
//	GetClientRect(&recta);     //ȡ�ͻ�����С  
//	Newp.x = recta.right - recta.left;
//	Newp.y = recta.bottom - recta.top;
//	fsp[0] = (float)Newp.x / old.x;
//	fsp[1] = (float)Newp.y / old.y;
//	CRect Rect;
//	int woc;
//	CPoint OldTLPoint, TLPoint; //���Ͻ�
//	CPoint OldBRPoint, BRPoint; //���½�
//	HWND  hwndChild = ::GetWindow(m_hWnd, GW_CHILD);  //�г����пؼ�  
//	while (hwndChild)
//	{
//		woc = ::GetDlgCtrlID(hwndChild);//ȡ��ID
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