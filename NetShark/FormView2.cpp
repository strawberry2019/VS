// FormView2.cpp : 实现文件
//

#include "stdafx.h"
#include "NetShark.h"
#include "FormView2.h"


// CFormView2

IMPLEMENT_DYNCREATE(CFormView2, CFormView)

CFormView2::CFormView2()
	: CFormView(IDD_FORMVIEW2)
{

}

CFormView2::~CFormView2()
{
}

void CFormView2::DoDataExchange(CDataExchange* pDX)
{
	CFormView::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CFormView2, CFormView)
END_MESSAGE_MAP()


// CFormView2 诊断

#ifdef _DEBUG
void CFormView2::AssertValid() const
{
	CFormView::AssertValid();
}

#ifndef _WIN32_WCE
void CFormView2::Dump(CDumpContext& dc) const
{
	CFormView::Dump(dc);
}
#endif
#endif //_DEBUG


// CFormView2 消息处理程序
