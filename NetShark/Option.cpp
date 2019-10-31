// Option.cpp : 实现文件
//

#include "stdafx.h"
#include "NetShark.h"
#include "Option.h"



// Option

IMPLEMENT_DYNCREATE(Option, CFormView)

Option::Option()
	: CFormView(IDD_OPTION)
{

}

Option::~Option()
{
}

void Option::DoDataExchange(CDataExchange* pDX)
{
	CFormView::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(Option, CFormView)
		ON_COMMAND(ID_32779, &Option::On32779)
END_MESSAGE_MAP()


// Option 诊断

#ifdef _DEBUG
void Option::AssertValid() const
{
	CFormView::AssertValid();
}

#ifndef _WIN32_WCE
void Option::Dump(CDumpContext& dc) const
{
	CFormView::Dump(dc);
}
#endif
#endif //_DEBUG


// Option 消息处理程序





void Option::On32779()
{
	// TODO: 在此添加命令处理程序代码
	AfxMessageBox(_T("123"));
}
