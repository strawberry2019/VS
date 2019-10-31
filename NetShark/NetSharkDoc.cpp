
// NetSharkDoc.cpp : CNetSharkDoc 类的实现
//

#include "stdafx.h"
// SHARED_HANDLERS 可以在实现预览、缩略图和搜索筛选器句柄的
// ATL 项目中进行定义，并允许与该项目共享文档代码。
#ifndef SHARED_HANDLERS
#include "NetShark.h"
#endif

#include "NetSharkDoc.h"

#include <propkey.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// CNetSharkDoc

IMPLEMENT_DYNCREATE(CNetSharkDoc, CDocument)

BEGIN_MESSAGE_MAP(CNetSharkDoc, CDocument)
END_MESSAGE_MAP()


// CNetSharkDoc 构造/析构

CNetSharkDoc::CNetSharkDoc()
{
	// TODO: 在此添加一次性构造代码

}

CNetSharkDoc::~CNetSharkDoc()
{
}

//BOOL CNetSharkDoc::OnNewDocument()
//{
//	if (!CDocument::OnNewDocument())
//		return FALSE;
//
//	// TODO: 在此添加重新初始化代码
//	// (SDI 文档将重用该文档)
//
//	return TRUE;
//}




// CNetSharkDoc 序列化

void CNetSharkDoc::Serialize(CArchive& ar)
{
	if (ar.IsStoring())
	{
		// TODO: 在此添加存储代码
	}
	else
	{
		// TODO: 在此添加加载代码
	}
}

#ifdef SHARED_HANDLERS

// 缩略图的支持
void CNetSharkDoc::OnDrawThumbnail(CDC& dc, LPRECT lprcBounds)
{
	// 修改此代码以绘制文档数据
	dc.FillSolidRect(lprcBounds, RGB(255, 255, 255));

	CString strText = _T("TODO: implement thumbnail drawing here");
	LOGFONT lf;

	CFont* pDefaultGUIFont = CFont::FromHandle((HFONT) GetStockObject(DEFAULT_GUI_FONT));
	pDefaultGUIFont->GetLogFont(&lf);
	lf.lfHeight = 36;

	CFont fontDraw;
	fontDraw.CreateFontIndirect(&lf);

	CFont* pOldFont = dc.SelectObject(&fontDraw);
	dc.DrawText(strText, lprcBounds, DT_CENTER | DT_WORDBREAK);
	dc.SelectObject(pOldFont);
}

// 搜索处理程序的支持
void CNetSharkDoc::InitializeSearchContent()
{
	CString strSearchContent;
	// 从文档数据设置搜索内容。
	// 内容部分应由“;”分隔

	// 例如:     strSearchContent = _T("point;rectangle;circle;ole object;")；
	SetSearchContent(strSearchContent);
}

void CNetSharkDoc::SetSearchContent(const CString& value)
{
	if (value.IsEmpty())
	{
		RemoveChunk(PKEY_Search_Contents.fmtid, PKEY_Search_Contents.pid);
	}
	else
	{
		CMFCFilterChunkValueImpl *pChunk = NULL;
		ATLTRY(pChunk = new CMFCFilterChunkValueImpl);
		if (pChunk != NULL)
		{
			pChunk->SetTextValue(PKEY_Search_Contents, value, CHUNK_TEXT);
			SetChunkValue(pChunk);
		}
	}
}

#endif // SHARED_HANDLERS

// CNetSharkDoc 诊断

#ifdef _DEBUG
void CNetSharkDoc::AssertValid() const
{
	CDocument::AssertValid();
}

void CNetSharkDoc::Dump(CDumpContext& dc) const
{
	CDocument::Dump(dc);
}
#endif //_DEBUG


// CNetSharkDoc 命令


BOOL CNetSharkDoc::OnNewDocument()
{
	// TODO: 在此添加专用代码和/或调用基类
	if (!CDocument::OnNewDocument())
				return FALSE;
	//设置MFC单文档标题前半部分
	SetTitle(_T("视频指挥教研室"));
	return true;
}
