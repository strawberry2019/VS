
// NetSharkView.cpp : CNetSharkView 类的实现
//

#include "stdafx.h"
// SHARED_HANDLERS 可以在实现预览、缩略图和搜索筛选器句柄的
// ATL 项目中进行定义，并允许与该项目共享文档代码。
#ifndef SHARED_HANDLERS
#include "NetShark.h"
#endif

#include "NetSharkDoc.h"
#include "NetSharkView.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CNetSharkView

IMPLEMENT_DYNCREATE(CNetSharkView, CView)

BEGIN_MESSAGE_MAP(CNetSharkView, CView)
	// 标准打印命令
	ON_COMMAND(ID_FILE_PRINT, &CView::OnFilePrint)
	ON_COMMAND(ID_FILE_PRINT_DIRECT, &CView::OnFilePrint)
	ON_COMMAND(ID_FILE_PRINT_PREVIEW, &CNetSharkView::OnFilePrintPreview)
	ON_WM_CONTEXTMENU()
	ON_WM_RBUTTONUP()
END_MESSAGE_MAP()

// CNetSharkView 构造/析构

CNetSharkView::CNetSharkView()
{
	// TODO: 在此处添加构造代码

}

CNetSharkView::~CNetSharkView()
{
}

BOOL CNetSharkView::PreCreateWindow(CREATESTRUCT& cs)
{
	// TODO: 在此处通过修改
	//  CREATESTRUCT cs 来修改窗口类或样式

	return CView::PreCreateWindow(cs);
}

// CNetSharkView 绘制

void CNetSharkView::OnDraw(CDC* /*pDC*/)
{
	CNetSharkDoc* pDoc = GetDocument();
	ASSERT_VALID(pDoc);
	if (!pDoc)
		return;

	// TODO: 在此处为本机数据添加绘制代码
}


// CNetSharkView 打印


void CNetSharkView::OnFilePrintPreview()
{
#ifndef SHARED_HANDLERS
	AFXPrintPreview(this);
#endif
}

BOOL CNetSharkView::OnPreparePrinting(CPrintInfo* pInfo)
{
	// 默认准备
	return DoPreparePrinting(pInfo);
}

void CNetSharkView::OnBeginPrinting(CDC* /*pDC*/, CPrintInfo* /*pInfo*/)
{
	// TODO: 添加额外的打印前进行的初始化过程
}

void CNetSharkView::OnEndPrinting(CDC* /*pDC*/, CPrintInfo* /*pInfo*/)
{
	// TODO: 添加打印后进行的清理过程
}

void CNetSharkView::OnRButtonUp(UINT /* nFlags */, CPoint point)
{
	ClientToScreen(&point);
	OnContextMenu(this, point);
}

void CNetSharkView::OnContextMenu(CWnd* /* pWnd */, CPoint point)
{
#ifndef SHARED_HANDLERS
	theApp.GetContextMenuManager()->ShowPopupMenu(IDR_POPUP_EDIT, point.x, point.y, this, TRUE);
#endif
}


// CNetSharkView 诊断

#ifdef _DEBUG
void CNetSharkView::AssertValid() const
{
	CView::AssertValid();
}

void CNetSharkView::Dump(CDumpContext& dc) const
{
	CView::Dump(dc);
}

CNetSharkDoc* CNetSharkView::GetDocument() const // 非调试版本是内联的
{
	ASSERT(m_pDocument->IsKindOf(RUNTIME_CLASS(CNetSharkDoc)));
	return (CNetSharkDoc*)m_pDocument;
}
#endif //_DEBUG


// CNetSharkView 消息处理程序
