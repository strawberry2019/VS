
// NetSharkView.cpp : CNetSharkView ���ʵ��
//

#include "stdafx.h"
// SHARED_HANDLERS ������ʵ��Ԥ��������ͼ������ɸѡ�������
// ATL ��Ŀ�н��ж��壬�����������Ŀ�����ĵ����롣
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
	// ��׼��ӡ����
	ON_COMMAND(ID_FILE_PRINT, &CView::OnFilePrint)
	ON_COMMAND(ID_FILE_PRINT_DIRECT, &CView::OnFilePrint)
	ON_COMMAND(ID_FILE_PRINT_PREVIEW, &CNetSharkView::OnFilePrintPreview)
	ON_WM_CONTEXTMENU()
	ON_WM_RBUTTONUP()
END_MESSAGE_MAP()

// CNetSharkView ����/����

CNetSharkView::CNetSharkView()
{
	// TODO: �ڴ˴���ӹ������

}

CNetSharkView::~CNetSharkView()
{
}

BOOL CNetSharkView::PreCreateWindow(CREATESTRUCT& cs)
{
	// TODO: �ڴ˴�ͨ���޸�
	//  CREATESTRUCT cs ���޸Ĵ��������ʽ

	return CView::PreCreateWindow(cs);
}

// CNetSharkView ����

void CNetSharkView::OnDraw(CDC* /*pDC*/)
{
	CNetSharkDoc* pDoc = GetDocument();
	ASSERT_VALID(pDoc);
	if (!pDoc)
		return;

	// TODO: �ڴ˴�Ϊ����������ӻ��ƴ���
}


// CNetSharkView ��ӡ


void CNetSharkView::OnFilePrintPreview()
{
#ifndef SHARED_HANDLERS
	AFXPrintPreview(this);
#endif
}

BOOL CNetSharkView::OnPreparePrinting(CPrintInfo* pInfo)
{
	// Ĭ��׼��
	return DoPreparePrinting(pInfo);
}

void CNetSharkView::OnBeginPrinting(CDC* /*pDC*/, CPrintInfo* /*pInfo*/)
{
	// TODO: ��Ӷ���Ĵ�ӡǰ���еĳ�ʼ������
}

void CNetSharkView::OnEndPrinting(CDC* /*pDC*/, CPrintInfo* /*pInfo*/)
{
	// TODO: ��Ӵ�ӡ����е��������
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


// CNetSharkView ���

#ifdef _DEBUG
void CNetSharkView::AssertValid() const
{
	CView::AssertValid();
}

void CNetSharkView::Dump(CDumpContext& dc) const
{
	CView::Dump(dc);
}

CNetSharkDoc* CNetSharkView::GetDocument() const // �ǵ��԰汾��������
{
	ASSERT(m_pDocument->IsKindOf(RUNTIME_CLASS(CNetSharkDoc)));
	return (CNetSharkDoc*)m_pDocument;
}
#endif //_DEBUG


// CNetSharkView ��Ϣ�������
