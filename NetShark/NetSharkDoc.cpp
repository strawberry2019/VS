
// NetSharkDoc.cpp : CNetSharkDoc ���ʵ��
//

#include "stdafx.h"
// SHARED_HANDLERS ������ʵ��Ԥ��������ͼ������ɸѡ�������
// ATL ��Ŀ�н��ж��壬�����������Ŀ�����ĵ����롣
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


// CNetSharkDoc ����/����

CNetSharkDoc::CNetSharkDoc()
{
	// TODO: �ڴ����һ���Թ������

}

CNetSharkDoc::~CNetSharkDoc()
{
}

//BOOL CNetSharkDoc::OnNewDocument()
//{
//	if (!CDocument::OnNewDocument())
//		return FALSE;
//
//	// TODO: �ڴ�������³�ʼ������
//	// (SDI �ĵ������ø��ĵ�)
//
//	return TRUE;
//}




// CNetSharkDoc ���л�

void CNetSharkDoc::Serialize(CArchive& ar)
{
	if (ar.IsStoring())
	{
		// TODO: �ڴ���Ӵ洢����
	}
	else
	{
		// TODO: �ڴ���Ӽ��ش���
	}
}

#ifdef SHARED_HANDLERS

// ����ͼ��֧��
void CNetSharkDoc::OnDrawThumbnail(CDC& dc, LPRECT lprcBounds)
{
	// �޸Ĵ˴����Ի����ĵ�����
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

// ������������֧��
void CNetSharkDoc::InitializeSearchContent()
{
	CString strSearchContent;
	// ���ĵ����������������ݡ�
	// ���ݲ���Ӧ�ɡ�;���ָ�

	// ����:     strSearchContent = _T("point;rectangle;circle;ole object;")��
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

// CNetSharkDoc ���

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


// CNetSharkDoc ����


BOOL CNetSharkDoc::OnNewDocument()
{
	// TODO: �ڴ����ר�ô����/����û���
	if (!CDocument::OnNewDocument())
				return FALSE;
	//����MFC���ĵ�����ǰ�벿��
	SetTitle(_T("��Ƶָ�ӽ�����"));
	return true;
}
