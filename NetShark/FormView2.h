#pragma once



// CFormView2 ������ͼ

class CFormView2 : public CFormView
{
	DECLARE_DYNCREATE(CFormView2)

protected:
	CFormView2();           // ��̬������ʹ�õ��ܱ����Ĺ��캯��
	virtual ~CFormView2();

public:
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_FORMVIEW2 };
#endif
#ifdef _DEBUG
	virtual void AssertValid() const;
#ifndef _WIN32_WCE
	virtual void Dump(CDumpContext& dc) const;
#endif
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
};


