#pragma once



// Option ������ͼ

class Option : public CFormView
{
	DECLARE_DYNCREATE(Option)

protected:
	Option();           // ��̬������ʹ�õ��ܱ����Ĺ��캯��
	virtual ~Option();

public:
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_OPTION };
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
public:
	
	afx_msg void On32779();
};


