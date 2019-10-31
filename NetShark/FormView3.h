#pragma once



// CFormView3 窗体视图

class CFormView3 : public CFormView
{
	DECLARE_DYNCREATE(CFormView3)

protected:
	CFormView3();           // 动态创建所使用的受保护的构造函数
	virtual ~CFormView3();

public:
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_FORMVIEW3 };
#endif
#ifdef _DEBUG
	virtual void AssertValid() const;
#ifndef _WIN32_WCE
	virtual void Dump(CDumpContext& dc) const;
#endif
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
};


