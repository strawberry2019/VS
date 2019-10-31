#pragma once



// Option 窗体视图

class Option : public CFormView
{
	DECLARE_DYNCREATE(Option)

protected:
	Option();           // 动态创建所使用的受保护的构造函数
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
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	
	afx_msg void On32779();
};


