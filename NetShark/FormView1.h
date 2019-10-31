#pragma once



// CFormView1 窗体视图

class CFormView1 : public CFormView
{
	DECLARE_DYNCREATE(CFormView1)

protected:
	CFormView1();           // 动态创建所使用的受保护的构造函数
	virtual ~CFormView1();

public:
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_FORMVIEW1 };
#endif
#ifdef _DEBUG
	virtual void AssertValid() const;
#ifndef _WIN32_WCE
	virtual void Dump(CDumpContext& dc) const;
	
#endif
#endif
//对话框自适应
	//afx_msg void OnSize(UINT nType, int cx, int cy);
	//void ReSize(void);
	//POINT old;


protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
	//virtual BOOL OnInitDialog();
};


