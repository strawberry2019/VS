#pragma once



// CFormView1 ������ͼ

class CFormView1 : public CFormView
{
	DECLARE_DYNCREATE(CFormView1)

protected:
	CFormView1();           // ��̬������ʹ�õ��ܱ����Ĺ��캯��
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
//�Ի�������Ӧ
	//afx_msg void OnSize(UINT nType, int cx, int cy);
	//void ReSize(void);
	//POINT old;


protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
	//virtual BOOL OnInitDialog();
};


