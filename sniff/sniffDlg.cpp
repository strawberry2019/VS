// mcf6Dlg.cpp : 实现文件
//

#include "stdafx.h"
#include "sniff.h"
#include "sniffDlg.h"
#include <stdint.h>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框
DWORD WINAPI sniff_CapThread(LPVOID lpParameter);

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();
    
// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()







CSniffDlg::CSniffDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CSniffDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSniffDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_listCtrl);
	DDX_Control(pDX, IDC_COMBO1, m_comboBox);
	DDX_Control(pDX, IDC_COMBO2, m_comboBoxRule);
	DDX_Control(pDX, IDC_TREE1, m_treeCtrl);
	DDX_Control(pDX, IDC_EDIT1, m_edit);
	DDX_Control(pDX, IDC_BUTTON1, m_buttonStart);
	DDX_Control(pDX, IDC_BUTTON2, m_buttonStop);
	DDX_Control(pDX, IDC_EDIT2, m_editNTcp);
	DDX_Control(pDX, IDC_EDIT3, m_editNUdp);
	DDX_Control(pDX, IDC_EDIT4, m_editNIcmp);
	DDX_Control(pDX, IDC_EDIT5, m_editNIp);
	DDX_Control(pDX, IDC_EDIT6, m_editNArp);
	DDX_Control(pDX, IDC_EDIT7, m_editNHttp);
	DDX_Control(pDX, IDC_EDIT8, m_editNOther);
	DDX_Control(pDX, IDC_EDIT9, m_editNSum);
	DDX_Control(pDX, IDC_BUTTON5, m_buttonSave);
	DDX_Control(pDX, IDC_BUTTON4, m_buttonRead);
	DDX_Control(pDX, IDC_EDIT10, m_editNIpv4);
	DDX_Control(pDX, IDC_EDIT11, m_editIcmpv6);
}

BEGIN_MESSAGE_MAP(CSniffDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BUTTON1, &CSniffDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CSniffDlg::OnBnClickedButton2)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CSniffDlg::OnLvnItemchangedList1)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &CSniffDlg::OnNMCustomdrawList1)
	ON_BN_CLICKED(IDC_BUTTON5, &CSniffDlg::OnBnClickedButton5)
	ON_BN_CLICKED(IDC_BUTTON4, &CSniffDlg::OnBnClickedButton4)
END_MESSAGE_MAP()


// Cmcf6Dlg 消息处理程序

BOOL CSniffDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	ShowWindow(SW_MINIMIZE);

	// TODO: 在此添加额外的初始化代码
    m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);

	m_listCtrl.InsertColumn(0,_T("编号"),3,30);                        //1表示右，2表示中，3表示左
	m_listCtrl.InsertColumn(1,_T("时间"),3,130);
	m_listCtrl.InsertColumn(2,_T("长度"),3,72);
	m_listCtrl.InsertColumn(3,_T("源MAC地址"),3,140);
	m_listCtrl.InsertColumn(4,_T("目的MAC地址"),3,140);
	m_listCtrl.InsertColumn(5,_T("协议"),3,70);
	m_listCtrl.InsertColumn(6,_T("源IP地址"),3,145);
	m_listCtrl.InsertColumn(7,_T("目的IP地址"),3,145);

	m_comboBox.AddString(_T("请选择一个网卡接口(必选)"));
	m_comboBoxRule.AddString(_T("请选择过滤规则(可选)"));
	
	if(lixsniff_initCap()<0)
		return FALSE;

	/*初始化接口列表*/
	for(dev=alldev;dev;dev=dev->next)
	{
		if(dev->description)
			m_comboBox.AddString(CString(dev->description));  //////////////////////////////Problem 1字符集问题
	}   

	/*初始化过滤规则列表*/
	m_comboBoxRule.AddString(_T("tcp"));
	m_comboBoxRule.AddString(_T("udp"));
	m_comboBoxRule.AddString(_T("ip"));
	m_comboBoxRule.AddString(_T("icmp"));
	m_comboBoxRule.AddString(_T("arp"));

	m_comboBox.SetCurSel(0);
	m_comboBoxRule.SetCurSel(0);

	m_buttonStop.EnableWindow(FALSE);
	m_buttonSave.EnableWindow(FALSE);

	//m_bitButton.RedrawWindow();

	/////////////////////////////////////////////////////////////////////////////////////////////////listControl用法
	//int nitem = m_listCtrl.InsertItem(0,_T("hello"));
	/*char buf[5];
	itoa(nitem,buf,10);
	MessageBox(CString(buf));*/
	/*m_listCtrl.SetItemText(nitem,1,_T("jak"));
	m_listCtrl.SetItemText(nitem,2,_T("bub"));
	m_listCtrl.SetItemText(nitem,3,_T("coco"));
	m_listCtrl.SetItemText(nitem,4,_T("haha"));*/
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CSniffDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CSniffDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CSniffDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

/////////////////////////////////////////［事件函数］///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//开始按钮
void CSniffDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	//如果已经有数据了，提示保存数据
	if(this->m_localDataList.IsEmpty() == FALSE)
	{
		if(MessageBox(_T("确认不保存数据？"),_T("警告"),MB_YESNO)==IDNO)
		{
			this->lixsniff_saveFile();
		}
	}

	this->npkt =1;													//重新计数
	this->m_localDataList.RemoveAll();				//每次一开始就将以前存的数据清空掉
	this->m_netDataList.RemoveAll();
	memset(&(this->npacket),0,sizeof(struct pktcount));
	this->lixsniff_updateNPacket();

	if(this->lixsniff_startCap()<0)
		return;
	this->m_listCtrl.DeleteAllItems();
	this->m_treeCtrl.DeleteAllItems();
	this->m_edit.SetWindowTextW(_T(""));
	this->m_buttonStart.EnableWindow(FALSE);
	this->m_buttonStop.EnableWindow(TRUE);
	this->m_buttonSave.EnableWindow(FALSE);
}

//结束按钮
void CSniffDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	if(NULL == this->m_ThreadHandle )
		return;
	if(TerminateThread(this->m_ThreadHandle,-1)==0)
	{
		MessageBox(_T("关闭线程错误，请稍后重试"));
		return;
	}
	this->m_ThreadHandle = NULL;
	this->m_buttonStart.EnableWindow(TRUE);
	this->m_buttonStop.EnableWindow(FALSE);	
	this->m_buttonSave.EnableWindow(TRUE);
}

//列表
void CSniffDlg::OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	int index;
	index = this->m_listCtrl.GetHotItem();

	if(index>this->m_localDataList.GetCount()-1)
		return;

	this->lixsniff_updateEdit(index);
	this->lixsniff_updateTree(index);
	*pResult = 0;
}

//保存按钮
void CSniffDlg::OnBnClickedButton5()
{
	// TODO: 在此添加控件通知处理程序代码
	if(this->lixsniff_saveFile()<0)
		return;
}

//读取按钮
void CSniffDlg::OnBnClickedButton4()
{
	// TODO: 在此添加控件通知处理程序代码
	//读取之前将ListCtrl清空
	this->m_listCtrl.DeleteAllItems();
	this->npkt =1;													//列表重新计数
	this->m_localDataList.RemoveAll();				//每次一开始就将以前存的数据清空掉
	this->m_netDataList.RemoveAll();
	memset(&(this->npacket),0,sizeof(struct pktcount));//各类包计数清空

	//打开文件对话框
	 CFileDialog   FileDlg(TRUE ,_T(".lix"),NULL,OFN_HIDEREADONLY   |   OFN_OVERWRITEPROMPT);   
	 FileDlg.m_ofn.lpstrInitialDir=_T("c:\\");   
	 if(FileDlg.DoModal()==IDOK)   
	 {   
		 int ret = this->lixsniff_readFile(FileDlg.GetPathName());
		 if(ret < 0)
				return;		 
	 }
}

//改变ListCtrl每行颜色
void CSniffDlg::OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	//LPNMCUSTOMDRAW pNMCD = reinterpret_cast<LPNMCUSTOMDRAW>(pNMHDR);
	LPNMLVCUSTOMDRAW pNMCD = (LPNMLVCUSTOMDRAW)pNMHDR;
	*pResult = 0;
	// TODO: 在此添加控件通知处理程序代码
	if(CDDS_PREPAINT==pNMCD->nmcd.dwDrawStage)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}else if(CDDS_ITEMPREPAINT ==pNMCD->nmcd.dwDrawStage){
		COLORREF crText;
		char buf[10];
		memset(buf,0,10);
		POSITION pos = this->m_localDataList.FindIndex(pNMCD->nmcd.dwItemSpec);
		struct datapkt * local_data = (struct datapkt *)this->m_localDataList.GetAt(pos);
		strcpy(buf,local_data->pktType);

		if(strcmp(buf,"IPV6")==0)
			crText = RGB(111,224,254);
		else if(strcmp(buf,"UDP")==0)
			crText = RGB(194,195,252);				
		else if(strcmp(buf,"TCP")==0)
				crText = RGB(230,230,230);
		else if(strcmp(buf,"ARP")==0)
				crText = RGB(226,238,227);
		else if(strcmp(buf,"ICMP")==0)
				crText = RGB(49,164,238);
		else if(strcmp(buf,"HTTP")==0)
				crText = RGB(238,232,180);
		else if(strcmp(buf,"ICMPv6")==0)
				crText = RGB(189,254,76);

		pNMCD->clrTextBk =crText;
		*pResult = CDRF_DODEFAULT;
	}
}
//////////////////////////////////////////［功能函数］///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//初始化winpcap
int CSniffDlg::lixsniff_initCap()
{
	devCount = 0;
	if(pcap_findalldevs(&alldev, errbuf) ==-1)
		return -1;
	for(dev=alldev;dev;dev=dev->next)
		devCount++;	
	return 0;
}

//开始捕获
int CSniffDlg::lixsniff_startCap()
{	
	int if_index,count;
	u_int netmask;
	struct bpf_program fcode;

	lixsniff_initCap();

	//获得接口和过滤器索引
	if_index = this->m_comboBox.GetCurSel();
	

	if(0==if_index || CB_ERR == if_index)
	{
		MessageBox(_T("请选择一个合适的网卡接口"));
		return -1;
	}
	

	/*获得选中的网卡接口*/
	dev=alldev;
	for(count=0;count<if_index-1;count++)
		dev=dev->next;
    
	if ((adhandle= pcap_open_live(dev->name,	// 设备名
							 65536,											//捕获数据包长度																					
							 1,													// 混杂模式 (非0意味着是混杂模式)
							 1000,												// 读超时设置
							 errbuf											// 错误信息
							 )) == NULL)
	{
		MessageBox(_T("无法打开接口："+CString(dev->description)));	
		pcap_freealldevs(alldev);
		return -1;
	}    

	/*检查是否为以太网*/
	if(pcap_datalink(adhandle)!=DLT_EN10MB)
	{
		MessageBox(_T("这不适合于非以太网的网络!"));
		pcap_freealldevs(alldev);
		return -1;
	}

	if(dev->addresses!=NULL)	
		netmask=((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask=0xffffff; 

	USES_CONVERSION;
	//CString str;
	m_rule.Empty();
	GetDlgItem(IDC_EDT_FILTER)->GetWindowTextW(m_rule);
	char * text = W2A(m_rule);

	//filter_index = this->m_comboBoxRule.GetCurSel();
	//if (CB_ERR == filter_index)
	//{
	//	MessageBox(_T("过滤器选择错误"));
	//	return -1;
	//}
	//编译过滤器
	if(m_rule.IsEmpty())
	{
		char filter[] = "";
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) <0 )
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldev);
			return -1;
		}
	}else{

		if (pcap_compile(adhandle, &fcode, text, 1, netmask) <0)
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldev);
			return -1;
		}


	/*	CString str;
		char *filter;
		int len,x;
		this->m_comboBoxRule.GetLBText(filter_index,str);
		len = str.GetLength()+1;
		filter = (char*)malloc(len);
		for(x=0;x<len;x++)
		{
			filter[x] = str.GetAt(x);
		}
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) <0 )
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldev);
			return -1;
		}*/
	}


	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		MessageBox(_T("设置过滤器错误"));
		pcap_freealldevs(alldev);
		return -1;
	}

	/* 设置数据包存储路径*/
	CFileFind file;
	char thistime[30];
	struct tm *ltime;
	memset(filepath,0,512);
	memset(filename,0,64);

	if(!file.FindFile(_T("SavedData")))
	{
		CreateDirectory(_T("SavedData"),NULL);
	}

	time_t nowtime;
	time(&nowtime);
	ltime=localtime(&nowtime);
	strftime(thistime,sizeof(thistime),"%Y%m%d %H%M%S",ltime);	
	strcpy(filepath,"SavedData\\");
	strcat(filename,thistime);
	strcat(filename,".lix");

	strcat(filepath,filename);
	dumpfile = pcap_dump_open(adhandle, filepath);
	if(dumpfile==NULL)
	{
		MessageBox(_T("文件创建错误！"));
		return -1; 
	}

	pcap_freealldevs(alldev);	

	/*接收数据，新建线程处理*/
	LPDWORD threadCap=NULL;
	m_ThreadHandle=CreateThread(NULL,0,sniff_CapThread,this,0,threadCap);
	if(m_ThreadHandle==NULL)
	{
		int code=GetLastError();
		CString str;
		str.Format(_T("创建线程错误，代码为%d."),code);
		MessageBox(str);
		return -1;
	}
	return 1;
}


static void pcap_cb(unsigned char *user, const struct pcap_pkthdr *hdr, const unsigned char *data)
{
	int *cnt = (int *)user;
	char src_ip[INET_ADDRSTRLEN + 1] = { 0 }, dst_ip[INET_ADDRSTRLEN + 1] = { 0 };

	//fprintf(stdout, "cnt: %d\n", ++(*cnt));
	//fprintf(stdout, "--------------------------------\n");

	struct ethhdr *eth_hdr = (struct ethhdr*)data;
	if (eth_hdr == NULL) return;
	uint8_t eth_hdrlen = sizeof(struct ethhdr);     //ETH包头长度: 14

	//fprintf(stdout, "eth proto: %hu\n", ntohs(eth_hdr->type));
	//fprintf(stdout, "src_mac: %02x:%02x:%02x:%02x:%02x:%02x ", eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2], eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]);
	//fprintf(stdout, "-> ");
	//fprintf(stdout, "dst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->h_dest[0], eth_hdr->h_dest[1], eth_hdr->h_dest[2], eth_hdr->h_dest[3], eth_hdr->h_dest[4], eth_hdr->h_dest[5]);

	struct iphdr *ip_hdr = (struct iphdr *)(hdr->len > eth_hdrlen ? data + eth_hdrlen : NULL);
#if 1 //注意这里分析IPv4 的包
	if (ntohs(eth_hdr->type) != 0x0800 || ip_hdr == NULL) return;
#else
	if (ntohs(eth_hdr->h_proto) != ETH_P_IPV6 || ipv6_hdr == NULL) return;
#endif
	uint8_t ip_hdrlen = ip_hdr->ihl * 4;              //IP包头长度
	uint16_t ip_totlen = ntohs(ip_hdr->tlen);    //IP包总长度

	inet_ntop(AF_INET, &ip_hdr->saddr, src_ip, INET_ADDRSTRLEN + 1);
	inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip, INET_ADDRSTRLEN + 1);
	//fprintf(stdout, "ip proto: %hhu\n", ip_hdr->proto);
	//fprintf(stdout, "src_ip: %s ", src_ip);
	//fprintf(stdout, "-> ");
	//fprintf(stdout, "dst_ip: %s\n", dst_ip);

	if (ip_hdr->proto == IPPROTO_ICMP)
	{
		struct icmphdr *icmp_hdr = (struct icmphdr*)(data + eth_hdrlen + ip_hdrlen);
		uint8_t icmp_hdrlen = sizeof(struct icmphdr);               //ICMP包头长度
		uint16_t icmp_bdylen = ip_totlen - ip_hdrlen - icmp_hdrlen; //ICMP包体长度

		fprintf(stdout, "type: %hhu ", icmp_hdr->type);
		fprintf(stdout, "code: %hhu ", icmp_hdr->code);
		fprintf(stdout, "checksum: %hu\n", ntohs(icmp_hdr->chksum));

		//dump_packet_fp(stdout, (unsigned char*)(data + eth_hdrlen + ip_hdrlen + icmp_hdrlen), icmp_bdylen);
	}
	else if (ip_hdr->proto == IPPROTO_TCP)
	{
		struct tcphdr *tcp_hdr = (struct tcphdr*)(data + eth_hdrlen + ip_hdrlen);
		uint8_t tcp_hdrlen = tcp_hdr->doff * 4;                       //TCP包头长度
		uint16_t tcp_bdylen = ip_totlen - ip_hdrlen - tcp_hdrlen;   //TCP包体长度

		fprintf(stdout, "src_port: %hu ", ntohs(tcp_hdr->sport));
		fprintf(stdout, "-> ");
		fprintf(stdout, "dst_port: %hu\n", ntohs(tcp_hdr->dport));

		//dump_packet_fp(stdout, (unsigned char*)(data + eth_hdrlen + ip_hdrlen + tcp_hdrlen), tcp_bdylen);
	}
	else if (ip_hdr->proto == IPPROTO_UDP)
	{
		struct udphdr *udp_hdr = (struct udphdr*)(data + eth_hdrlen + ip_hdrlen);
		uint8_t udp_hdrlen = sizeof(struct udphdr);                 //UDP包头长度: 8
		uint16_t udp_totlen = ntohs(udp_hdr->len);                  //UDP包总长度
		//数据指针
		const uint8_t * r_data = data + eth_hdrlen + ip_hdrlen + udp_hdrlen;
		int r_data_len = udp_totlen - udp_hdrlen;
		//fprintf(stdout, "src_port: %hu ", ntohs(udp_hdr->source));
		//fprintf(stdout, "-> ");
		//fprintf(stdout, "dst_port: %hu\n", ntohs(udp_hdr->dest));

		//dump_packet_fp(stdout, (unsigned char*)(data + eth_hdrlen + ip_hdrlen + udp_hdrlen), udp_totlen - udp_hdrlen);
	}
	else
	{
		//fprintf(stdout, "unknown ip packet\n");
		//dump_packet_fp(stdout, (unsigned char*)(data + eth_hdrlen + ip_hdrlen), ip_totlen - ip_hdrlen);
	}

	//fprintf(stdout, "--------------------------------\n");
}


DWORD WINAPI sniff_CapThread(LPVOID lpParameter)
{
	int res,nItem ;
	struct tm *ltime;
	CString timestr,buf,srcMac,destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr *header;									  //数据包头
	const u_char *pkt_data=NULL,*pData=NULL;     //网络中收到的字节流数据
	u_char *ppkt_data;
	
	CSniffDlg  *pthis = (CSniffDlg *) lpParameter;
	if(NULL == pthis->m_ThreadHandle)
	{
		MessageBox(NULL,_T("线程句柄错误"),_T("提示"),MB_OK);
		return -1;
	}

	//pkt_data则是我们需要的报文内容, 通过试验, 在调用pcap_next_ex()之后
	//系统会分配一部分内存(大概有500KB左右)供其使用, 返回的报文内容则存放
	//在这部分内存中, 不过这只是暂存, 
	//不能将大量的数据内容放在这一部分内存中的; 通过调试可以看到, 
	//pcap_next_ex()将返回的报文内容线型的存储在这一部分内存中, 
	//当数据量占满了这部分内存后, 会充开始位置覆盖原有数据,
	//所以需要保存报文内容需要写入本地文件或另外开辟内存空间存储!
	while((res = pcap_next_ex( pthis->adhandle, &header, &pkt_data)) >= 0)
	{
		if(res == 0)				//超时
			continue;
		
		struct datapkt *data = (struct datapkt*)malloc(sizeof(struct datapkt));		
		memset(data,0,sizeof(struct datapkt));

		if(NULL == data)
		{
			MessageBox(NULL,_T("空间已满，无法接收新的数据包"),_T("Error"),MB_OK);
			return -1;
		}

 	    //分析出错或所接收数据包不在处理范围内
		//enter :
		if(analyze_frame(pkt_data,data,&(pthis->npacket))<0)
			continue;  
		
		//将数据包保存到打开的文件中
		if(pthis->dumpfile!=NULL)
		{
			pcap_dump((unsigned char*)pthis->dumpfile,header,pkt_data);
		}

		//更新各类数据包计数
		pthis->lixsniff_updateNPacket();

		//将本地化后的数据装入一个链表中，以便后来使用		
		ppkt_data = (u_char*)malloc(header->len);
		memcpy(ppkt_data,pkt_data,header->len);

		pthis->m_localDataList.AddTail(data);
		pthis->m_netDataList.AddTail(ppkt_data);
	
		/*预处理，获得时间、长度*/
		data->len = header->len;								//链路中收到的数据长度
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		data->time[0] = ltime->tm_year+1900;
		data->time[1] = ltime->tm_mon+1;
		data->time[2] = ltime->tm_mday;
		data->time[3] = ltime->tm_hour;
		data->time[4] = ltime->tm_min;
		data->time[5] = ltime->tm_sec;

		/*为新接收到的数据包在listControl中新建一个item*/
		buf.Format(_T("%d"),pthis->npkt);
		nItem = pthis->m_listCtrl.InsertItem(pthis->npkt,buf);

		/*显示时间戳*/
		timestr.Format(_T("%d/%d/%d  %d:%d:%d"),data->time[0],
			data->time[1],data->time[2],data->time[3],data->time[4],data->time[5]);
		pthis->m_listCtrl.SetItemText(nItem,1,timestr);
		//pthis->m_listCtrl.setitem
		
		/*显示长度*/
		buf.Empty();
		buf.Format(_T("%d"),data->len);
		pthis->m_listCtrl.SetItemText(nItem,2,buf);

		/*显示源MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),data->ethh->src[0],data->ethh->src[1],
							data->ethh->src[2],data->ethh->src[3],data->ethh->src[4],data->ethh->src[5]);
		pthis->m_listCtrl.SetItemText(nItem,3,buf);

		/*显示目的MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),data->ethh->dest[0],data->ethh->dest[1],
							data->ethh->dest[2],data->ethh->dest[3],data->ethh->dest[4],data->ethh->dest[5]);
		pthis->m_listCtrl.SetItemText(nItem,4,buf);

		/*获得协议*/
		pthis->m_listCtrl.SetItemText(nItem,5,CString(data->pktType));

		/*获得源IP*/
		buf.Empty();
		if(0x0806== data->ethh->type) //arp协议分析写在这里 钱波
		{
			buf.Format(_T("%d.%d.%d.%d"),data->arph->ar_srcip[0],
				data->arph->ar_srcip[1],data->arph->ar_srcip[2],data->arph->ar_srcip[3]);			
		}
		else if(0x0800 == data->ethh->type) { //ipv4 写在这里 钱波
			struct  in_addr in;
			in.S_un.S_addr = data->iph->saddr;
			buf = CString(inet_ntoa(in));
		}
		else if(0x86dd ==data->ethh->type ){ //ipv6 写在这里
			int n;
			for(n=0;n<8;n++)
			{			
				if(n<=6)
					buf.AppendFormat(_T("%02x:"),data->iph6->saddr[n]);		
				else
					buf.AppendFormat(_T("%02x"),data->iph6->saddr[n]);		
			}
		}
		pthis->m_listCtrl.SetItemText(nItem,6,buf);

		/*获得目的IP*/
		buf.Empty();
		if(0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"),data->arph->ar_destip[0],
				data->arph->ar_destip[1],data->arph->ar_destip[2],data->arph->ar_destip[3]);			
		}else if(0x0800 == data->ethh->type){
			struct  in_addr in;
			in.S_un.S_addr = data->iph->daddr;
			buf = CString(inet_ntoa(in));
		}else if(0x86dd ==data->ethh->type ){
			int n;
			for(n=0;n<8;n++)
			{			
				if(n<=6)
					buf.AppendFormat(_T("%02x:"),data->iph6->daddr[n]);		
				else
					buf.AppendFormat(_T("%02x"),data->iph6->daddr[n]);		
			}
		}
		pthis->m_listCtrl.SetItemText(nItem,7,buf);
	
		/*对包计数*/
		pthis->npkt++;
	
	}
	return 1;
}

//更新信息
int CSniffDlg::lixsniff_updateEdit(int index)
{
	POSITION localpos,netpos;
	localpos = this->m_localDataList.FindIndex(index);
	netpos = this->m_netDataList.FindIndex(index);

	struct datapkt* local_data = (struct datapkt*)(this->m_localDataList.GetAt(localpos));
	u_char * net_data = (u_char*)(this->m_netDataList.GetAt(netpos));

	CString buf;
	print_packet_hex(net_data,local_data->len,&buf);
	//this-
	this->m_edit.SetWindowText(buf);

	return 1;
}

//更新统计数据
int CSniffDlg::lixsniff_updateNPacket()
{
		CString str_num;		
		str_num.Format(_T("%d"),this->npacket.n_arp);
		this->m_editNArp.SetWindowText(str_num);

		str_num.Format(_T("%d"),this->npacket.n_http);
		this->m_editNHttp.SetWindowText(str_num);

		str_num.Format(_T("%d"),this->npacket.n_icmp);
		this->m_editNIcmp.SetWindowText(str_num);

		str_num.Format(_T("%d"),this->npacket.n_ip6);
		this->m_editNIp.SetWindowText(str_num);

		str_num.Format(_T("%d"),this->npacket.n_other);
		this->m_editNOther.SetWindowText(str_num);

		str_num.Format(_T("%d"),this->npacket.n_sum);
		this->m_editNSum.SetWindowText(str_num);

		str_num.Format(_T("%d"),this->npacket.n_tcp);
		this->m_editNTcp.SetWindowText(str_num);
		
		str_num.Format(_T("%d"),this->npacket.n_udp);
		this->m_editNUdp.SetWindowText(str_num);
	
		str_num.Format(_T("%d"),this->npacket.n_ip);
		this->m_editNIpv4.SetWindowText(str_num);

		str_num.Format(_T("%d"),this->npacket.n_icmp6);
		this->m_editIcmpv6.SetWindowText(str_num);

		return 1;
}

//更新树形控件
int CSniffDlg::lixsniff_updateTree(int index)
{
	POSITION localpos;
	CString str;
	int i;
	
	this->m_treeCtrl.DeleteAllItems();

	localpos = this->m_localDataList.FindIndex(index);
	struct datapkt* local_data = (struct datapkt*)(this->m_localDataList.GetAt(localpos));
	
	HTREEITEM root = this->m_treeCtrl.GetRootItem();
	str.Format(_T("接收到的第%d个数据包"),index+1);
	HTREEITEM data = this->m_treeCtrl.InsertItem(str,root);

	/*处理帧数据*/
	HTREEITEM frame = this->m_treeCtrl.InsertItem(_T("链路层数据"),data);
	//源MAC
	str.Format(_T("源MAC："));
	for(i=0;i<6;i++)
	{
		if(i<=4)
			str.AppendFormat(_T("%02x-"),local_data->ethh->src[i]);
		else
			str.AppendFormat(_T("%02x"),local_data->ethh->src[i]);
	}
	this->m_treeCtrl.InsertItem(str,frame);
	//目的MAC
	str.Format(_T("目的MAC："));
	for(i=0;i<6;i++)
	{
		if(i<=4)
			str.AppendFormat(_T("%02x-"),local_data->ethh->dest[i]);
		else
			str.AppendFormat(_T("%02x"),local_data->ethh->dest[i]);
	}
	this->m_treeCtrl.InsertItem(str,frame);
	//类型
	str.Format(_T("类型：0x%02x"),local_data->ethh->type);
	this->m_treeCtrl.InsertItem(str,frame);

	/*处理IP、ARP、IPv6数据包*/
	if(0x0806 == local_data->ethh->type)							//ARP
	{
		HTREEITEM arp = this->m_treeCtrl.InsertItem(_T("ARP协议头"),data);
		str.Format(_T("硬件类型：%d"),local_data->arph->ar_hrd);
		this->m_treeCtrl.InsertItem(str,arp);
		str.Format(_T("协议类型：0x%02x"),local_data->arph->ar_pro);
		this->m_treeCtrl.InsertItem(str,arp);
		str.Format(_T("硬件地址长度：%d"),local_data->arph->ar_hln);
		this->m_treeCtrl.InsertItem(str,arp);
		str.Format(_T("协议地址长度：%d"),local_data->arph->ar_pln);
		this->m_treeCtrl.InsertItem(str,arp);
		str.Format(_T("操作码：%d"),local_data->arph->ar_op);
		this->m_treeCtrl.InsertItem(str,arp);

		str.Format(_T("发送方MAC："));
		for(i=0;i<6;i++)
		{
			if(i<=4)
				str.AppendFormat(_T("%02x-"),local_data->arph->ar_srcmac[i]);
			else
				str.AppendFormat(_T("%02x"),local_data->arph->ar_srcmac[i]);
		}
		this->m_treeCtrl.InsertItem(str,arp);

		str.Format(_T("发送方IP："),local_data->arph->ar_hln);
		for(i=0;i<4;i++)
		{
			if(i<=2)
				str.AppendFormat(_T("%d."),local_data->arph->ar_srcip[i]);
			else
				str.AppendFormat(_T("%d"),local_data->arph->ar_srcip[i]);
		}
		this->m_treeCtrl.InsertItem(str,arp);

		str.Format(_T("接收方MAC："),local_data->arph->ar_hln);
		for(i=0;i<6;i++)
		{
			if(i<=4)
				str.AppendFormat(_T("%02x-"),local_data->arph->ar_destmac[i]);
			else
				str.AppendFormat(_T("%02x"),local_data->arph->ar_destmac[i]);
		}
		this->m_treeCtrl.InsertItem(str,arp);

		str.Format(_T("接收方IP："),local_data->arph->ar_hln);
		for(i=0;i<4;i++)
		{
			if(i<=2)
				str.AppendFormat(_T("%d."),local_data->arph->ar_destip[i]);
			else
				str.AppendFormat(_T("%d"),local_data->arph->ar_destip[i]);
		}
		this->m_treeCtrl.InsertItem(str,arp);

	}else if(0x0800 == local_data->ethh->type){					//IP
		
		HTREEITEM ip = this->m_treeCtrl.InsertItem(_T("IP协议头"),data);

		str.Format(_T("版本：%d"),local_data->iph->version);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("IP头长：%d"),local_data->iph->ihl);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("服务类型：%d"),local_data->iph->tos);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("总长度：%d"),local_data->iph->tlen);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("标识：0x%02x"),local_data->iph->id);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("段偏移：%d"),local_data->iph->frag_off);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("生存期：%d"),local_data->iph->ttl);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("协议：%d"),local_data->iph->proto);
		this->m_treeCtrl.InsertItem(str,ip);		
		str.Format(_T("头部校验和：0x%02x"),local_data->iph->check);
		this->m_treeCtrl.InsertItem(str,ip);

		str.Format(_T("源IP："));
		struct in_addr in;
		in.S_un.S_addr = local_data->iph->saddr;		
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_treeCtrl.InsertItem(str,ip);

		str.Format(_T("目的IP："));
		in.S_un.S_addr = local_data->iph->daddr;		
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_treeCtrl.InsertItem(str,ip);

		/*处理传输层ICMP、UDP、TCP*/
		if(1 == local_data->iph->proto )							//ICMP
		{
			HTREEITEM icmp = this->m_treeCtrl.InsertItem(_T("ICMP协议头"),data);
				
			str.Format(_T("类型:%d"),local_data->icmph->type);
			this->m_treeCtrl.InsertItem(str,icmp);
			str.Format(_T("代码:%d"),local_data->icmph->code);
			this->m_treeCtrl.InsertItem(str,icmp);
			str.Format(_T("序号:%d"),local_data->icmph->seq);
			this->m_treeCtrl.InsertItem(str,icmp);
			str.Format(_T("校验和:%d"),local_data->icmph->chksum);
			this->m_treeCtrl.InsertItem(str,icmp);

		}
		else if(6 == local_data->iph->proto){				//TCP
			
			HTREEITEM tcp = this->m_treeCtrl.InsertItem(_T("TCP协议头"),data);

			str.Format(_T("  源端口:%d"),local_data->tcph->sport);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  目的端口:%d"),local_data->tcph->dport);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  序列号:0x%02x"),local_data->tcph->seq);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  确认号:%d"),local_data->tcph->ack_seq);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  头部长度:%d"),local_data->tcph->doff);

			HTREEITEM flag = this->m_treeCtrl.InsertItem(_T(" +标志位"),tcp);
	
			str.Format(_T("cwr %d"),local_data->tcph->cwr);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("ece %d"),local_data->tcph->ece);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("urg %d"),local_data->tcph->urg);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("ack %d"),local_data->tcph->ack);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("psh %d"),local_data->tcph->psh);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("rst %d"),local_data->tcph->rst);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("syn %d"),local_data->tcph->syn);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("fin %d"),local_data->tcph->fin);
			this->m_treeCtrl.InsertItem(str,flag);

			str.Format(_T("  紧急指针:%d"),local_data->tcph->urg_ptr);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  校验和:0x%02x"),local_data->tcph->check);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  选项:%d"),local_data->tcph->opt);
			this->m_treeCtrl.InsertItem(str,tcp);
		}else if(17 == local_data->iph->proto){				//UDP
			HTREEITEM udp = this->m_treeCtrl.InsertItem(_T("UDP协议头"),data);
				
			str.Format(_T("源端口:%d"),local_data->udph->sport);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("目的端口:%d"),local_data->udph->dport);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("总长度:%d"),local_data->udph->len);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("校验和:0x%02x"),local_data->udph->check);
			this->m_treeCtrl.InsertItem(str,udp);
		}
	}else if(0x86dd == local_data->ethh->type){		//IPv6
		HTREEITEM ip6 = this->m_treeCtrl.InsertItem(_T("IPv6协议头"),data);
		
		//////////////////////////////////////////////////////////////////////////////////////////
		str.Format(_T("版本:%d"),local_data->iph6->flowtype);
		this->m_treeCtrl.InsertItem(str,ip6);
		str.Format(_T("流类型:%d"),local_data->iph6->version);
		this->m_treeCtrl.InsertItem(str,ip6);
		///////////////////////////////////////////////////////////////////////////////////////////
		str.Format(_T("流标签:%d"),local_data->iph6->flowid);
		this->m_treeCtrl.InsertItem(str,ip6);
		str.Format(_T("有效载荷长度:%d"),local_data->iph6->plen);
		this->m_treeCtrl.InsertItem(str,ip6);
		str.Format(_T("下一个首部:0x%02x"),local_data->iph6->nh);
		this->m_treeCtrl.InsertItem(str,ip6);
		str.Format(_T("跳限制:%d"),local_data->iph6->hlim);
		this->m_treeCtrl.InsertItem(str,ip6);

		str.Format(_T("源地址:"));
		int n;
		for(n=0;n<8;n++)
		{			
			if(n<=6)
				str.AppendFormat(_T("%02x:"),local_data->iph6->saddr[n]);		
			else
				str.AppendFormat(_T("%02x"),local_data->iph6->saddr[n]);		
		}	
		this->m_treeCtrl.InsertItem(str,ip6);

		str.Format(_T("目的地址:"));
		for(n=0;n<8;n++)
		{			
			if(n<=6)
				str.AppendFormat(_T("%02x:"),local_data->iph6->saddr[n]);		
			else
				str.AppendFormat(_T("%02x"),local_data->iph6->saddr[n]);		
		}	
		this->m_treeCtrl.InsertItem(str,ip6);

		/*处理传输层ICMPv6、UDP、TCP*/
		if(0x3a== local_data->iph6->nh )							//ICMPv6
		{
			HTREEITEM icmp6 = this->m_treeCtrl.InsertItem(_T("ICMPv6协议头"),data);
				
			str.Format(_T("类型:%d"),local_data->icmph6->type);
			this->m_treeCtrl.InsertItem(str,icmp6);
			str.Format(_T("代码:%d"),local_data->icmph6->code);
			this->m_treeCtrl.InsertItem(str,icmp6);
			str.Format(_T("序号:%d"),local_data->icmph6->seq);
			this->m_treeCtrl.InsertItem(str,icmp6);
			str.Format(_T("校验和:%d"),local_data->icmph6->chksum);
			this->m_treeCtrl.InsertItem(str,icmp6);
			str.Format(_T("选项-类型:%d"),local_data->icmph6->op_type);
			this->m_treeCtrl.InsertItem(str,icmp6);
			str.Format(_T("选项-长度%d"),local_data->icmph6->op_len);
			this->m_treeCtrl.InsertItem(str,icmp6);
			str.Format(_T("选项-链路层地址:"));
			int i;
			for(i=0;i<6;i++)
			{
				if(i<=4)				
					str.AppendFormat(_T("%02x-"),local_data->icmph6->op_ethaddr[i]);
				else
					str.AppendFormat(_T("%02x"),local_data->icmph6->op_ethaddr[i]);
			}
			this->m_treeCtrl.InsertItem(str,icmp6);

		}else if(0x06 == local_data->iph6->nh){				//TCP
			
			HTREEITEM tcp = this->m_treeCtrl.InsertItem(_T("TCP协议头"),data);

			str.Format(_T("  源端口:%d"),local_data->tcph->sport);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  目的端口:%d"),local_data->tcph->dport);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  序列号:0x%02x"),local_data->tcph->seq);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  确认号:%d"),local_data->tcph->ack_seq);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  头部长度:%d"),local_data->tcph->doff);

			HTREEITEM flag = this->m_treeCtrl.InsertItem(_T("标志位"),tcp);
	
			str.Format(_T("cwr %d"),local_data->tcph->cwr);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("ece %d"),local_data->tcph->ece);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("urg %d"),local_data->tcph->urg);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("ack %d"),local_data->tcph->ack);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("psh %d"),local_data->tcph->psh);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("rst %d"),local_data->tcph->rst);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("syn %d"),local_data->tcph->syn);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("fin %d"),local_data->tcph->fin);
			this->m_treeCtrl.InsertItem(str,flag);

			str.Format(_T("  紧急指针:%d"),local_data->tcph->urg_ptr);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  校验和:0x%02x"),local_data->tcph->check);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  选项:%d"),local_data->tcph->opt);
			this->m_treeCtrl.InsertItem(str,tcp);
		}else if(0x11== local_data->iph6->nh){				//UDP
			HTREEITEM udp = this->m_treeCtrl.InsertItem(_T("UDP协议头"),data);

			str.Format(_T("源端口:%d"),local_data->udph->sport);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("目的端口:%d"),local_data->udph->dport);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("总长度:%d"),local_data->udph->len);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("校验和:0x%02x"),local_data->udph->check);
			this->m_treeCtrl.InsertItem(str,udp);
		}
	}

	return 1;
}


int CSniffDlg::lixsniff_saveFile()
{
	CFileFind find;
	if(NULL==find.FindFile(CString(filepath)))
	{
		MessageBox(_T("保存文件遇到未知意外"));
		return -1;
	}

	//打开文件对话框
	 CFileDialog   FileDlg(FALSE,_T(".lix"),NULL,OFN_HIDEREADONLY   |   OFN_OVERWRITEPROMPT);   
	 FileDlg.m_ofn.lpstrInitialDir=_T("c:\\");   
	 if(FileDlg.DoModal()==IDOK)   
	 {   
			CopyFile(CString(filepath),FileDlg.GetPathName(),TRUE);
	 }
	return 1;
}

int CSniffDlg::lixsniff_readFile(CString path)
{
	int res,nItem,i ;
	struct tm *ltime;
	CString timestr,buf,srcMac,destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr *header;									  //数据包头
	const u_char *pkt_data=NULL;     //网络中收到的字节流数据
	u_char *ppkt_data;

	CSniffDlg  *pthis =this;						
	pcap_t *fp;
	
	//首先处理一下路径，利用pcap_open_offline打开文件时，
	//路径需要用char *类型，不能用CString强制转换后的char *
	int len = path.GetLength()+1;							/////////////////////////////////注意这一个细节，必须要加1，否则会出错
	char* charpath = (char *)malloc(len);
	memset(charpath,0,len);
	if(NULL==charpath)
		return -1;

	for(i=0;i<len;i++)
		charpath[i] = (char)path.GetAt(i);
	
	//打开相关文件
	if ((fp = pcap_open_offline( /*(char*)(LPCTSTR)path*/charpath, errbuf)) == NULL)
	{
		MessageBox(_T("打开文件错误")+CString(errbuf));
		return -1;
	}
	
	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		struct datapkt *data = (struct datapkt*)malloc(sizeof(struct datapkt));		
		memset(data,0,sizeof(struct datapkt));

		if(NULL == data)
		{
			MessageBox(_T("空间已满，无法接收新的数据包"));
			return  -1;
		}

 	    //分析出错或所接收数据包不在处理范围内
		if(analyze_frame(pkt_data,data,&(pthis->npacket))<0)
			 continue;
		
		//更新各类数据包计数
		pthis->lixsniff_updateNPacket();

		//将本地化后的数据装入一个链表中，以便后来使用		
		ppkt_data = (u_char*)malloc(header->len);
		memcpy(ppkt_data,pkt_data,header->len);

		pthis->m_localDataList.AddTail(data);
		pthis->m_netDataList.AddTail(ppkt_data);
	
		/*预处理，获得时间、长度*/
		data->len = header->len;								//链路中收到的数据长度
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		data->time[0] = ltime->tm_year+1900;
		data->time[1] = ltime->tm_mon+1;
		data->time[2] = ltime->tm_mday;
		data->time[3] = ltime->tm_hour;
		data->time[4] = ltime->tm_min;
		data->time[5] = ltime->tm_sec;

		/*为新接收到的数据包在listControl中新建一个item*/
		buf.Format(_T("%d"),pthis->npkt);
		nItem = pthis->m_listCtrl.InsertItem(pthis->npkt,buf);

		/*显示时间戳*/
		timestr.Format(_T("%d/%d/%d  %d:%d:%d"),data->time[0],
			data->time[1],data->time[2],data->time[3],data->time[4],data->time[5]);
		pthis->m_listCtrl.SetItemText(nItem,1,timestr);
		
		/*显示长度*/
		buf.Empty();
		buf.Format(_T("%d"),data->len);
		pthis->m_listCtrl.SetItemText(nItem,2,buf);

		/*显示源MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),data->ethh->src[0],data->ethh->src[1],
							data->ethh->src[2],data->ethh->src[3],data->ethh->src[4],data->ethh->src[5]);
		pthis->m_listCtrl.SetItemText(nItem,3,buf);

		/*显示目的MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),data->ethh->dest[0],data->ethh->dest[1],
							data->ethh->dest[2],data->ethh->dest[3],data->ethh->dest[4],data->ethh->dest[5]);
		pthis->m_listCtrl.SetItemText(nItem,4,buf);

		/*获得协议*/
		pthis->m_listCtrl.SetItemText(nItem,5,CString(data->pktType));

		/*获得源IP*/
		buf.Empty();
		if(0x0806== data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"),data->arph->ar_srcip[0],
				data->arph->ar_srcip[1],data->arph->ar_srcip[2],data->arph->ar_srcip[3]);			
		}else  if(0x0800 == data->ethh->type){
			struct  in_addr in;
			in.S_un.S_addr = data->iph->saddr;
			buf = CString(inet_ntoa(in));
		}else if(0x86dd == data->ethh->type){
			int i;
			for(i=0;i<8;i++)
			{
				if(i<=6)
					buf.AppendFormat(_T("%02x-"),data->iph6->saddr[i]);
				else
					buf.AppendFormat(_T("%02x"),data->iph6->saddr[i]);
			}
		}
		pthis->m_listCtrl.SetItemText(nItem,6,buf);

		/*获得目的IP*/
		buf.Empty();
		if(0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"),data->arph->ar_destip[0],
				data->arph->ar_destip[1],data->arph->ar_destip[2],data->arph->ar_destip[3]);			
		}else if(0x0800 == data->ethh->type) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->daddr;
			buf = CString(inet_ntoa(in));
		}else if(0x86dd == data->ethh->type){
			int i;
			for(i=0;i<8;i++)
			{
				if(i<=6)

					buf.AppendFormat(_T("%02x-"),data->iph6->daddr[i]);
				else
					buf.AppendFormat(_T("%02x"),data->iph6->daddr[i]);
			}
		}
		pthis->m_listCtrl.SetItemText(nItem,7,buf);
	
		/*对包计数*/
		pthis->npkt++;
	}

	pcap_close(fp);

	return 1;
}


void CSniffDlg::AnalyseRTP(int tcpudp, unsigned short port, unsigned char  * pkt, int len)
{
	CString str;
	//tcp
	if (tcpudp == 0) {

	}
	//udp
	else if (tcpudp == 1) {

	}
}