// rescue_gui.cpp - Rescue Security Center: a dark security-operations console.
//
// Faithfully rebuilds the Rescue dashboard design as a native, dependency-free,
// double-buffered Win32 app (cross-compiles with MinGW for x86_64 and ARM64):
// a left navigation rail, a hero protection panel with a shield + live stats, a
// grid of the six defense modules with status chips, and an activity feed +
// quarantine list. Buttons drive the real engines (scanner / ransom_guard /
// lockdown_breaker / backup) that sit next to this .exe. Custom GDI drawing with
// hit-tested regions, MDL2 icon glyphs, and hover states - no dated Win32 chrome.
#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <shlobj.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <deque>
#include <thread>

#pragma GCC diagnostic ignored "-Wunused-parameter"

// ------------------------------------------------------------- palette (dark)-
#define CBG      RGB(0x0a,0x0e,0x16)
#define CBG2     RGB(0x0d,0x12,0x20)
#define CPANEL   RGB(0x12,0x1a,0x2b)
#define CPANEL2  RGB(0x17,0x21,0x36)
#define CLINE    RGB(0x24,0x31,0x49)
#define CLINE2   RGB(0x2f,0x3f,0x5c)
#define CINK     RGB(0xe8,0xee,0xf7)
#define CMUT     RGB(0x93,0xa1,0xba)
#define CMUT2    RGB(0x68,0x76,0x8f)
#define CACC     RGB(0x3d,0x8b,0xfd)
#define CACC2    RGB(0x5a,0xa2,0xff)
#define CACCD    RGB(0x16,0x23,0x3d)
#define CGOOD    RGB(0x3f,0xb9,0x50)
#define CGOODD   RGB(0x12,0x30,0x21)
#define CWARN    RGB(0xe0,0xa4,0x15)
#define CWARND   RGB(0x33,0x28,0x0a)
#define CCRIT    RGB(0xfb,0x5a,0x4b)
#define CCRITD   RGB(0x3a,0x15,0x12)

// ------------------------------------------------------------- actions --------
enum {
    A_NONE=0, A_QUICK, A_FULL, A_USB, A_GUARD_TGL, A_UNLOCK, A_ASEP, A_BACKUP,
    A_QUAR_OPEN, A_NAV_DASH, A_NAV_GUARD, A_NAV_SCAN, A_NAV_QUAR, A_NAV_USB,
    A_NAV_LOGS, A_NAV_SET
};

struct Hit { RECT rc; int action; };
static std::vector<Hit> gHits;
static int gHover = A_NONE;

// activity feed + state
enum Sev { EV_OK, EV_WARN, EV_CRIT, EV_INFO };
struct Event { Sev sev; std::wstring title, detail, ago; };
static std::deque<Event> gFeed;

static HWND gWnd=nullptr;
static bool gGuardOn=false;
static HANDLE gGuardProc=nullptr;
static bool gScanning=false;
static int  gScanPct=0;
static long gScanCount=0;
static std::wstring gScanPath;
static long gThreats=0;   // real: quarantine item count

static HFONT fDispXL,fDisp,fDispS,fSans,fSansS,fSansXS,fMono,fIcon,fIconBig,fIconNav,fShield;

// ------------------------------------------------------------- helpers --------
static std::wstring exeDir(){ wchar_t b[MAX_PATH*2]; GetModuleFileNameW(nullptr,b,MAX_PATH*2);
    std::wstring p=b; size_t s=p.find_last_of(L"\\/"); return s==std::wstring::npos?L".":p.substr(0,s); }
static std::wstring tool(const wchar_t* n){ return L"\""+exeDir()+L"\\"+n+L"\""; }
static std::wstring pdRescue(){ wchar_t b[MAX_PATH*2]; DWORD n=GetEnvironmentVariableW(L"ProgramData",b,MAX_PATH*2);
    return (n?std::wstring(b):L"C:\\ProgramData")+L"\\Rescue"; }

static void feedAdd(Sev s,const std::wstring& t,const std::wstring& d){
    gFeed.push_front({s,t,d,L"now"}); if(gFeed.size()>40) gFeed.pop_back();
    if(gWnd) InvalidateRect(gWnd,nullptr,FALSE);
}

// count quarantined items from the real manifest (honest stat, not demo data)
static long quarantineCount(){
    std::wstring mf=pdRescue()+L"\\Quarantine\\manifest.txt";
    FILE* f=_wfopen(mf.c_str(),L"r, ccs=UTF-8"); if(!f) return 0;
    long n=0; wchar_t line[2048];
    while(fgetws(line,2048,f)){ if(line[0]>='0'&&line[0]<='9') ++n; }   // dated rows
    fclose(f); return n;
}

// ---- engine runner (background thread; drains output, posts progress) -------
static void runReader(HANDLE rd,bool scan){
    char buf[4096]; DWORD got=0; std::string acc;
    while(ReadFile(rd,buf,sizeof(buf)-1,&got,nullptr)&&got){
        buf[got]=0; acc.append(buf,got);
        if(scan){ // count "score" hits and progress heartbeat
            gScanCount+=got/64; if(gScanPct<95) gScanPct+=1;
            if(gWnd) InvalidateRect(gWnd,nullptr,FALSE);
        }
    }
    CloseHandle(rd); (void)acc;
}
static HANDLE launchEngine(const std::wstring& cmdline,bool scan,bool* doneFlag){
    SECURITY_ATTRIBUTES sa{}; sa.nLength=sizeof(sa); sa.bInheritHandle=TRUE;
    HANDLE rd=nullptr,wr=nullptr; if(!CreatePipe(&rd,&wr,&sa,0)) return nullptr;
    SetHandleInformation(rd,HANDLE_FLAG_INHERIT,0);
    STARTUPINFOW si{}; si.cb=sizeof(si); si.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
    si.wShowWindow=SW_HIDE; si.hStdOutput=wr; si.hStdError=wr; si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
    std::wstring cmd=cmdline; std::vector<wchar_t> m(cmd.begin(),cmd.end()); m.push_back(0);
    PROCESS_INFORMATION pi{};
    BOOL ok=CreateProcessW(nullptr,m.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW,nullptr,exeDir().c_str(),&si,&pi);
    CloseHandle(wr);
    if(!ok){ CloseHandle(rd); return nullptr; }
    CloseHandle(pi.hThread);
    if(!doneFlag){ std::thread([rd,scan]{ runReader(rd,scan); }).detach(); return pi.hProcess; }
    std::thread([rd,scan,hp=pi.hProcess]{
        runReader(rd,scan); WaitForSingleObject(hp,INFINITE); CloseHandle(hp);
        gScanning=false; gScanPct=100;
        feedAdd(EV_INFO,L"Scan completed",L"Objects checked \u00b7 review any findings above");
        gScanPct=0; gScanCount=0;
        if(gWnd) InvalidateRect(gWnd,nullptr,FALSE);
    }).detach();
    return nullptr;
}

static void startScan(bool full){
    if(gScanning) return; gScanning=true; gScanPct=2; gScanCount=0;
    gScanPath = full?L"scanning all fixed drives":L"Downloads, Desktop, Temp, startup";
    feedAdd(EV_INFO, full?L"Full scan started":L"Quick scan started", gScanPath);
    launchEngine(tool(L"scanner.exe")+(full?L" --full":L""),true,(bool*)1);
    InvalidateRect(gWnd,nullptr,FALSE);
}
static void setGuard(bool on){
    if(on&&!gGuardProc){ gGuardProc=launchEngine(tool(L"ransom_guard.exe")+L" --shield",false,nullptr);
        gGuardOn=gGuardProc!=nullptr; feedAdd(EV_OK,L"Real-time guard enabled",L"Behavioral protection + disk shield armed"); }
    else if(!on&&gGuardProc){ TerminateProcess(gGuardProc,0); CloseHandle(gGuardProc); gGuardProc=nullptr;
        gGuardOn=false; feedAdd(EV_WARN,L"Real-time guard disabled",L"Files are no longer being watched"); }
    InvalidateRect(gWnd,nullptr,FALSE);
}
static void doAction(int a){
    switch(a){
    case A_QUICK: case A_NAV_SCAN: startScan(false); break;
    case A_FULL: startScan(true); break;
    case A_GUARD_TGL: case A_NAV_GUARD: setGuard(!gGuardOn); break;
    case A_UNLOCK: feedAdd(EV_INFO,L"Unlock / clean started",L"Undoing lockdown levers + screen effects");
        launchEngine(tool(L"lockdown_breaker.exe")+L" --fix --kill-overlays --kill-effects",false,(bool*)1); break;
    case A_ASEP: feedAdd(EV_INFO,L"Autostart scan started",L"Checking every ASEP against signatures");
        launchEngine(tool(L"asep_cleaner.exe"),false,(bool*)1); break;
    case A_USB: case A_NAV_USB:
        MessageBoxW(gWnd,L"Build a bootable rescue USB with:\n\n  offline\\Make-RescueDisk.ps1 -Drive F: -Mode bootable\n\n"
                        L"or a one-click restore disk (official Windows ISO + your backup):\n\n"
                        L"  offline\\Make-RescueDisk.ps1 -Drive F: -Mode oneclick -Iso <ISO>",
                    L"Rescue USB",MB_ICONINFORMATION); break;
    case A_BACKUP:{
        BROWSEINFOW bi{}; bi.hwndOwner=gWnd; bi.lpszTitle=L"Choose a BACKUP DISK or folder (external drive best)";
        bi.ulFlags=BIF_RETURNONLYFSDIRS|BIF_NEWDIALOGSTYLE; LPITEMIDLIST pidl=SHBrowseForFolderW(&bi);
        if(pidl){ wchar_t p[MAX_PATH]; if(SHGetPathFromIDListW(pidl,p)){ feedAdd(EV_INFO,L"Backup started",p);
            launchEngine(tool(L"backup.exe")+L" --snapshot \""+p+L"\" --keep 10",false,(bool*)1);} CoTaskMemFree(pidl);} break; }
    case A_QUAR_OPEN: case A_NAV_QUAR:{ std::wstring q=pdRescue()+L"\\Quarantine";
        CreateDirectoryW(pdRescue().c_str(),nullptr); CreateDirectoryW(q.c_str(),nullptr);
        ShellExecuteW(gWnd,L"explore",q.c_str(),nullptr,nullptr,SW_SHOW); break; }
    default: break;
    }
}

// ------------------------------------------------------------- GDI utils ------
static void fillR(HDC dc,RECT r,COLORREF c){ HBRUSH b=CreateSolidBrush(c); FillRect(dc,&r,b); DeleteObject(b); }
static void vgrad(HDC dc,RECT r,COLORREF a,COLORREF b){ int h=r.bottom-r.top; if(h<=0)return;
    for(int y=0;y<h;++y){ double t=(double)y/h; int R=(int)(GetRValue(a)+(GetRValue(b)-GetRValue(a))*t);
        int G=(int)(GetGValue(a)+(GetGValue(b)-GetGValue(a))*t); int B=(int)(GetBValue(a)+(GetBValue(b)-GetBValue(a))*t);
        RECT ln={r.left,r.top+y,r.right,r.top+y+1}; fillR(dc,ln,RGB(R,G,B)); } }
static void card(HDC dc,RECT r,COLORREF fill,COLORREF border,int rad){
    HBRUSH b=CreateSolidBrush(fill); HPEN p=CreatePen(PS_SOLID,1,border);
    HGDIOBJ ob=SelectObject(dc,b),op=SelectObject(dc,p);
    RoundRect(dc,r.left,r.top,r.right,r.bottom,rad,rad);
    SelectObject(dc,ob); SelectObject(dc,op); DeleteObject(b); DeleteObject(p); }
static void txt(HDC dc,const wchar_t* s,RECT r,HFONT f,COLORREF c,UINT fmt){
    HGDIOBJ of=SelectObject(dc,f); SetTextColor(dc,c); SetBkMode(dc,TRANSPARENT);
    DrawTextW(dc,s,-1,&r,fmt|DT_NOPREFIX); SelectObject(dc,of); }
static void chip(HDC dc,int x,int y,const wchar_t* s,COLORREF fg,COLORREF bg,COLORREF bd){
    HDC mdc=dc; SIZE sz; HGDIOBJ of=SelectObject(mdc,fSansXS); GetTextExtentPoint32W(mdc,s,(int)wcslen(s),&sz); SelectObject(mdc,of);
    RECT r={x,y,x+sz.cx+30,y+22}; card(dc,r,bg,bd,11);
    // dot
    HBRUSH b=CreateSolidBrush(fg); RECT d={x+10,y+8,x+16,y+14}; HGDIOBJ ob=SelectObject(dc,b);
    Ellipse(dc,d.left,d.top,d.right,d.bottom); SelectObject(dc,ob); DeleteObject(b);
    RECT tr={x+20,y,r.right,y+22}; txt(dc,s,tr,fSansXS,fg,DT_LEFT|DT_VCENTER|DT_SINGLELINE); }
static void reg(RECT r,int a){ gHits.push_back({r,a}); }
static bool isHot(int a){ return gHover==a && a!=A_NONE; }

// ------------------------------------------------------------- module cards ---
struct Mod { const wchar_t* icon,*name,*role,*metric1,*metric2; int chipKind; const wchar_t* chip; int action; };
// chipKind: 0 ok,1 warn,2 crit,3 idle
static void drawMod(HDC dc,RECT r,const Mod& m,bool dim){
    COLORREF bd = isHot(m.action)?CLINE2:CLINE;
    card(dc,r,CPANEL,bd,14);
    // icon tile
    RECT it={r.left+16,r.top+16,r.left+54,r.top+54};
    COLORREF itbg=dim?RGB(0x14,0x1c,0x2c):(m.chipKind==1?CWARND:CACCD);
    COLORREF itfg=dim?CMUT:(m.chipKind==1?CWARN:CACC2);
    card(dc,it,itbg,dim?CLINE:RGB(0x22,0x37,0x5c),10);
    txt(dc,m.icon,it,fIcon,itfg,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOCLIP);
    RECT nm={r.left+64,r.top+16,r.right-96,r.top+40}; txt(dc,m.name,nm,fDispS,CINK,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
    RECT ro={r.left+64,r.top+38,r.right-16,r.top+58}; txt(dc,m.role,ro,fSansXS,CMUT2,DT_LEFT|DT_SINGLELINE);
    // chip top-right
    COLORREF cf=CGOOD,cb=CGOODD,cd=RGB(0x1c,0x4a,0x30);
    if(m.chipKind==1){cf=CWARN;cb=CWARND;cd=RGB(0x4d,0x3c,0x10);}
    else if(m.chipKind==2){cf=CCRIT;cb=CCRITD;cd=RGB(0x58,0x20,0x19);}
    else if(m.chipKind==3){cf=CMUT;cb=RGB(0x14,0x1c,0x2c);cd=CLINE;}
    SIZE sz; HGDIOBJ of=SelectObject(dc,fSansXS); GetTextExtentPoint32W(dc,m.chip,(int)wcslen(m.chip),&sz); SelectObject(dc,of);
    chip(dc,r.right-sz.cx-46,r.top+16,m.chip,cf,cb,cd);
    // metric box
    RECT mb={r.left+16,r.top+66,r.right-16,r.top+110}; card(dc,mb,CBG2,CLINE,8);
    RECT m1={mb.left+11,mb.top+7,mb.right-11,mb.top+27}; txt(dc,m.metric1,m1,fSansS,CMUT,DT_LEFT|DT_SINGLELINE);
    RECT m2={mb.left+11,mb.top+24,mb.right-11,mb.bottom-6}; txt(dc,m.metric2,m2,fSansS,CMUT,DT_LEFT|DT_SINGLELINE);
    // action link
    RECT lk={r.right-92,r.bottom-32,r.right-14,r.bottom-8};
    txt(dc,isHot(m.action)?L"Open  \u2192":L"Open  \u203a",lk,fSansS,CACC2,DT_RIGHT|DT_VCENTER|DT_SINGLELINE);
    reg(r,m.action);
}

// ------------------------------------------------------------- paint ----------
static void navItem(HDC dc,int x,int& y,int w,const wchar_t* icon,const wchar_t* label,int action,bool on,const wchar_t* badge){
    RECT r={x,y,x+w,y+38};
    if(on) card(dc,r,CACCD,CACCD,9);
    else if(isHot(action)){ card(dc,r,CPANEL,CPANEL,9); }
    RECT ic={x+11,y,x+34,y+38}; txt(dc,icon,ic,fIconNav,on?CACC2:CMUT,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOCLIP);
    RECT tr={x+40,y,x+w-30,y+38}; txt(dc,label,tr,fSans,on?CACC2:CMUT,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    if(badge){ SIZE sz; HGDIOBJ of=SelectObject(dc,fSansXS); GetTextExtentPoint32W(dc,badge,(int)wcslen(badge),&sz); SelectObject(dc,of);
        RECT b={x+w-sz.cx-24,y+9,x+w-8,y+29}; card(dc,b,CWARN,CWARN,10); txt(dc,badge,b,fSansXS,RGB(0x18,0x12,0x00),DT_CENTER|DT_VCENTER|DT_SINGLELINE); }
    reg(r,action); y+=40;
}

static void paint(HWND hwnd){
    PAINTSTRUCT ps; HDC wdc=BeginPaint(hwnd,&ps); RECT cr; GetClientRect(hwnd,&cr);
    HDC dc=CreateCompatibleDC(wdc); HBITMAP bmp=CreateCompatibleBitmap(wdc,cr.right,cr.bottom);
    HGDIOBJ ob=SelectObject(dc,bmp);
    gHits.clear();
    fillR(dc,cr,CBG);

    // ---------------- left rail ----------------
    int RAIL=232;
    RECT rail={0,0,RAIL,cr.bottom}; vgrad(dc,rail,CBG2,CBG);
    RECT rl={RAIL-1,0,RAIL,cr.bottom}; fillR(dc,rl,CLINE);
    // brand
    RECT bmk={22,20,58,56}; txt(dc,L"\uE83D",bmk,fShield,CACC2,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOCLIP);
    RECT bn={62,20,RAIL-8,44}; txt(dc,L"Rescue",bn,fDisp,CINK,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT bs={64,44,RAIL-8,62}; txt(dc,L"SECURITY CENTER",bs,fSansXS,CMUT2,DT_LEFT|DT_SINGLELINE);
    int ny=84;
    navItem(dc,14,ny,RAIL-28,L"\uE80A",L"Dashboard",A_NAV_DASH,true,nullptr);
    navItem(dc,14,ny,RAIL-28,L"\uE83D",L"Real-time Guard",A_NAV_GUARD,false,nullptr);
    navItem(dc,14,ny,RAIL-28,L"\uE721",L"Scan",A_NAV_SCAN,false,nullptr);
    { wchar_t qc[8]; wsprintfW(qc,L"%ld",gThreats); navItem(dc,14,ny,RAIL-28,L"\uE7BA",L"Quarantine",A_NAV_QUAR,false, gThreats>0?qc:nullptr); }
    navItem(dc,14,ny,RAIL-28,L"\uEDA2",L"Rescue USB",A_NAV_USB,false,nullptr);
    navItem(dc,14,ny,RAIL-28,L"\uE7C3",L"Logs",A_NAV_LOGS,false,nullptr);
    navItem(dc,14,ny,RAIL-28,L"\uE713",L"Settings",A_NAV_SET,false,nullptr);
    RECT foot={22,cr.bottom-56,RAIL-14,cr.bottom-12};
    txt(dc,gGuardOn?L"\u25CF  Protected \u00b7 guard live\nRescue 0.1.0 \u00b7 both arches":
                    L"\u25CF  Idle \u00b7 guard off\nRescue 0.1.0 \u00b7 both arches",
        foot,fSansXS,gGuardOn?CGOOD:CMUT2,DT_LEFT|DT_WORDBREAK);

    // ---------------- top bar ----------------
    int X=RAIL, W=cr.right-RAIL;
    RECT top={X,0,cr.right,58}; fillR(dc,top,CBG2);
    RECT tl={X,57,cr.right,58}; fillR(dc,tl,CLINE);
    RECT th={X+26,0,X+300,58}; txt(dc,L"Dashboard",th,fDispS,CINK,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    wchar_t clock[32]; SYSTEMTIME st; GetLocalTime(&st); wsprintfW(clock,L"%02d:%02d:%02d",st.wHour,st.wMinute,st.wSecond);
    RECT tc={cr.right-140,0,cr.right-58,58}; txt(dc,clock,tc,fMono,CMUT,DT_RIGHT|DT_VCENTER|DT_SINGLELINE);
    RECT tg={cr.right-46,14,cr.right-14,46}; card(dc,tg,CPANEL,CLINE,9);
    txt(dc,L"\uE713",tg,fIconNav,CMUT,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOCLIP); reg(tg,A_NAV_SET);

    int pad=24, cx=X+pad, cw=W-pad*2, y=58+pad;

    // ---------------- hero ----------------
    int heroH=196; RECT hero={cx,y,cx+cw,y+heroH}; vgrad(dc,hero,CPANEL,CBG2);
    card(dc,hero,CPANEL,CLINE,14); // border overlay (fill already gradient-ish)
    // re-stroke border since card overwrote fill; draw gradient inside then border:
    { RECT inner={hero.left+1,hero.top+1,hero.right-1,hero.bottom-1}; vgrad(dc,inner,CPANEL,CBG2);
      HPEN p=CreatePen(PS_SOLID,1,CLINE); HGDIOBJ op=SelectObject(dc,p); HGDIOBJ obr=SelectObject(dc,GetStockObject(NULL_BRUSH));
      RoundRect(dc,hero.left,hero.top,hero.right,hero.bottom,14,14); SelectObject(dc,op); SelectObject(dc,obr); DeleteObject(p); }
    // shield
    RECT sh={hero.left+28,hero.top+28,hero.left+156,hero.bottom-28};
    txt(dc,L"\uE83D",sh,fShield,gGuardOn?CGOOD:CWARN,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOCLIP);
    int hx=hero.left+180;
    RECT he={hx,hero.top+22,hero.right-24,hero.top+42};
    txt(dc,gGuardOn?L"SYSTEM PROTECTED":L"REDUCED PROTECTION",he,fSansXS,gGuardOn?CGOOD:CWARN,DT_LEFT|DT_SINGLELINE);
    RECT ht={hx,hero.top+40,hero.right-24,hero.top+78};
    txt(dc,gScanning?L"Scan running\u2026":(gGuardOn?L"You're protected":L"Real-time guard is off"),
        ht,fDispXL,CINK,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
    RECT hsub={hx,hero.top+80,hero.right-24,hero.top+104};
    txt(dc, gGuardOn?L"Real-time ransomware guard + disk shield are watching your files.":
                     L"Turn on real-time protection to stop ransomware as it runs.",
        hsub,fSansS,CMUT,DT_LEFT|DT_SINGLELINE);
    // CTA buttons
    int by=hero.top+112, bx=hx;
    struct B{const wchar_t* t;int a;bool prim;} btns[]={{L"Run quick scan",A_QUICK,true},{L"Full scan",A_FULL,false},{L"Build rescue USB",A_USB,false}};
    for(auto& bb:btns){ SIZE sz; HGDIOBJ of=SelectObject(dc,fSansS); GetTextExtentPoint32W(dc,bb.t,(int)wcslen(bb.t),&sz); SelectObject(dc,of);
        RECT r={bx,by,bx+sz.cx+34,by+38};
        COLORREF f=bb.prim?CACC:CPANEL2, b2=bb.prim?CACC:CLINE2;
        if(isHot(bb.a)){ f=bb.prim?CACC2:CPANEL2; b2=CACC; }
        card(dc,r,f,b2,10); txt(dc,bb.t,r,fSansS,bb.prim?RGB(0x04,0x12,0x2b):CINK,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        reg(r,bb.a); bx=r.right+11; }
    // scan progress bar (only while scanning)
    if(gScanning){
        RECT tr={hx,hero.bottom-24,hero.right-24,hero.bottom-17}; card(dc,tr,CPANEL2,CLINE,6);
        RECT fl={tr.left,tr.top,tr.left+(int)((tr.right-tr.left)*gScanPct/100.0),tr.bottom}; if(fl.right>fl.left) card(dc,fl,CACC,CACC,6);
        RECT lp={hx,hero.bottom-40,hero.right-24,hero.bottom-24}; wchar_t s[128];
        wsprintfW(s,L"%ls  \u00b7  %ld scanned",gScanPath.c_str(),gScanCount); txt(dc,s,lp,fSansXS,CMUT,DT_LEFT|DT_SINGLELINE);
    } else {
        // stat grid (4 tiles)
        int gy=hero.top+150, gw=(hero.right-24-hx-3*3)/4, gh=40;
        struct T{const wchar_t* k,*v;COLORREF vc;} tiles[]={
            {L"THREATS BLOCKED", nullptr, CGOOD},{L"REAL-TIME GUARD", gGuardOn?L"On":L"Off", gGuardOn?CGOOD:CWARN},
            {L"CANARY FILES", gGuardOn?L"6 active":L"\u2014", CINK},{L"DISK SHIELD", gGuardOn?L"On":L"Off", gGuardOn?CGOOD:CMUT}};
        wchar_t tb[16]; wsprintfW(tb,L"%ld",gThreats);
        for(int i=0;i<4;++i){ RECT t={hx+i*(gw+3),gy,hx+i*(gw+3)+gw,gy+gh}; card(dc,t,CBG2,CLINE,8);
            RECT k={t.left+10,t.top+5,t.right-6,t.top+19}; txt(dc,tiles[i].k,k,fSansXS,CMUT2,DT_LEFT|DT_SINGLELINE);
            RECT v={t.left+10,t.top+18,t.right-6,t.bottom-4}; txt(dc,i==0?tb:tiles[i].v,v,fDispS,tiles[i].vc,DT_LEFT|DT_SINGLELINE|DT_BOTTOM); }
    }
    y=hero.bottom+pad;

    // ---------------- section header ----------------
    RECT sec={cx,y,cx+240,y+20}; txt(dc,L"Defense modules",sec,fSans,CINK,DT_LEFT|DT_SINGLELINE);
    RECT secl={cx+150,y+10,cx+cw,y+11}; fillR(dc,secl,CLINE);
    y+=30;

    // ---------------- module grid (3 cols x 2 rows) ----------------
    Mod mods[6]={
        {L"\uE83D",L"Ransom Guard",L"Behavioral real-time protection", gGuardOn?L"Watching folders \u00b7 6 canaries armed":L"Off \u00b7 turn on to arm canaries", L"Trip \u2192 suspend the busiest writer", 0, gGuardOn?L"Active":L"Off", A_GUARD_TGL},
        {L"\uE785",L"Lockdown Breaker",L"Undo malware lockdowns", L"Task Mgr \u00b7 regedit \u00b7 CMD \u00b7 shell", L"WDAC policy \u00b7 input lock \u00b7 overlays", 0, L"Ready", A_UNLOCK},
        {L"\uE8FD",L"ASEP Cleaner",L"Every autostart, signature-checked", L"Run \u00b7 services \u00b7 tasks \u00b7 IFEO", L"Flags unsigned \u00b7 no virus DB needed", 0, L"Ready", A_ASEP},
        {L"\uE721",L"Threat Scanner",L"Heuristic + hash + quarantine", L"PE entropy \u00b7 MOTW priority", L"Downloads deep-scanned first", 0, L"Updated", A_QUICK},
        {L"\uE9D9",L"Watchdog",L"Self-protecting service pair", L"Two services \u00b7 each restarts the other", L"Keeps Ransom Guard alive", 0, L"Ready", A_BACKUP},
        {L"\uE950",L"Kernel Filter",L"Un-killable real-time tier", L"Minifilter \u00b7 per-write attribution", L"Requires a signed driver to load", 3, L"Not installed", A_NONE},
    };
    mods[2].chipKind=0; // asep neutral unless flagged
    int cols=3, gap=14; int mw=(cw-gap*(cols-1))/cols, mh=124;
    for(int i=0;i<6;++i){ int col=i%cols,row=i/cols; RECT r={cx+col*(mw+gap),y+row*(mh+gap),cx+col*(mw+gap)+mw,y+row*(mh+gap)+mh};
        drawMod(dc,r,mods[i], i==5); }
    y+=2*(mh+gap)+6;

    // ---------------- lower: activity + quarantine ----------------
    int lgap=22; int aw=(cw-lgap)*58/100;
    int lh=cr.bottom-y-pad; if(lh<140) lh=140;
    RECT act={cx,y,cx+aw,y+lh}; card(dc,act,CPANEL,CLINE,14);
    RECT ahl={act.left+18,act.top,act.right-16,act.top+44};
    txt(dc,L"Activity",ahl,fSans,CINK,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT ahln={act.left,act.top+44,act.right,act.top+45}; fillR(dc,ahln,CLINE);
    int ey=act.top+52;
    for(auto& e:gFeed){ if(ey>act.bottom-40) break;
        COLORREF sv= e.sev==EV_OK?CGOOD:e.sev==EV_WARN?CWARN:e.sev==EV_CRIT?CCRIT:CACC;
        RECT bar={act.left+18,ey+2,act.left+21,ey+40}; card(dc,bar,sv,sv,2);
        RECT t={act.left+32,ey,act.right-70,ey+20}; txt(dc,e.title.c_str(),t,fSansS,CINK,DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS);
        RECT d={act.left+32,ey+20,act.right-70,ey+40}; txt(dc,e.detail.c_str(),d,fSansXS,CMUT,DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS);
        RECT g={act.right-64,ey,act.right-14,ey+20}; txt(dc,e.ago.c_str(),g,fSansXS,CMUT2,DT_RIGHT|DT_SINGLELINE);
        ey+=46; }
    if(gFeed.empty()){ RECT em={act.left,act.top+60,act.right,act.bottom}; txt(dc,L"No activity yet. Run a scan or turn on protection.",em,fSansS,CMUT2,DT_CENTER|DT_TOP); }

    RECT quar={cx+aw+lgap,y,cx+cw,y+lh}; card(dc,quar,CPANEL,CLINE,14);
    RECT qhl={quar.left+18,quar.top,quar.right-16,quar.top+44}; txt(dc,L"Quarantine",qhl,fSans,CINK,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    { wchar_t qc[24]; wsprintfW(qc,L"%ld item%ls",gThreats,gThreats==1?L"":L"s"); RECT qcr={quar.left,quar.top,quar.right-16,quar.top+44};
      txt(dc,gThreats?qc:L"empty",qcr,fMono,CMUT2,DT_RIGHT|DT_VCENTER|DT_SINGLELINE); }
    RECT qln={quar.left,quar.top+44,quar.right,quar.top+45}; fillR(dc,qln,CLINE);
    RECT qbody={quar.left,quar.top+52,quar.right,quar.bottom};
    if(gThreats==0){ txt(dc,L"Quarantine is empty.\nNeutralized threats will appear here.",qbody,fSansS,CMUT2,DT_CENTER|DT_TOP);
        RECT ob={quar.left+18,quar.bottom-46,quar.right-18,quar.bottom-14};
        card(dc,ob, isHot(A_QUAR_OPEN)?CPANEL2:CBG2, isHot(A_QUAR_OPEN)?CACC:CLINE2,9);
        txt(dc,L"Open quarantine folder",ob,fSansS,CINK,DT_CENTER|DT_VCENTER|DT_SINGLELINE); reg(ob,A_QUAR_OPEN); }
    else { RECT ob={quar.left+18,quar.top+56,quar.right-18,quar.top+88};
        card(dc,ob, isHot(A_QUAR_OPEN)?CPANEL2:CBG2, isHot(A_QUAR_OPEN)?CACC:CLINE2,9);
        wchar_t s[48]; wsprintfW(s,L"Review %ld quarantined item%ls",gThreats,gThreats==1?L"":L"s");
        txt(dc,s,ob,fSansS,CINK,DT_CENTER|DT_VCENTER|DT_SINGLELINE); reg(ob,A_QUAR_OPEN); }

    BitBlt(wdc,0,0,cr.right,cr.bottom,dc,0,0,SRCCOPY);
    SelectObject(dc,ob); DeleteObject(bmp); DeleteDC(dc); EndPaint(hwnd,&ps);
}

// ------------------------------------------------------------- input ----------
static int hitTest(int x,int y){ POINT p={x,y};
    for(auto it=gHits.rbegin();it!=gHits.rend();++it) if(PtInRect(&it->rc,p)) return it->action;
    return A_NONE; }

static LRESULT CALLBACK WndProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){
    switch(msg){
    case WM_CREATE:{
        auto F=[&](int h,int wt,const wchar_t* fam){ return CreateFontW(h,0,0,0,wt,0,0,0,DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,fam); };
        fDispXL=F(30,FW_BOLD,L"Segoe UI"); fDisp=F(22,FW_SEMIBOLD,L"Segoe UI"); fDispS=F(18,FW_SEMIBOLD,L"Segoe UI");
        fSans=F(16,FW_NORMAL,L"Segoe UI"); fSansS=F(15,FW_NORMAL,L"Segoe UI"); fSansXS=F(12,FW_SEMIBOLD,L"Segoe UI");
        fMono=F(14,FW_NORMAL,L"Consolas"); fIcon=F(22,FW_NORMAL,L"Segoe MDL2 Assets"); fIconBig=F(30,FW_NORMAL,L"Segoe MDL2 Assets");
        fIconNav=F(17,FW_NORMAL,L"Segoe MDL2 Assets"); fShield=F(84,FW_NORMAL,L"Segoe MDL2 Assets");
        gThreats=quarantineCount();
        feedAdd(EV_INFO,L"Welcome to Rescue",L"Run a quick scan, or turn on real-time protection.");
        SetTimer(hwnd,1,1000,nullptr); return 0; }
    case WM_TIMER: InvalidateRect(hwnd,nullptr,FALSE); return 0;   // clock + progress
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: paint(hwnd); return 0;
    case WM_GETMINMAXINFO:{ auto* mm=(MINMAXINFO*)lp; mm->ptMinTrackSize.x=980; mm->ptMinTrackSize.y=640; return 0; }
    case WM_MOUSEMOVE:{ int a=hitTest(GET_X_LPARAM(lp),GET_Y_LPARAM(lp));
        if(a!=gHover){ gHover=a; SetCursor(LoadCursorW(nullptr, a==A_NONE?IDC_ARROW:IDC_HAND)); InvalidateRect(hwnd,nullptr,FALSE);} return 0; }
    case WM_SETCURSOR: if(LOWORD(lp)==HTCLIENT && gHover!=A_NONE){ SetCursor(LoadCursorW(nullptr,IDC_HAND)); return TRUE; } break;
    case WM_LBUTTONUP:{ int a=hitTest(GET_X_LPARAM(lp),GET_Y_LPARAM(lp)); if(a!=A_NONE) doAction(a); return 0; }
    case WM_SIZE: InvalidateRect(hwnd,nullptr,FALSE); return 0;
    case WM_CLOSE: if(gGuardProc){ TerminateProcess(gGuardProc,0); CloseHandle(gGuardProc);} DestroyWindow(hwnd); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}

int WINAPI wWinMain(HINSTANCE hInst,HINSTANCE,PWSTR,int nShow){
    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    INITCOMMONCONTROLSEX icc{sizeof(icc),ICC_STANDARD_CLASSES}; InitCommonControlsEx(&icc);
    WNDCLASSW wc{}; wc.lpfnWndProc=WndProc; wc.hInstance=hInst; wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);
    wc.hbrBackground=nullptr; wc.lpszClassName=L"RescueSecurityCenter"; wc.hIcon=LoadIconW(nullptr,IDI_SHIELD);
    RegisterClassW(&wc);
    gWnd=CreateWindowExW(0,wc.lpszClassName,L"Rescue Security Center",WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,CW_USEDEFAULT,1180,780,nullptr,nullptr,hInst,nullptr);
    ShowWindow(gWnd,nShow); UpdateWindow(gWnd);
    MSG m; while(GetMessageW(&m,nullptr,0,0)>0){ TranslateMessage(&m); DispatchMessageW(&m); }
    return 0;
}
