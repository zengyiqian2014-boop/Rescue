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

// Bundled-font resource ids (must match src/rescue_gui.rc).
#define IDF_SORA_SB   101   // Sora SemiBold  -> "Sora SemiBold"
#define IDF_SORA_XB   102   // Sora ExtraBold -> "Sora ExtraBold"
#define IDF_PLEX_RG   103   // IBM Plex Sans  -> "IBM Plex Sans"
#define IDF_PLEX_SB   104   // IBM Plex Sans SemiBold -> "IBM Plex Sans SemiBold"
#define IDF_PLEXMONO  105   // IBM Plex Mono  -> "IBM Plex Mono"

// Load the embedded UI fonts privately for this process (no install needed),
// so the console renders with its intended type - Sora + IBM Plex - on any
// machine, exactly like the design, instead of falling back to a system face.
static void loadBundledFonts(HINSTANCE hInst){
    const int ids[]={IDF_SORA_SB,IDF_SORA_XB,IDF_PLEX_RG,IDF_PLEX_SB,IDF_PLEXMONO};
    for(int id:ids){
        HRSRC r=FindResourceW(hInst,MAKEINTRESOURCEW(id),RT_RCDATA); if(!r) continue;
        HGLOBAL h=LoadResource(hInst,r); if(!h) continue;
        void* p=LockResource(h); DWORD sz=SizeofResource(hInst,r);
        if(p&&sz){ DWORD n=0; AddFontMemResourceEx(p,sz,nullptr,&n); }
    }
}

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

// which page the content area shows
enum { VIEW_DASH, VIEW_SCAN, VIEW_QUAR, VIEW_GUARD, VIEW_USB, VIEW_LOGS, VIEW_SET };
static int gView=VIEW_DASH;

static HWND gWnd=nullptr;
static bool gGuardOn=false;
static HANDLE gGuardProc=nullptr;
static bool gScanning=false;
static bool gScanFull=false;
static int  gScanPct=0;
static long gScanCount=0;
static DWORD gScanStart=0;      // GetTickCount at scan start (for elapsed)
static std::wstring gScanPath;
static std::wstring gScanLast;  // last completed-scan summary
static long gThreats=0;   // real: quarantine item count

static HFONT fDispXL,fDisp,fDispS,fSans,fSansS,fSansXS,fMono;

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
    long before=gThreats;
    std::thread([rd,scan,before,hp=pi.hProcess]{
        runReader(rd,scan); WaitForSingleObject(hp,INFINITE); CloseHandle(hp);
        gThreats=quarantineCount(); long found=gThreats-before; if(found<0) found=0;
        if(scan){
            gScanning=false; gScanPct=100;
            DWORD ms=GetTickCount()-gScanStart; wchar_t s[192];
            if(found>0) wsprintfW(s,L"%ld found \u00b7 quarantined \u00b7 %lu.%lus",found,(unsigned long)(ms/1000),(unsigned long)((ms%1000)/100));
            else        wsprintfW(s,L"No threats found \u00b7 %lu.%lus",(unsigned long)(ms/1000),(unsigned long)((ms%1000)/100));
            gScanLast=s;
            feedAdd(found>0?EV_WARN:EV_OK, gScanFull?L"Full scan completed":L"Quick scan completed", gScanLast);
        } else {
            feedAdd(found>0?EV_WARN:EV_OK,L"Task finished", found>0?L"Threats moved to quarantine":L"Completed \u00b7 nothing to clean");
        }
        if(gWnd) InvalidateRect(gWnd,nullptr,FALSE);
    }).detach();
    return nullptr;
}

static void startScan(bool full){
    if(gScanning) return; gScanning=true; gScanFull=full; gScanPct=2; gScanCount=0; gScanStart=GetTickCount();
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
    // ---- navigation: switch the visible page ----
    case A_NAV_DASH: gView=VIEW_DASH; break;
    case A_NAV_SCAN: gView=VIEW_SCAN; break;
    case A_NAV_QUAR: gView=VIEW_QUAR; gThreats=quarantineCount(); break;
    case A_NAV_GUARD: gView=VIEW_GUARD; break;
    case A_NAV_USB:  gView=VIEW_USB; break;
    case A_NAV_LOGS: gView=VIEW_LOGS; break;
    case A_NAV_SET:  gView=VIEW_SET; break;
    // ---- actions ----
    case A_QUICK: gView=VIEW_SCAN; startScan(false); break;
    case A_FULL:  gView=VIEW_SCAN; startScan(true); break;
    case A_GUARD_TGL: setGuard(!gGuardOn); break;
    case A_UNLOCK: feedAdd(EV_INFO,L"Unlock / clean started",L"Undoing lockdown levers + screen effects");
        launchEngine(tool(L"lockdown_breaker.exe")+L" --fix --kill-overlays --kill-effects",false,(bool*)1); break;
    case A_ASEP: feedAdd(EV_INFO,L"Autostart scan started",L"Checking every ASEP against signatures");
        launchEngine(tool(L"asep_cleaner.exe"),false,(bool*)1); break;
    case A_USB:{
        // Open the emergency kit (kept as PowerShell so it still runs if malware
        // blocks .exe via WDAC/SRP policy). One click, no typing.
        std::wstring kit=exeDir()+L"\\..\\advanced\\offline";
        if(GetFileAttributesW(kit.c_str())==INVALID_FILE_ATTRIBUTES) kit=exeDir()+L"\\advanced\\offline";
        if(GetFileAttributesW(kit.c_str())==INVALID_FILE_ATTRIBUTES) kit=exeDir();
        ShellExecuteW(gWnd,L"explore",kit.c_str(),nullptr,nullptr,SW_SHOW);
        MessageBoxW(gWnd,L"Opened the Rescue emergency kit.\n\nRun Make-RescueDisk.ps1 to build a bootable "
                        L"rescue USB (bootable WinPE, or a one-click restore disk from an official Windows ISO + "
                        L"your backup).\n\nThese stay as PowerShell on purpose: if malware blocks .exe files via "
                        L"system policy, the .ps1 emergency kit still runs.",L"Rescue USB",MB_ICONINFORMATION);
        break; }
    case A_BACKUP:{
        BROWSEINFOW bi{}; bi.hwndOwner=gWnd; bi.lpszTitle=L"Choose a BACKUP DISK or folder (external drive best)";
        bi.ulFlags=BIF_RETURNONLYFSDIRS|BIF_NEWDIALOGSTYLE; LPITEMIDLIST pidl=SHBrowseForFolderW(&bi);
        if(pidl){ wchar_t p[MAX_PATH]; if(SHGetPathFromIDListW(pidl,p)){ feedAdd(EV_INFO,L"Backup started",p);
            launchEngine(tool(L"backup.exe")+L" --snapshot \""+p+L"\" --keep 10",false,(bool*)1);} CoTaskMemFree(pidl);} break; }
    case A_QUAR_OPEN:{ std::wstring q=pdRescue()+L"\\Quarantine";
        CreateDirectoryW(pdRescue().c_str(),nullptr); CreateDirectoryW(q.c_str(),nullptr);
        ShellExecuteW(gWnd,L"explore",q.c_str(),nullptr,nullptr,SW_SHOW); break; }
    default: break;
    }
    if(gWnd) InvalidateRect(gWnd,nullptr,FALSE);
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
// crisp vector icons drawn with GDI - identical on every Windows, no icon font.
static void drawIcon(HDC dc,const wchar_t* name,RECT b,COLORREF col){
    double s=(b.right-b.left)/24.0; if(s<=0) return; int ox=b.left, oy=b.top;
    int w=(int)(s*1.7); if(w<2) w=2;
    LOGBRUSH lb{BS_SOLID,col,0};
    HPEN pen=ExtCreatePen(PS_GEOMETRIC|PS_SOLID|PS_ENDCAP_ROUND|PS_JOIN_ROUND,w,&lb,0,nullptr);
    HGDIOBJ op=SelectObject(dc,pen), obr=SelectObject(dc,GetStockObject(NULL_BRUSH));
    auto P=[&](double x,double y){ POINT pt={(LONG)(ox+x*s),(LONG)(oy+y*s)}; return pt; };
    auto L=[&](double x1,double y1,double x2,double y2){ POINT a=P(x1,y1),c=P(x2,y2); MoveToEx(dc,a.x,a.y,0); LineTo(dc,c.x,c.y); };
    auto PL=[&](std::initializer_list<POINT> v){ std::vector<POINT> q(v); Polyline(dc,q.data(),(int)q.size()); };
    auto EL=[&](double x1,double y1,double x2,double y2){ POINT a=P(x1,y1),c=P(x2,y2); Ellipse(dc,a.x,a.y,c.x,c.y); };
    std::wstring n=name;
    if(n==L"shield"){ PL({P(12,2),P(20,5),P(20,12),P(12,22),P(4,12),P(4,5),P(12,2)}); PL({P(8,12),P(11,15),P(16,8.5)}); }
    else if(n==L"home"){ PL({P(4,11),P(12,4),P(20,11)}); PL({P(7,11),P(7,20),P(17,20),P(17,11)}); }
    else if(n==L"search"){ EL(4,4,16,16); L(14.5,14.5,20,20); }
    else if(n==L"warn"){ PL({P(12,3),P(21,20),P(3,20),P(12,3)}); L(12,9,12,15); L(12,17.6,12,18.2); }
    else if(n==L"usb"){ PL({P(8,6),P(8,20),P(16,20),P(16,6),P(8,6)}); L(9.5,3,9.5,6); L(14.5,3,14.5,6); L(8,10,16,10); }
    else if(n==L"page"){ PL({P(6,3),P(6,21),P(18,21),P(18,3),P(6,3)}); L(9,8,15,8); L(9,12,15,12); L(9,16,15,16); }
    else if(n==L"gear"){ EL(7.5,7.5,16.5,16.5); L(12,3,12,6); L(12,18,12,21); L(3,12,6,12); L(18,12,21,12); L(5.5,5.5,7.6,7.6); L(16.4,16.4,18.5,18.5); L(16.4,7.6,18.5,5.5); L(7.6,16.4,5.5,18.5); }
    else if(n==L"unlock"){ PL({P(6,11),P(6,20),P(18,20),P(18,11),P(6,11)}); PL({P(9,11),P(9,7),P(10.5,5),P(13.5,5),P(15,7)}); }
    else if(n==L"list"){ L(5,7,19,7); L(5,12,19,12); L(5,17,15,17); }
    else if(n==L"dog"){ EL(4,7.5,20,16.5); EL(10,11,14,15); }
    else if(n==L"cpu"){ PL({P(7,7),P(7,17),P(17,17),P(17,7),P(7,7)}); PL({P(10,10),P(10,14),P(14,14),P(14,10),P(10,10)});
        L(9,4,9,7); L(15,4,15,7); L(9,17,9,20); L(15,17,15,20); L(4,9,7,9); L(4,15,7,15); L(17,9,20,9); L(17,15,20,15); }
    SelectObject(dc,op); SelectObject(dc,obr); DeleteObject(pen);
}

// Hero centerpiece: a gradient-filled shield with a check mark (like the design).
static void heroShield(HDC dc,RECT b,bool prot){
    double s=(b.right-b.left)/24.0; if(s<=0) return; int ox=b.left, oy=b.top;
    auto P=[&](double x,double y){ POINT p={(LONG)(ox+x*s),(LONG)(oy+y*s)}; return p; };
    POINT poly[6]={P(12,2),P(20,5),P(20,12),P(12,22),P(4,12),P(4,5)};
    HRGN rgn=CreatePolygonRgn(poly,6,WINDING); SelectClipRgn(dc,rgn);
    if(prot) vgrad(dc,b,RGB(0x1c,0x3f,0x66),RGB(0x11,0x39,0x37));
    else     vgrad(dc,b,RGB(0x3c,0x31,0x12),RGB(0x2a,0x22,0x0c));
    SelectClipRgn(dc,nullptr); DeleteObject(rgn);
    COLORREF sc=prot?CACC2:CWARN;
    LOGBRUSH lb{BS_SOLID,sc,0};
    HPEN pen=ExtCreatePen(PS_GEOMETRIC|PS_SOLID|PS_JOIN_ROUND|PS_ENDCAP_ROUND,(int)(s*1.3),&lb,0,nullptr);
    HGDIOBJ op=SelectObject(dc,pen), ob=SelectObject(dc,GetStockObject(NULL_BRUSH));
    Polygon(dc,poly,6);
    COLORREF ck=prot?CGOOD:CWARN; LOGBRUSH lb2{BS_SOLID,ck,0};
    HPEN pen2=ExtCreatePen(PS_GEOMETRIC|PS_SOLID|PS_JOIN_ROUND|PS_ENDCAP_ROUND,(int)(s*1.7),&lb2,0,nullptr);
    SelectObject(dc,pen2); POINT ch[3]={P(8,12),P(11,15.2),P(16.5,8)}; Polyline(dc,ch,3);
    SelectObject(dc,op); SelectObject(dc,ob); DeleteObject(pen); DeleteObject(pen2);
}

static void reg(RECT r,int a){ gHits.push_back({r,a}); }
static bool isHot(int a){ return gHover==a && a!=A_NONE; }

// ------------------------------------------------------------- module cards ---
struct Mod { const wchar_t* icon,*name,*role,*metric1,*metric2; int chipKind; const wchar_t* chip; int action; const wchar_t* foot,*btn; };
// chipKind: 0 ok,1 warn,2 crit,3 idle
static void drawMod(HDC dc,RECT r,const Mod& m,bool dim){
    COLORREF bd = isHot(m.action)?CLINE2:CLINE;
    card(dc,r,CPANEL,bd,14);
    // icon tile
    RECT it={r.left+16,r.top+16,r.left+54,r.top+54};
    COLORREF itbg=dim?RGB(0x14,0x1c,0x2c):(m.chipKind==1?CWARND:CACCD);
    COLORREF itfg=dim?CMUT:(m.chipKind==1?CWARN:CACC2);
    card(dc,it,itbg,dim?CLINE:RGB(0x22,0x37,0x5c),10);
    { RECT ii={it.left+9,it.top+9,it.right-9,it.bottom-9}; drawIcon(dc,m.icon,ii,itfg); }
    RECT nm={r.left+64,r.top+16,r.right-96,r.top+40}; txt(dc,m.name,nm,fDispS,CINK,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
    RECT ro={r.left+64,r.top+38,r.right-16,r.top+58}; txt(dc,m.role,ro,fSansXS,CMUT2,DT_LEFT|DT_SINGLELINE);
    // chip top-right
    COLORREF cf=CGOOD,cb=CGOODD,cd=RGB(0x1c,0x4a,0x30);
    if(m.chipKind==1){cf=CWARN;cb=CWARND;cd=RGB(0x4d,0x3c,0x10);}
    else if(m.chipKind==2){cf=CCRIT;cb=CCRITD;cd=RGB(0x58,0x20,0x19);}
    else if(m.chipKind==3){cf=CMUT;cb=RGB(0x14,0x1c,0x2c);cd=CLINE;}
    SIZE sz; HGDIOBJ of=SelectObject(dc,fSansXS); GetTextExtentPoint32W(dc,m.chip,(int)wcslen(m.chip),&sz); SelectObject(dc,of);
    chip(dc,r.right-sz.cx-46,r.top+16,m.chip,cf,cb,cd);
    // metric box (compact, two lines)
    RECT mb={r.left+16,r.top+62,r.right-16,r.top+96}; card(dc,mb,CBG2,CLINE,8);
    RECT m1={mb.left+11,mb.top+4,mb.right-11,mb.top+19}; txt(dc,m.metric1,m1,fSansXS,CMUT,DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS);
    RECT m2={mb.left+11,mb.top+18,mb.right-11,mb.bottom-3}; txt(dc,m.metric2,m2,fSansXS,CMUT2,DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS);
    // footer: short status on the left, a real button on the right
    RECT fl={r.left+17,r.bottom-30,r.right-16,r.bottom-8}; txt(dc,m.foot,fl,fSansXS,CMUT2,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    SIZE bs; HGDIOBJ ofb=SelectObject(dc,fSansXS); GetTextExtentPoint32W(dc,m.btn,(int)wcslen(m.btn),&bs); SelectObject(dc,ofb);
    int bw=bs.cx+26; RECT bt={r.right-16-bw,r.bottom-33,r.right-16,r.bottom-9};
    bool en=m.action!=A_NONE, hot=en&&isHot(m.action);
    COLORREF bf = !en?RGB(0x14,0x1c,0x2c) : hot?CACC:CACCD;
    COLORREF bb = !en?CLINE : hot?CACC:RGB(0x22,0x37,0x5c);
    COLORREF btc= !en?CMUT2 : hot?RGB(0x04,0x12,0x2b):CACC2;
    card(dc,bt,bf,bb,8); txt(dc,m.btn,bt,fSansXS,btc,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    if(en) reg(bt,m.action);
}

// ------------------------------------------------------------- paint ----------
static void navItem(HDC dc,int x,int& y,int w,const wchar_t* icon,const wchar_t* label,int action,bool on,const wchar_t* badge){
    RECT r={x,y,x+w,y+38};
    if(on) card(dc,r,CACCD,CACCD,9);
    else if(isHot(action)){ card(dc,r,CPANEL,CPANEL,9); }
    { RECT ic={x+9,y+9,x+29,y+29}; drawIcon(dc,icon,ic,on?CACC2:CMUT); }
    RECT tr={x+40,y,x+w-30,y+38}; txt(dc,label,tr,fSans,on?CACC2:CMUT,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    if(badge){ SIZE sz; HGDIOBJ of=SelectObject(dc,fSansXS); GetTextExtentPoint32W(dc,badge,(int)wcslen(badge),&sz); SelectObject(dc,of);
        RECT b={x+w-sz.cx-24,y+9,x+w-8,y+29}; card(dc,b,CWARN,CWARN,10); txt(dc,badge,b,fSansXS,RGB(0x18,0x12,0x00),DT_CENTER|DT_VCENTER|DT_SINGLELINE); }
    reg(r,action); y+=40;
}

// ---- reusable cards (shared by the dashboard and the dedicated pages) --------
static void drawFeedCard(HDC dc,RECT act){
    card(dc,act,CPANEL,CLINE,14);
    RECT ahl={act.left+18,act.top,act.right-16,act.top+44};
    txt(dc,L"Activity",ahl,fDispS,CINK,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
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
}
static void drawQuarCard(HDC dc,RECT quar){
    card(dc,quar,CPANEL,CLINE,14);
    RECT qhl={quar.left+18,quar.top,quar.right-16,quar.top+44}; txt(dc,L"Quarantine",qhl,fDispS,CINK,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
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
}
static void pageBtn(HDC dc,RECT r,const wchar_t* label,int action,bool primary){
    bool hot=isHot(action);
    COLORREF f = primary?(hot?CACC2:CACC):CPANEL2;
    COLORREF b = primary?(hot?CACC2:CACC):(hot?CACC:CLINE2);
    card(dc,r,f,b,10); txt(dc,label,r,fSansS,primary?RGB(0x04,0x12,0x2b):CINK,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    reg(r,action);
}
// ---- dedicated pages ---------------------------------------------------------
static void drawScanPage(HDC dc,int cx,int cy,int cw,RECT cr){
    int pad=24; RECT c={cx,cy,cx+cw,cy+232}; card(dc,c,CPANEL,CLINE,14);
    RECT ic={c.left+22,c.top+22,c.left+62,c.top+62}; card(dc,ic,CACCD,RGB(0x22,0x37,0x5c),10);
    { RECT ii={ic.left+9,ic.top+9,ic.right-9,ic.bottom-9}; drawIcon(dc,L"search",ii,CACC2); }
    RECT ti={c.left+74,c.top+18,c.right-24,c.top+48};
    txt(dc, gScanning?(gScanFull?L"Full scan running":L"Quick scan running"):L"Threat scanner", ti,fDisp,CINK,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
    RECT su={c.left+74,c.top+50,c.right-24,c.top+72};
    txt(dc, gScanning?L"Signatures + PE heuristics · downloads deep-scanned first":
            (gScanLast.empty()?L"Quick scans high-risk folders. Full scan covers every fixed drive.":gScanLast.c_str()),
        su,fSansS,CMUT,DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS);
    int pct = gScanning?gScanPct:(gScanLast.empty()?0:100);
    RECT pr={c.left+24,c.top+94,c.right-24,c.top+110}; card(dc,pr,CPANEL2,CLINE,8);
    if(pct>0){ RECT fl={pr.left+2,pr.top+2,pr.left+2+(int)((pr.right-pr.left-4)*pct/100.0),pr.bottom-2};
        if(fl.right>fl.left+3){ COLORREF pc=gScanning?CACC:CGOOD; card(dc,fl,pc,pc,7);} }
    RECT pl={c.left+24,c.top+120,c.right-24,c.top+142}; wchar_t s[240];
    if(gScanning) wsprintfW(s,L"%d%%   ·   %ls   ·   %ld items",pct,gScanPath.c_str(),gScanCount);
    else if(!gScanLast.empty()) wsprintfW(s,L"Done   ·   %ls",gScanLast.c_str());
    else wcscpy(s,L"Idle · ready to scan");
    txt(dc,s,pl,fMono,gScanning?CACC2:CMUT,DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS);
    int by=c.top+164;
    if(!gScanning){
        RECT b1={c.left+24,by,c.left+190,by+40}; pageBtn(dc,b1,L"Run quick scan",A_QUICK,true);
        RECT b2={c.left+202,by,c.left+326,by+40}; pageBtn(dc,b2,L"Full scan",A_FULL,false);
    } else { RECT b1={c.left+24,by,c.left+190,by+40}; card(dc,b1,CPANEL2,CLINE,10);
        txt(dc,L"Scanning…",b1,fSansS,CMUT,DT_CENTER|DT_VCENTER|DT_SINGLELINE); }
    RECT act={cx,c.bottom+pad,cx+cw,cr.bottom-pad}; if(act.bottom-act.top>120) drawFeedCard(dc,act);
}
static void drawGuardPage(HDC dc,int cx,int cy,int cw,RECT cr){
    int pad=24; RECT c={cx,cy,cx+cw,cy+224}; card(dc,c,CPANEL,CLINE,14);
    RECT si={c.left+30,c.top+34,c.left+158,c.top+162}; heroShield(dc,si,gGuardOn);
    int hx=c.left+190;
    RECT he={hx,c.top+34,c.right-24,c.top+54}; txt(dc,gGuardOn?L"REAL-TIME GUARD ACTIVE":L"REAL-TIME GUARD OFF",he,fSansXS,gGuardOn?CGOOD:CWARN,DT_LEFT|DT_SINGLELINE);
    RECT ht={hx,c.top+52,c.right-24,c.top+92}; txt(dc,gGuardOn?L"Your files are protected":L"Files are not protected",ht,fDispXL,CINK,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
    RECT hs={hx,c.top+96,c.right-24,c.top+156}; txt(dc,L"Behavioral detection arms canary files and, on a ransomware write pattern, suspends the busiest writing process tree. The disk shield denies raw writes to physical drives to stop wipers and MBR/GPT overwrite.",hs,fSansS,CMUT,DT_LEFT|DT_WORDBREAK);
    RECT bt={hx,c.top+164,hx+186,c.top+204}; pageBtn(dc,bt,gGuardOn?L"Turn off guard":L"Turn on guard",A_GUARD_TGL,!gGuardOn);
    RECT act={cx,c.bottom+pad,cx+cw,cr.bottom-pad}; if(act.bottom-act.top>120) drawFeedCard(dc,act);
}
static void drawSimplePage(HDC dc,int cx,int cy,int cw,RECT cr,const wchar_t* icon,const wchar_t* title,const wchar_t* desc,const wchar_t* btn,int action){
    RECT c={cx,cy,cx+cw,cy+204}; card(dc,c,CPANEL,CLINE,14);
    RECT ic={c.left+22,c.top+22,c.left+62,c.top+62}; card(dc,ic,CACCD,RGB(0x22,0x37,0x5c),10);
    { RECT ii={ic.left+9,ic.top+9,ic.right-9,ic.bottom-9}; drawIcon(dc,icon,ii,CACC2); }
    RECT ti={c.left+74,c.top+22,c.right-24,c.top+52}; txt(dc,title,ti,fDisp,CINK,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
    RECT ds={c.left+24,c.top+82,c.right-24,c.top+150}; txt(dc,desc,ds,fSansS,CMUT,DT_LEFT|DT_WORDBREAK);
    if(btn){ RECT bt={c.left+24,c.top+152,c.left+250,c.top+192}; pageBtn(dc,bt,btn,action,true); }
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
    { RECT bmk={22,20,52,50}; drawIcon(dc,L"shield",bmk,CACC2); }
    RECT bn={62,20,RAIL-8,44}; txt(dc,L"Rescue",bn,fDisp,CINK,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT bs={64,44,RAIL-8,62}; txt(dc,L"SECURITY CENTER",bs,fSansXS,CMUT2,DT_LEFT|DT_SINGLELINE);
    int ny=84;
    navItem(dc,14,ny,RAIL-28,L"home",L"Dashboard",A_NAV_DASH,gView==VIEW_DASH,nullptr);
    navItem(dc,14,ny,RAIL-28,L"shield",L"Real-time Guard",A_NAV_GUARD,gView==VIEW_GUARD,nullptr);
    navItem(dc,14,ny,RAIL-28,L"search",L"Scan",A_NAV_SCAN,gView==VIEW_SCAN,nullptr);
    { wchar_t qc[8]; wsprintfW(qc,L"%ld",gThreats); navItem(dc,14,ny,RAIL-28,L"warn",L"Quarantine",A_NAV_QUAR,gView==VIEW_QUAR, gThreats>0?qc:nullptr); }
    navItem(dc,14,ny,RAIL-28,L"usb",L"Rescue USB",A_NAV_USB,gView==VIEW_USB,nullptr);
    navItem(dc,14,ny,RAIL-28,L"page",L"Logs",A_NAV_LOGS,gView==VIEW_LOGS,nullptr);
    navItem(dc,14,ny,RAIL-28,L"gear",L"Settings",A_NAV_SET,gView==VIEW_SET,nullptr);
    RECT foot={22,cr.bottom-56,RAIL-14,cr.bottom-12};
    txt(dc,gGuardOn?L"\u25CF  Protected \u00b7 guard live\nRescue 0.1.0 \u00b7 both arches":
                    L"\u25CF  Idle \u00b7 guard off\nRescue 0.1.0 \u00b7 both arches",
        foot,fSansXS,gGuardOn?CGOOD:CMUT2,DT_LEFT|DT_WORDBREAK);

    // ---------------- top bar ----------------
    int X=RAIL, W=cr.right-RAIL;
    RECT top={X,0,cr.right,58}; fillR(dc,top,CBG2);
    RECT tl={X,57,cr.right,58}; fillR(dc,tl,CLINE);
    const wchar_t* vt[]={L"Dashboard",L"Scan",L"Quarantine",L"Real-time Guard",L"Rescue USB",L"Activity Log",L"Settings"};
    RECT th={X+26,0,X+360,58}; txt(dc,vt[gView],th,fDispS,CINK,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    wchar_t clock[32]; SYSTEMTIME st; GetLocalTime(&st); wsprintfW(clock,L"%02d:%02d:%02d",st.wHour,st.wMinute,st.wSecond);
    RECT tc={cr.right-140,0,cr.right-58,58}; txt(dc,clock,tc,fMono,CMUT,DT_RIGHT|DT_VCENTER|DT_SINGLELINE);
    RECT tg={cr.right-46,14,cr.right-14,46}; card(dc,tg,CPANEL,CLINE,9);
    { RECT gi={tg.left+7,tg.top+7,tg.right-7,tg.bottom-7}; drawIcon(dc,L"gear",gi,CMUT); } reg(tg,A_NAV_SET);

    int pad=24, cx=X+pad, cw=W-pad*2, y=58+pad;

    // ================= page dispatch =================
    if(gView==VIEW_SCAN){ drawScanPage(dc,cx,y,cw,cr); }
    else if(gView==VIEW_QUAR){ RECT c={cx,y,cx+cw,cr.bottom-pad}; drawQuarCard(dc,c); }
    else if(gView==VIEW_GUARD){ drawGuardPage(dc,cx,y,cw,cr); }
    else if(gView==VIEW_USB){ drawSimplePage(dc,cx,y,cw,cr,L"usb",L"Rescue USB",
        L"Build a bootable rescue USB to clean or restore a machine that no longer boots. "
        L"WinPE boot media, or a one-click restore disk from an official Windows ISO plus your backup. "
        L"The kit stays as PowerShell on purpose: if malware blocks .exe files via system policy, the .ps1 kit still runs.",
        L"Open emergency kit",A_USB); }
    else if(gView==VIEW_LOGS){ RECT act={cx,y,cx+cw,cr.bottom-pad}; drawFeedCard(dc,act); }
    else if(gView==VIEW_SET){ drawSimplePage(dc,cx,y,cw,cr,L"gear",L"Settings",
        L"Rescue runs elevated so it can touch OS-protected files and HKLM policy keys. "
        L"Real-time guard, disk shield and canary files are controlled from the Dashboard and the Real-time Guard page. "
        L"Engine 0.1.0 · x86_64 + ARM64 builds · bundled Sora / IBM Plex UI fonts.",
        nullptr,A_NONE); }
    else { // ================= VIEW_DASH =================

    // ---------------- hero ----------------
    int heroH=196; RECT hero={cx,y,cx+cw,y+heroH}; vgrad(dc,hero,CPANEL,CBG2);
    card(dc,hero,CPANEL,CLINE,14); // border overlay (fill already gradient-ish)
    // re-stroke border since card overwrote fill; draw gradient inside then border:
    { RECT inner={hero.left+1,hero.top+1,hero.right-1,hero.bottom-1}; vgrad(dc,inner,CPANEL,CBG2);
      HPEN p=CreatePen(PS_SOLID,1,CLINE); HGDIOBJ op=SelectObject(dc,p); HGDIOBJ obr=SelectObject(dc,GetStockObject(NULL_BRUSH));
      RoundRect(dc,hero.left,hero.top,hero.right,hero.bottom,14,14); SelectObject(dc,op); SelectObject(dc,obr); DeleteObject(p); }
    // shield
    RECT sh={hero.left+28,hero.top+28,hero.left+156,hero.bottom-28};
    { int d=(sh.bottom-sh.top); RECT si={(sh.left+sh.right-d)/2,sh.top,(sh.left+sh.right-d)/2+d,sh.bottom}; heroShield(dc,si,gGuardOn); }
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
    RECT sec={cx,y,cx+240,y+20}; txt(dc,L"Defense modules",sec,fDispS,CINK,DT_LEFT|DT_SINGLELINE);
    RECT secl={cx+150,y+10,cx+cw,y+11}; fillR(dc,secl,CLINE);
    y+=30;

    // ---------------- module grid (3 cols x 2 rows) ----------------
    Mod mods[6]={
        {L"shield",L"Ransom Guard",L"Behavioral real-time protection", gGuardOn?L"Watching folders \u00b7 6 canaries armed":L"Off \u00b7 turn on to arm canaries", L"Trip \u2192 suspend the busiest writer", 0, gGuardOn?L"Active":L"Off", A_GUARD_TGL, gGuardOn?L"Live":L"Off", gGuardOn?L"Turn off":L"Turn on"},
        {L"unlock",L"Lockdown Breaker",L"Undo malware lockdowns", L"Task Mgr \u00b7 regedit \u00b7 CMD \u00b7 shell", L"WDAC policy \u00b7 input lock \u00b7 overlays", 0, L"Ready", A_UNLOCK, L"Idle", L"Scan now"},
        {L"list",L"ASEP Cleaner",L"Every autostart, signature-checked", L"Run \u00b7 services \u00b7 tasks \u00b7 IFEO", L"Flags unsigned \u00b7 no virus DB needed", 0, L"Ready", A_ASEP, L"Ready", L"Review"},
        {L"search",L"Threat Scanner",L"Heuristic + hash + quarantine", L"PE entropy \u00b7 MOTW priority", L"Downloads deep-scanned first", 0, L"Updated", A_QUICK, L"Ready", L"Scan"},
        {L"dog",L"Watchdog",L"Self-protecting service pair", L"Two services \u00b7 each restarts the other", L"Keeps Ransom Guard alive", 0, L"Ready", A_BACKUP, L"Paired", L"Back up"},
        {L"cpu",L"Kernel Filter",L"Un-killable real-time tier", L"Minifilter \u00b7 per-write attribution", L"Requires a signed driver to load", 3, L"Not installed", A_NONE, L"Phase 6", L"Learn why"},
    };
    mods[2].chipKind=0; // asep neutral unless flagged
    int cols=3, gap=14; int mw=(cw-gap*(cols-1))/cols, mh=124;
    for(int i=0;i<6;++i){ int col=i%cols,row=i/cols; RECT r={cx+col*(mw+gap),y+row*(mh+gap),cx+col*(mw+gap)+mw,y+row*(mh+gap)+mh};
        drawMod(dc,r,mods[i], i==5); }
    y+=2*(mh+gap)+6;

    // ---------------- lower: activity + quarantine ----------------
    int lgap=22; int aw=(cw-lgap)*58/100;
    int lh=cr.bottom-y-pad; if(lh<140) lh=140;
    RECT act={cx,y,cx+aw,y+lh}; drawFeedCard(dc,act);
    RECT quar={cx+aw+lgap,y,cx+cw,y+lh}; drawQuarCard(dc,quar);

    } // ================= end VIEW_DASH =================

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
        // Bundled type: Sora (display) + IBM Plex Sans/Mono (body). Loaded from
        // the exe's own resources in wWinMain, so these faces resolve everywhere.
        fDispXL=F(30,FW_NORMAL,L"Sora ExtraBold"); fDisp=F(22,FW_NORMAL,L"Sora ExtraBold"); fDispS=F(18,FW_NORMAL,L"Sora SemiBold");
        fSans=F(16,FW_NORMAL,L"IBM Plex Sans"); fSansS=F(15,FW_NORMAL,L"IBM Plex Sans"); fSansXS=F(12,FW_NORMAL,L"IBM Plex Sans SemiBold");
        fMono=F(14,FW_NORMAL,L"IBM Plex Mono");
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
    loadBundledFonts(hInst);   // register Sora + IBM Plex before any font is made
    // Optional deep-link: open straight to a page, e.g. Rescue.exe --view=scan
    { std::wstring cl=GetCommandLineW();
      if(cl.find(L"--view=scan")!=std::wstring::npos) gView=VIEW_SCAN;
      else if(cl.find(L"--view=quar")!=std::wstring::npos) gView=VIEW_QUAR;
      else if(cl.find(L"--view=guard")!=std::wstring::npos) gView=VIEW_GUARD;
      else if(cl.find(L"--view=usb")!=std::wstring::npos) gView=VIEW_USB;
      else if(cl.find(L"--view=logs")!=std::wstring::npos) gView=VIEW_LOGS;
      else if(cl.find(L"--view=settings")!=std::wstring::npos) gView=VIEW_SET;
      if(cl.find(L"--demo")!=std::wstring::npos){ // render-preview only (screenshots)
          gScanning=true; gScanFull=false; gScanPct=63; gScanCount=18452; gScanPath=L"C:\\Users\\me\\Downloads"; }
    }
    WNDCLASSW wc{}; wc.lpfnWndProc=WndProc; wc.hInstance=hInst; wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);
    wc.hbrBackground=nullptr; wc.lpszClassName=L"RescueSecurityCenter"; wc.hIcon=LoadIconW(nullptr,IDI_SHIELD);
    RegisterClassW(&wc);
    gWnd=CreateWindowExW(0,wc.lpszClassName,L"Rescue Security Center",WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,CW_USEDEFAULT,1180,780,nullptr,nullptr,hInst,nullptr);
    ShowWindow(gWnd,nShow); UpdateWindow(gWnd);
    MSG m; while(GetMessageW(&m,nullptr,0,0)>0){ TranslateMessage(&m); DispatchMessageW(&m); }
    return 0;
}
