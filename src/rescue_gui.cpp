// rescue_gui.cpp - Rescue: the one window a user touches. A fully custom-drawn,
// modern flat UI (no dated gray Win32 chrome): gradient header, rounded status
// card that turns green when protected, rounded action cards with icon glyphs
// and hover lift, and a framed activity log. Double-buffered so it never
// flickers. Still one dependency-free, statically linked .exe that cross-compiles
// with MinGW for x86_64 and ARM64, and it drives the same engines under the hood.
#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <shlobj.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <thread>

#pragma GCC diagnostic ignored "-Wunused-parameter"

// ------------------------------------------------------------- palette --------
static const COLORREF C_BG        = RGB(0xEE, 0xF1, 0xF6);
static const COLORREF C_HEAD_TOP  = RGB(0x1B, 0x2A, 0x4E);
static const COLORREF C_HEAD_BOT  = RGB(0x2B, 0x54, 0x9C);
static const COLORREF C_CARD      = RGB(0xFF, 0xFF, 0xFF);
static const COLORREF C_CARD_HOT  = RGB(0xF5, 0xF8, 0xFF);
static const COLORREF C_BORDER    = RGB(0xD8, 0xDE, 0xE8);
static const COLORREF C_TEXT      = RGB(0x1E, 0x27, 0x33);
static const COLORREF C_MUTED     = RGB(0x6B, 0x76, 0x88);
static const COLORREF C_ACCENT    = RGB(0x2D, 0x6C, 0xDF);
static const COLORREF C_GREEN     = RGB(0x1E, 0x93, 0x51);
static const COLORREF C_GREEN_D   = RGB(0x17, 0x7A, 0x43);
static const COLORREF C_RED       = RGB(0xC4, 0x57, 0x2B);
static const COLORREF C_RED_D     = RGB(0xA8, 0x49, 0x22);
static const COLORREF C_WHITE     = RGB(0xFF, 0xFF, 0xFF);

// ------------------------------------------------------------- ids ------------
enum {
    ID_QUICKSCAN = 1001, ID_FULLSCAN, ID_UNLOCK, ID_BACKUP, ID_QUARANTINE,
    ID_PROTECT, ID_LOG
};
#define WM_APP_APPEND (WM_APP + 1)
#define WM_APP_BUSY   (WM_APP + 2)

// A card button model (owner-drawn). MDL2 icon glyph + title + subtitle.
struct Card { int id; const wchar_t* icon; const wchar_t* title; const wchar_t* sub; bool hot; bool down; };
static Card gCards[] = {
    { ID_QUICKSCAN,  L"\uE721", L"Quick Scan",     L"Downloads, Temp, startup", false, false },
    { ID_FULLSCAN,   L"\uE896", L"Full Scan",      L"Every drive, deep check",  false, false },
    { ID_UNLOCK,     L"\uE785", L"Unlock / Clean", L"Undo a malware lockdown",  false, false },
    { ID_BACKUP,     L"\uE78C", L"Back Up Files",  L"Time Machine snapshot",    false, false },
    { ID_QUARANTINE, L"\uE7BA", L"Quarantine",     L"Review what was isolated", false, false },
};
static Card gProtect = { ID_PROTECT, L"\uE83D", L"", L"", false, false };

static HWND gLog=nullptr, gMain=nullptr;
static HWND gCardWnd[5]={0}, gProtectWnd=nullptr;
static HANDLE gGuardProc=nullptr;
static bool  gBusy=false;
static HFONT gFTitle,gFSub,gFCard,gFCardSub,gFIcon,gFIconBig,gFStatus,gFStatusSub,gFMono;

// ------------------------------------------------------------- helpers --------
static std::wstring exeDir() {
    wchar_t b[MAX_PATH*2]; GetModuleFileNameW(nullptr,b,MAX_PATH*2);
    std::wstring p=b; size_t s=p.find_last_of(L"\\/");
    return s==std::wstring::npos?L".":p.substr(0,s);
}
static std::wstring tool(const wchar_t* n){ return L"\""+exeDir()+L"\\"+n+L"\""; }

static Card* cardById(int id){
    if(id==ID_PROTECT) return &gProtect;
    for(auto& c:gCards) if(c.id==id) return &c;
    return nullptr;
}

static void logAtEnd(const wchar_t* t){
    int len=GetWindowTextLengthW(gLog);
    SendMessageW(gLog,EM_SETSEL,len,len);
    SendMessageW(gLog,EM_REPLACESEL,FALSE,(LPARAM)t);
}
static void appendLog(HWND h,const wchar_t* t){
    size_t n=wcslen(t); wchar_t* c=(wchar_t*)malloc((n+1)*sizeof(wchar_t));
    if(!c) return; memcpy(c,t,(n+1)*sizeof(wchar_t));
    PostMessageW(h,WM_APP_APPEND,(WPARAM)c,0);
}

// ---- engine runner (redirected stdout streamed into the log) ----------------
static void runReader(HWND h, HANDLE rd){
    char buf[4096]; DWORD got=0;
    while(ReadFile(rd,buf,sizeof(buf)-1,&got,nullptr)&&got){
        buf[got]=0;
        int wn=MultiByteToWideChar(CP_ACP,0,buf,(int)got,nullptr,0);
        std::wstring w(wn,0); MultiByteToWideChar(CP_ACP,0,buf,(int)got,w.data(),wn);
        appendLog(h,w.c_str());
    }
    CloseHandle(rd);
}
static HANDLE launchEngine(HWND h,const std::wstring& cmdline,bool fg){
    SECURITY_ATTRIBUTES sa{}; sa.nLength=sizeof(sa); sa.bInheritHandle=TRUE;
    HANDLE rd=nullptr,wr=nullptr;
    if(!CreatePipe(&rd,&wr,&sa,0)) return nullptr;
    SetHandleInformation(rd,HANDLE_FLAG_INHERIT,0);
    STARTUPINFOW si{}; si.cb=sizeof(si);
    si.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    si.hStdOutput=wr; si.hStdError=wr; si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
    std::wstring cmd=cmdline; std::vector<wchar_t> m(cmd.begin(),cmd.end()); m.push_back(0);
    PROCESS_INFORMATION pi{};
    BOOL ok=CreateProcessW(nullptr,m.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW,
                           nullptr,exeDir().c_str(),&si,&pi);
    CloseHandle(wr);
    if(!ok){ CloseHandle(rd); appendLog(h,L"\r\n[!] could not start the engine.\r\n"); return nullptr; }
    CloseHandle(pi.hThread);
    if(fg){
        SendMessageW(h,WM_APP_BUSY,1,0);
        std::thread([h,rd,hp=pi.hProcess]{ runReader(h,rd); WaitForSingleObject(hp,INFINITE);
            CloseHandle(hp); SendMessageW(h,WM_APP_BUSY,0,0); appendLog(h,L"\r\n---- done ----\r\n"); }).detach();
        return nullptr;
    }
    std::thread([h,rd]{ runReader(h,rd); }).detach();
    return pi.hProcess;
}

static void refreshProtect(){
    bool p=gGuardProc!=nullptr;
    InvalidateRect(gProtectWnd,nullptr,TRUE);
    InvalidateRect(gMain,nullptr,FALSE);
    (void)p;
}
static void setProtection(HWND h,bool on){
    if(on&&!gGuardProc){
        appendLog(h,L"\r\n=== Real-time protection ON ===\r\n");
        gGuardProc=launchEngine(h,tool(L"ransom_guard.exe")+L" --shield",false);
    } else if(!on&&gGuardProc){
        TerminateProcess(gGuardProc,0); CloseHandle(gGuardProc); gGuardProc=nullptr;
        appendLog(h,L"\r\n=== Real-time protection OFF ===\r\n");
    }
    refreshProtect();
}

static void onCommand(HWND h,int id){
    if(gBusy&&id!=ID_PROTECT&&id!=ID_QUARANTINE){ appendLog(h,L"\r\n[busy - let the current task finish]\r\n"); return; }
    switch(id){
    case ID_QUICKSCAN: appendLog(h,L"\r\n=== Quick scan ===\r\n"); launchEngine(h,tool(L"scanner.exe"),true); break;
    case ID_FULLSCAN:  appendLog(h,L"\r\n=== Full scan ===\r\n");  launchEngine(h,tool(L"scanner.exe")+L" --full",true); break;
    case ID_UNLOCK:    appendLog(h,L"\r\n=== Unlock / clean ===\r\n");
        launchEngine(h,tool(L"lockdown_breaker.exe")+L" --fix --kill-overlays --kill-effects",true); break;
    case ID_BACKUP:{
        BROWSEINFOW bi{}; bi.hwndOwner=h; bi.lpszTitle=L"Choose a BACKUP DISK or folder (an external drive is best)";
        bi.ulFlags=BIF_RETURNONLYFSDIRS|BIF_NEWDIALOGSTYLE;
        LPITEMIDLIST pidl=SHBrowseForFolderW(&bi);
        if(pidl){ wchar_t path[MAX_PATH];
            if(SHGetPathFromIDListW(pidl,path)){ appendLog(h,L"\r\n=== Backup ===\r\n");
                launchEngine(h,tool(L"backup.exe")+L" --snapshot \""+path+L"\" --keep 10",true); }
            CoTaskMemFree(pidl); }
        break; }
    case ID_PROTECT: setProtection(h,gGuardProc==nullptr); break;
    case ID_QUARANTINE:{
        wchar_t pd[MAX_PATH*2]; DWORD n=GetEnvironmentVariableW(L"ProgramData",pd,MAX_PATH*2);
        std::wstring base=(n?std::wstring(pd):L"C:\\ProgramData");
        CreateDirectoryW((base+L"\\Rescue").c_str(),nullptr);
        std::wstring q=base+L"\\Rescue\\Quarantine"; CreateDirectoryW(q.c_str(),nullptr);
        ShellExecuteW(h,L"explore",q.c_str(),nullptr,nullptr,SW_SHOW); break; }
    }
}

// ------------------------------------------------------------- drawing --------
static void fillGradient(HDC dc,RECT rc,COLORREF a,COLORREF b){
    int h=rc.bottom-rc.top; if(h<=0) return;
    for(int y=0;y<h;++y){
        double t=(double)y/h;
        int r=(int)(GetRValue(a)+(GetRValue(b)-GetRValue(a))*t);
        int g=(int)(GetGValue(a)+(GetGValue(b)-GetGValue(a))*t);
        int bl=(int)(GetBValue(a)+(GetBValue(b)-GetBValue(a))*t);
        HBRUSH br=CreateSolidBrush(RGB(r,g,bl));
        RECT line={rc.left,rc.top+y,rc.right,rc.top+y+1};
        FillRect(dc,&line,br); DeleteObject(br);
    }
}
static void roundCard(HDC dc,RECT rc,COLORREF fill,COLORREF border,int rad){
    HBRUSH b=CreateSolidBrush(fill); HPEN p=CreatePen(PS_SOLID,1,border);
    HGDIOBJ ob=SelectObject(dc,b),op=SelectObject(dc,p);
    RoundRect(dc,rc.left,rc.top,rc.right,rc.bottom,rad,rad);
    SelectObject(dc,ob); SelectObject(dc,op); DeleteObject(b); DeleteObject(p);
}
static void drawText(HDC dc,const wchar_t* s,RECT rc,HFONT f,COLORREF col,UINT fmt){
    HGDIOBJ of=SelectObject(dc,f); SetTextColor(dc,col); SetBkMode(dc,TRANSPARENT);
    DrawTextW(dc,s,-1,&rc,fmt); SelectObject(dc,of);
}

// owner-draw an action card
static void drawCard(DRAWITEMSTRUCT* di){
    Card* c=cardById((int)di->CtlID); if(!c) return;
    HDC dc=di->hDC; RECT rc=di->rcItem;
    // background of the button = page bg, then a rounded card
    HBRUSH bg=CreateSolidBrush(C_BG); FillRect(dc,&rc,bg); DeleteObject(bg);
    COLORREF fill = c->down ? RGB(0xEA,0xF0,0xFF) : (c->hot ? C_CARD_HOT : C_CARD);
    COLORREF bord = c->hot ? C_ACCENT : C_BORDER;
    RECT card=rc; roundCard(dc,card,fill,bord,14);
    // icon in an accent circle
    RECT ic={card.left+16,card.top+ (card.bottom-card.top)/2-20,card.left+56,card.top+(card.bottom-card.top)/2+20};
    drawText(dc,c->icon,ic,gFIcon,C_ACCENT,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOCLIP);
    RECT tr={card.left+66,card.top+14,card.right-12,card.top+42};
    drawText(dc,c->title,tr,gFCard,C_TEXT,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
    RECT sr={card.left+66,card.top+40,card.right-12,card.bottom-10};
    drawText(dc,c->sub,sr,gFCardSub,C_MUTED,DT_LEFT|DT_SINGLELINE);
}

// owner-draw the big protection toggle
static void drawProtect(DRAWITEMSTRUCT* di){
    bool on=gGuardProc!=nullptr;
    HDC dc=di->hDC; RECT rc=di->rcItem;
    HBRUSH bg=CreateSolidBrush(C_BG); FillRect(dc,&rc,bg); DeleteObject(bg);
    COLORREF base = on ? (gProtect.hot?C_GREEN:C_GREEN_D) : (gProtect.hot?C_RED:C_RED_D);
    roundCard(dc,rc,base,base,16);
    // shield glyph
    RECT ic={rc.left+22,rc.top,rc.left+92,rc.bottom};
    drawText(dc,L"\uE83D",ic,gFIconBig,C_WHITE,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOCLIP);
    RECT tr={rc.left+96,rc.top+14,rc.right-160,rc.top+48};
    drawText(dc,on?L"Protected":L"Not protected",tr,gFStatus,C_WHITE,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
    RECT sr={rc.left+96,rc.top+46,rc.right-160,rc.bottom-12};
    drawText(dc,on?L"Real-time guard + disk shield are running":
                  L"Real-time defense is off - click to turn it on",
             sr,gFStatusSub,RGB(0xE6,0xEC,0xF6),DT_LEFT|DT_SINGLELINE);
    // pill on the right
    RECT pill={rc.right-146,rc.top+(rc.bottom-rc.top)/2-20,rc.right-22,rc.top+(rc.bottom-rc.top)/2+20};
    roundCard(dc,pill,C_WHITE,C_WHITE,20);
    drawText(dc,on?L"Turn off":L"Turn on",pill,gFCard,base,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
}

// hover subclass for every owner-draw button
static LRESULT CALLBACK btnProc(HWND h,UINT m,WPARAM w,LPARAM l,UINT_PTR id,DWORD_PTR ref){
    Card* c=cardById((int)id);
    switch(m){
    case WM_MOUSEMOVE:
        if(c && !c->hot){ c->hot=true; InvalidateRect(h,nullptr,TRUE);
            TRACKMOUSEEVENT te{sizeof(te),TME_LEAVE,h,0}; TrackMouseEvent(&te); }
        break;
    case WM_MOUSELEAVE: if(c){ c->hot=false; c->down=false; InvalidateRect(h,nullptr,TRUE);} break;
    case WM_LBUTTONDOWN: if(c){ c->down=true; InvalidateRect(h,nullptr,TRUE);} break;
    case WM_LBUTTONUP:   if(c){ c->down=false; InvalidateRect(h,nullptr,TRUE);} break;
    }
    return DefSubclassProc(h,m,w,l);
}

static HWND mkCardBtn(HWND parent,int id){
    HWND b=CreateWindowExW(0,L"BUTTON",L"",WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
        0,0,0,0,parent,(HMENU)(INT_PTR)id,(HINSTANCE)GetWindowLongPtrW(parent,GWLP_HINSTANCE),nullptr);
    SetWindowSubclass(b,btnProc,id,0);
    return b;
}

// ------------------------------------------------------------- layout ---------
static int gHeadH=92, gStatusH=88, gPad=18;
static void layout(HWND hwnd){
    RECT rc; GetClientRect(hwnd,&rc); int W=rc.right;
    int y=gHeadH+gPad;
    MoveWindow(gProtectWnd,gPad,y,W-2*gPad,gStatusH,TRUE);
    y+=gStatusH+gPad;
    int cols=(W> 760)?3:2;
    int cw=(W-gPad*(cols+1))/cols, ch=78;
    for(int i=0;i<5;++i){ int col=i%cols,row=i/cols;
        MoveWindow(gCardWnd[i],gPad+col*(cw+gPad),y+row*(ch+gPad),cw,ch,TRUE); }
    int rows=(5+cols-1)/cols;
    int logY=y+rows*(ch+gPad)+6;
    // log sits inside a card drawn in WM_PAINT; inset it
    MoveWindow(gLog,gPad+14,logY+34,W-2*gPad-28,rc.bottom-logY-gPad-14,TRUE);
    InvalidateRect(hwnd,nullptr,FALSE);
}

static void paintMain(HWND hwnd){
    PAINTSTRUCT ps; HDC wdc=BeginPaint(hwnd,&ps);
    RECT rc; GetClientRect(hwnd,&rc);
    // double buffer
    HDC dc=CreateCompatibleDC(wdc);
    HBITMAP bmp=CreateCompatibleBitmap(wdc,rc.right,rc.bottom);
    HGDIOBJ ob=SelectObject(dc,bmp);
    HBRUSH bg=CreateSolidBrush(C_BG); FillRect(dc,&rc,bg); DeleteObject(bg);
    // header
    RECT head={0,0,rc.right,gHeadH}; fillGradient(dc,head,C_HEAD_TOP,C_HEAD_BOT);
    RECT sh={24,0,84,gHeadH};
    drawText(dc,L"\uE83D",sh,gFIconBig,C_WHITE,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOCLIP);
    RECT ti={92,18,rc.right-20,56}; drawText(dc,L"Rescue",ti,gFTitle,C_WHITE,DT_LEFT|DT_SINGLELINE);
    RECT su={94,54,rc.right-20,80}; drawText(dc,L"Anti-Ransomware Protection",su,gFSub,RGB(0xC7,0xD4,0xEC),DT_LEFT|DT_SINGLELINE);
    // activity log card frame
    int y=gHeadH+gPad+gStatusH+gPad;
    int cols=(rc.right>760)?3:2; int ch=78; int rows=(5+cols-1)/cols;
    int logY=y+rows*(ch+gPad)+6;
    RECT lc={gPad,logY,rc.right-gPad,rc.bottom-gPad}; roundCard(dc,lc,C_CARD,C_BORDER,14);
    RECT ll={gPad+16,logY+8,rc.right-gPad-16,logY+30};
    drawText(dc,L"Activity",ll,gFCard,C_TEXT,DT_LEFT|DT_SINGLELINE);
    BitBlt(wdc,0,0,rc.right,rc.bottom,dc,0,0,SRCCOPY);
    SelectObject(dc,ob); DeleteObject(bmp); DeleteDC(dc);
    EndPaint(hwnd,&ps);
}

// ------------------------------------------------------------- wndproc --------
static LRESULT CALLBACK WndProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){
    switch(msg){
    case WM_CREATE:{
        gFTitle    =CreateFontW(34,0,0,0,FW_SEMIBOLD,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Segoe UI");
        gFSub      =CreateFontW(17,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Segoe UI");
        gFCard     =CreateFontW(19,0,0,0,FW_SEMIBOLD,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Segoe UI");
        gFCardSub  =CreateFontW(13,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Segoe UI");
        gFIcon     =CreateFontW(28,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Segoe MDL2 Assets");
        gFIconBig  =CreateFontW(40,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Segoe MDL2 Assets");
        gFStatus   =CreateFontW(24,0,0,0,FW_SEMIBOLD,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Segoe UI");
        gFStatusSub=CreateFontW(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Segoe UI");
        gFMono     =CreateFontW(15,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Consolas");
        gProtectWnd=mkCardBtn(hwnd,ID_PROTECT);
        for(int i=0;i<5;++i) gCardWnd[i]=mkCardBtn(hwnd,gCards[i].id);
        gLog=CreateWindowExW(0,L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
            0,0,0,0,hwnd,(HMENU)(INT_PTR)ID_LOG,((LPCREATESTRUCTW)lp)->hInstance,nullptr);
        SendMessageW(gLog,WM_SETFONT,(WPARAM)gFMono,TRUE);
        logAtEnd(L"Welcome to Rescue. Click Quick Scan to check this PC, or turn on\r\n"
                 L"real-time protection. Every action asks for your approval.\r\n");
        layout(hwnd); return 0; }
    case WM_SIZE: layout(hwnd); return 0;
    case WM_ERASEBKGND: return 1;   // painted in WM_PAINT (no flicker)
    case WM_PAINT: paintMain(hwnd); return 0;
    case WM_DRAWITEM:{
        DRAWITEMSTRUCT* di=(DRAWITEMSTRUCT*)lp;
        if(di->CtlID==ID_PROTECT) drawProtect(di); else drawCard(di);
        return TRUE; }
    case WM_COMMAND: if(HIWORD(wp)==BN_CLICKED) onCommand(hwnd,LOWORD(wp)); return 0;
    case WM_APP_APPEND:{ wchar_t* t=(wchar_t*)wp; if(t){ logAtEnd(t); free(t);} return 0; }
    case WM_APP_BUSY:{ gBusy=wp!=0;
        for(int i=0;i<5;++i){ int id=gCards[i].id; if(id==ID_QUARANTINE) continue; EnableWindow(gCardWnd[i],!gBusy); }
        return 0; }
    case WM_CTLCOLOREDIT:{ HDC dc=(HDC)wp; SetTextColor(dc,C_TEXT); SetBkColor(dc,C_WHITE);
        static HBRUSH wb=CreateSolidBrush(C_WHITE); return (LRESULT)wb; }
    case WM_CLOSE: if(gGuardProc){ TerminateProcess(gGuardProc,0); CloseHandle(gGuardProc); gGuardProc=nullptr; }
        DestroyWindow(hwnd); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}

int WINAPI wWinMain(HINSTANCE hInst,HINSTANCE,PWSTR,int nShow){
    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    INITCOMMONCONTROLSEX icc{sizeof(icc),ICC_STANDARD_CLASSES}; InitCommonControlsEx(&icc);
    WNDCLASSW wc{};
    wc.lpfnWndProc=WndProc; wc.hInstance=hInst; wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);
    wc.hbrBackground=nullptr; wc.lpszClassName=L"RescueMainWindow"; wc.hIcon=LoadIconW(nullptr,IDI_SHIELD);
    RegisterClassW(&wc);
    gMain=CreateWindowExW(0,wc.lpszClassName,L"Rescue",WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,CW_USEDEFAULT,900,720,nullptr,nullptr,hInst,nullptr);
    ShowWindow(gMain,nShow); UpdateWindow(gMain);
    MSG m; while(GetMessageW(&m,nullptr,0,0)>0){ TranslateMessage(&m); DispatchMessageW(&m); }
    return 0;
}
