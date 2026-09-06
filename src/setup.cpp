// setup.cpp - RescueSetup.exe: a small, self-contained installer for Rescue.
//
// The whole product (Rescue.exe + engines + the advanced\ PowerShell kit +
// driver) is embedded as an uncompressed TAR resource and unpacked into
// %ProgramFiles%\Rescue. The installer creates Start-menu/Desktop shortcuts,
// registers an Add/Remove-Programs entry, and can OPTIONALLY turn on the kernel
// protection tier at install time (off by default; also switchable later from
// inside the app). It runs elevated (manifest) because it writes Program Files,
// HKLM and, if asked, deploys a Code-Integrity policy.
//
// Run with --uninstall to remove everything (it reverses the kernel CI too).
#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <objidl.h>
#include <gdiplus.h>
#include <string>
#include <vector>

#pragma GCC diagnostic ignored "-Wunused-parameter"

#define IDI_APPICON 1
#define IDR_PAYLOAD 300
#define IDP_BRAND   212

#define CBG     RGB(0x0a,0x0e,0x16)
#define CBG2    RGB(0x0d,0x12,0x20)
#define CPANEL  RGB(0x12,0x1a,0x2b)
#define CINK    RGB(0xe8,0xee,0xf7)
#define CMUT    RGB(0x93,0xa1,0xba)
#define CMUT2   RGB(0x68,0x76,0x8f)
#define CACC    RGB(0x3d,0x8b,0xfd)

static const wchar_t* APP_VER  = L"0.1.0";

static HINSTANCE gInst=nullptr;
static HWND gWnd=nullptr, gChkKernel=nullptr, gChkDesktop=nullptr, gBtnInstall=nullptr, gBtnClose=nullptr, gStatus=nullptr;
static HFONT gF=nullptr, gFB=nullptr, gFS=nullptr;
static Gdiplus::Bitmap* gBrand=nullptr;
static std::wstring gInstallDir;
static bool gDone=false;

// ------------------------------------------------------------- helpers --------
static std::wstring progFiles(){ wchar_t b[MAX_PATH]; if(SHGetFolderPathW(nullptr,CSIDL_PROGRAM_FILES,nullptr,0,b)==S_OK) return b; return L"C:\\Program Files"; }
static std::wstring exePath(){ wchar_t b[MAX_PATH*2]; GetModuleFileNameW(nullptr,b,MAX_PATH*2); return b; }
static std::wstring exeDir(){ std::wstring p=exePath(); size_t s=p.find_last_of(L"\\/"); return s==std::wstring::npos?L".":p.substr(0,s); }

static void setStatus(const std::wstring& s){ if(gStatus) SetWindowTextW(gStatus,s.c_str()); }

// ---- TAR (ustar) extraction from the embedded resource ----------------------
static long octal(const char* p,int n){ long v=0; for(int i=0;i<n && p[i];++i){ if(p[i]<'0'||p[i]>'7') break; v=v*8+(p[i]-'0'); } return v; }
static bool extractPayload(const std::wstring& dest){
    HRSRC r=FindResourceW(gInst,MAKEINTRESOURCEW(IDR_PAYLOAD),RT_RCDATA); if(!r) return false;
    HGLOBAL h=LoadResource(gInst,r); if(!h) return false;
    const char* base=(const char*)LockResource(h); DWORD sz=SizeofResource(gInst,r);
    if(!base||!sz) return false;
    DWORD off=0;
    while(off+512<=sz){
        const char* hdr=base+off;
        bool zero=true; for(int i=0;i<512;++i) if(hdr[i]){ zero=false; break; }
        if(zero) break;                              // end-of-archive
        char name[101]={0}; memcpy(name,hdr,100);
        char prefix[156]={0}; memcpy(prefix,hdr+345,155);
        long fsz=octal(hdr+124,12); char type=hdr[156];
        std::string rel = (prefix[0]? std::string(prefix)+"/" : std::string()) + name;
        while(rel.rfind("./",0)==0) rel=rel.substr(2);   // strip leading ./ from tar
        off+=512;
        bool unsafe = rel.empty() || rel[0]=='/' || rel.find("..")!=std::string::npos;
        if(!unsafe && type!='5' && type!='L'){   // regular file
            std::wstring wrel(rel.begin(),rel.end());
            for(auto& c:wrel) if(c==L'/') c=L'\\';
            std::wstring full=dest+L"\\"+wrel;
            size_t s=full.find_last_of(L'\\'); if(s!=std::wstring::npos) SHCreateDirectoryExW(nullptr,full.substr(0,s).c_str(),nullptr);
            HANDLE f=CreateFileW(full.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
            if(f!=INVALID_HANDLE_VALUE){ DWORD wr=0; if(fsz>0) WriteFile(f,base+off,(DWORD)fsz,&wr,nullptr); CloseHandle(f); }
        }
        off += ((fsz+511)/512)*512;                  // advance past padded data
    }
    return true;
}

// ---- shortcut creation (IShellLink) -----------------------------------------
static void makeShortcut(const std::wstring& lnk,const std::wstring& target,const std::wstring& workdir,const std::wstring& desc){
    IShellLinkW* sl=nullptr;
    if(SUCCEEDED(CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_IShellLinkW,(void**)&sl))){
        sl->SetPath(target.c_str()); sl->SetWorkingDirectory(workdir.c_str());
        sl->SetDescription(desc.c_str()); sl->SetIconLocation(target.c_str(),0);
        IPersistFile* pf=nullptr;
        if(SUCCEEDED(sl->QueryInterface(IID_IPersistFile,(void**)&pf))){ pf->Save(lnk.c_str(),TRUE); pf->Release(); }
        sl->Release();
    }
}
static std::wstring specialDir(int csidl){ wchar_t b[MAX_PATH]; if(SHGetFolderPathW(nullptr,csidl,nullptr,0,b)==S_OK) return b; return L""; }

// ---- Add/Remove Programs registration ---------------------------------------
static void regArp(const std::wstring& dir){
    HKEY k; if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Rescue",
        0,nullptr,0,KEY_WRITE,nullptr,&k,nullptr)!=ERROR_SUCCESS) return;
    auto S=[&](const wchar_t* n,const std::wstring& v){ RegSetValueExW(k,n,0,REG_SZ,(const BYTE*)v.c_str(),(DWORD)((v.size()+1)*sizeof(wchar_t))); };
    std::wstring exe=dir+L"\\Rescue.exe"; std::wstring un=L"\""+dir+L"\\RescueSetup.exe\" --uninstall";
    S(L"DisplayName",L"Rescue Security Center"); S(L"DisplayVersion",APP_VER);
    S(L"Publisher",L"Rescue (Open Source)"); S(L"DisplayIcon",exe);
    S(L"InstallLocation",dir); S(L"UninstallString",un);
    DWORD one=1; RegSetValueExW(k,L"NoModify",0,REG_DWORD,(const BYTE*)&one,sizeof(one));
    RegSetValueExW(k,L"NoRepair",0,REG_DWORD,(const BYTE*)&one,sizeof(one));
    RegCloseKey(k);
}

// ---- the install itself ------------------------------------------------------
static void doInstall(bool enableKernel,bool desktop){
    EnableWindow(gBtnInstall,FALSE); EnableWindow(gChkKernel,FALSE); EnableWindow(gChkDesktop,FALSE);
    gInstallDir = progFiles()+L"\\Rescue";
    setStatus(L"Creating "+gInstallDir+L" ...");
    SHCreateDirectoryExW(nullptr,gInstallDir.c_str(),nullptr);
    setStatus(L"Copying files ...");
    if(!extractPayload(gInstallDir)){ setStatus(L"ERROR: could not unpack the embedded payload."); return; }
    // copy ourselves in as the uninstaller
    CopyFileW(exePath().c_str(),(gInstallDir+L"\\RescueSetup.exe").c_str(),FALSE);

    setStatus(L"Creating shortcuts ...");
    std::wstring target=gInstallDir+L"\\Rescue.exe";
    std::wstring progs=specialDir(CSIDL_COMMON_PROGRAMS);
    if(!progs.empty()){ SHCreateDirectoryExW(nullptr,(progs+L"\\Rescue").c_str(),nullptr);
        makeShortcut(progs+L"\\Rescue\\Rescue Security Center.lnk",target,gInstallDir,L"Rescue Security Center");
        makeShortcut(progs+L"\\Rescue\\Uninstall Rescue.lnk",gInstallDir+L"\\RescueSetup.exe",gInstallDir,L"Uninstall Rescue"); }
    if(desktop){ std::wstring dsk=specialDir(CSIDL_COMMON_DESKTOPDIRECTORY);
        if(!dsk.empty()) makeShortcut(dsk+L"\\Rescue Security Center.lnk",target,gInstallDir,L"Rescue Security Center"); }

    setStatus(L"Registering ...");
    regArp(gInstallDir);

    if(enableKernel){
        setStatus(L"Launching kernel protection setup ...");
        std::wstring script=gInstallDir+L"\\advanced\\installer\\Enable-KernelCI.ps1";
        std::wstring drv=gInstallDir+L"\\advanced\\driver";
        if(GetFileAttributesW(script.c_str())!=INVALID_FILE_ATTRIBUTES){
            std::wstring args=L"-NoExit -ExecutionPolicy Bypass -File \""+script+L"\" -SysPath \""+drv+L"\\rescuemon.sys\" -InfPath \""+drv+L"\\rescuemon.inf\"";
            ShellExecuteW(gWnd,L"open",L"powershell.exe",args.c_str(),drv.c_str(),SW_SHOWNORMAL);
        }
    }
    setStatus(L"Done. Rescue is installed in "+gInstallDir+L".");
    gDone=true;
    SetWindowTextW(gBtnInstall,L"Launch Rescue"); EnableWindow(gBtnInstall,TRUE);
    SetWindowTextW(gBtnClose,L"Close");
}

// ---- uninstall ---------------------------------------------------------------
static void doUninstall(){
    std::wstring dir=exeDir();
    // reverse kernel CI if it was enabled
    std::wstring restore=dir+L"\\advanced\\installer\\Restore-KernelCI.ps1";
    if(GetFileAttributesW(restore.c_str())!=INVALID_FILE_ATTRIBUTES){
        std::wstring args=L"-ExecutionPolicy Bypass -File \""+restore+L"\"";
        SHELLEXECUTEINFOW si{}; si.cbSize=sizeof(si); si.fMask=SEE_MASK_NOCLOSEPROCESS; si.lpVerb=L"open";
        si.lpFile=L"powershell.exe"; si.lpParameters=args.c_str(); si.nShow=SW_SHOWNORMAL;
        if(ShellExecuteExW(&si) && si.hProcess){ WaitForSingleObject(si.hProcess,120000); CloseHandle(si.hProcess); }
    }
    // shortcuts + ARP
    std::wstring progs=specialDir(CSIDL_COMMON_PROGRAMS);
    if(!progs.empty()){ std::wstring d=progs+L"\\Rescue"; SHFILEOPSTRUCTW fo{}; std::wstring from=d+L"\0"; std::vector<wchar_t> f(from.begin(),from.end()); f.push_back(0); f.push_back(0);
        fo.wFunc=FO_DELETE; fo.pFrom=f.data(); fo.fFlags=FOF_NO_UI; SHFileOperationW(&fo); }
    std::wstring dsk=specialDir(CSIDL_COMMON_DESKTOPDIRECTORY);
    if(!dsk.empty()) DeleteFileW((dsk+L"\\Rescue Security Center.lnk").c_str());
    RegDeleteKeyW(HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Rescue");
    // delete the install dir after we exit (a detached cmd removes it)
    std::wstring cmd=L"/c timeout /t 2 >nul & rmdir /s /q \""+dir+L"\"";
    ShellExecuteW(nullptr,L"open",L"cmd.exe",cmd.c_str(),nullptr,SW_HIDE);
    MessageBoxW(nullptr,L"Rescue has been removed.",L"Uninstall Rescue",MB_ICONINFORMATION);
}

// ------------------------------------------------------------- UI -------------
static HFONT mkFont(int h,int w){ return CreateFontW(h,0,0,0,w,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI"); }

static LRESULT CALLBACK WndProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){
    switch(msg){
    case WM_CREATE:{
        gF=mkFont(17,FW_NORMAL); gFB=mkFont(26,FW_SEMIBOLD); gFS=mkFont(15,FW_NORMAL);
        int x=150, y=132;
        CreateWindowW(L"STATIC",L"Install location:  %ProgramFiles%\\Rescue",WS_CHILD|WS_VISIBLE,
            x,y,420,22,hwnd,nullptr,gInst,nullptr); y+=34;
        gChkKernel=CreateWindowW(L"BUTTON",L"Enable kernel protection now (advanced, optional)",
            WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,x,y,440,22,hwnd,(HMENU)101,gInst,nullptr); y+=24;
        CreateWindowW(L"STATIC",L"Deploys a custom Code-Integrity policy for the RescueMon driver. "
            L"Off by default; needs Memory Integrity off, and you can also turn it on later inside the app.",
            WS_CHILD|WS_VISIBLE,x+22,y,420,42,hwnd,(HMENU)201,gInst,nullptr); y+=50;
        gChkDesktop=CreateWindowW(L"BUTTON",L"Create a desktop shortcut",
            WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,x,y,300,22,hwnd,(HMENU)102,gInst,nullptr);
        SendMessageW(gChkDesktop,BM_SETCHECK,BST_CHECKED,0); y+=44;
        gStatus=CreateWindowW(L"STATIC",L"Ready to install.",WS_CHILD|WS_VISIBLE,x,y,440,40,hwnd,(HMENU)202,gInst,nullptr);
        gBtnInstall=CreateWindowW(L"BUTTON",L"Install",WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,360,330,110,34,hwnd,(HMENU)1,gInst,nullptr);
        gBtnClose  =CreateWindowW(L"BUTTON",L"Cancel", WS_CHILD|WS_VISIBLE,478,330,90,34,hwnd,(HMENU)2,gInst,nullptr);
        for(HWND c:{gChkKernel,gChkDesktop,gBtnInstall,gBtnClose}) SendMessageW(c,WM_SETFONT,(WPARAM)gF,TRUE);
        SendMessageW(gStatus,WM_SETFONT,(WPARAM)gFS,TRUE);
        SendMessageW(GetDlgItem(hwnd,201),WM_SETFONT,(WPARAM)gFS,TRUE);
        SendMessageW(GetWindow(hwnd,GW_CHILD),WM_SETFONT,(WPARAM)gF,TRUE);
        return 0; }
    case WM_CTLCOLORSTATIC: case WM_CTLCOLORBTN:{
        HDC dc=(HDC)wp; SetBkMode(dc,TRANSPARENT); SetTextColor(dc, (HWND)lp==GetDlgItem(hwnd,201)?CMUT:CINK);
        static HBRUSH b=CreateSolidBrush(CBG); return (LRESULT)b; }
    case WM_PAINT:{
        PAINTSTRUCT ps; HDC dc=BeginPaint(hwnd,&ps); RECT cr; GetClientRect(hwnd,&cr);
        HBRUSH bg=CreateSolidBrush(CBG); FillRect(dc,&cr,bg); DeleteObject(bg);
        RECT hd={0,0,cr.right,104}; HBRUSH hb=CreateSolidBrush(CBG2); FillRect(dc,&hd,hb); DeleteObject(hb);
        RECT ln={0,104,cr.right,105}; HBRUSH lb=CreateSolidBrush(RGB(0x24,0x31,0x49)); FillRect(dc,&ln,lb); DeleteObject(lb);
        if(gBrand){ Gdiplus::Graphics g(dc); g.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
            g.DrawImage(gBrand,Gdiplus::RectF(34,26,52,52),0,0,(Gdiplus::REAL)gBrand->GetWidth(),(Gdiplus::REAL)gBrand->GetHeight(),Gdiplus::UnitPixel); }
        SetBkMode(dc,TRANSPARENT);
        HGDIOBJ of=SelectObject(dc,gFB); SetTextColor(dc,CINK); RECT t={104,26,cr.right,58}; DrawTextW(dc,L"Rescue Security Center",-1,&t,DT_LEFT|DT_SINGLELINE);
        SelectObject(dc,gFS); SetTextColor(dc,CMUT2); RECT s={106,60,cr.right,84}; DrawTextW(dc,L"Setup \u00b7 anti-ransomware protection",-1,&s,DT_LEFT|DT_SINGLELINE);
        SelectObject(dc,of); EndPaint(hwnd,&ps); return 0; }
    case WM_COMMAND:{
        int id=LOWORD(wp);
        if(id==1){
            if(gDone){ ShellExecuteW(hwnd,L"open",(gInstallDir+L"\\Rescue.exe").c_str(),nullptr,gInstallDir.c_str(),SW_SHOW); DestroyWindow(hwnd); return 0; }
            bool k=SendMessageW(gChkKernel,BM_GETCHECK,0,0)==BST_CHECKED;
            bool d=SendMessageW(gChkDesktop,BM_GETCHECK,0,0)==BST_CHECKED;
            doInstall(k,d);
        } else if(id==2){ DestroyWindow(hwnd); }
        return 0; }
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}

static Gdiplus::Bitmap* loadPng(int id){
    HRSRC r=FindResourceW(gInst,MAKEINTRESOURCEW(id),RT_RCDATA); if(!r) return nullptr;
    HGLOBAL h=LoadResource(gInst,r); if(!h) return nullptr; void* p=LockResource(h); DWORD sz=SizeofResource(gInst,r);
    if(!p||!sz) return nullptr; HGLOBAL b=GlobalAlloc(GMEM_MOVEABLE,sz); if(!b) return nullptr;
    void* q=GlobalLock(b); memcpy(q,p,sz); GlobalUnlock(b); IStream* st=nullptr;
    Gdiplus::Bitmap* bm=nullptr; if(CreateStreamOnHGlobal(b,TRUE,&st)==S_OK&&st){ bm=Gdiplus::Bitmap::FromStream(st); st->Release(); }
    return bm;
}

int WINAPI wWinMain(HINSTANCE hInst,HINSTANCE,PWSTR cmd,int nShow){
    gInst=hInst;
    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if(cmd && wcsstr(cmd,L"--uninstall")){ doUninstall(); return 0; }
    ULONG_PTR tok=0; Gdiplus::GdiplusStartupInput gsi; Gdiplus::GdiplusStartup(&tok,&gsi,nullptr);
    gBrand=loadPng(IDP_BRAND);
    WNDCLASSW wc{}; wc.lpfnWndProc=WndProc; wc.hInstance=hInst; wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);
    wc.hbrBackground=nullptr; wc.lpszClassName=L"RescueSetup"; wc.hIcon=(HICON)LoadImageW(hInst,MAKEINTRESOURCEW(IDI_APPICON),IMAGE_ICON,0,0,LR_DEFAULTSIZE);
    RegisterClassW(&wc);
    int W=600,H=420; RECT r={0,0,W,H}; AdjustWindowRect(&r,WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,FALSE);
    gWnd=CreateWindowExW(0,wc.lpszClassName,L"Rescue Setup",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        CW_USEDEFAULT,CW_USEDEFAULT,r.right-r.left,r.bottom-r.top,nullptr,nullptr,hInst,nullptr);
    ShowWindow(gWnd,nShow); UpdateWindow(gWnd);
    MSG m; while(GetMessageW(&m,nullptr,0,0)>0){ if(!IsDialogMessageW(gWnd,&m)){ TranslateMessage(&m); DispatchMessageW(&m); } }
    return 0;
}
