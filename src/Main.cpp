#include "stdafx.h"
#include "InjectionCore.h"
#include "DumpHandler.h"
#include "DriverExtract.h"
#include "Message.hpp"

#include <BlackBone/src/BlackBone/Misc/Utils.h>
#include <BlackBone/src/BlackBone/Process/Process.h>

#include <algorithm>
#include <chrono>
#include <cwctype>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <optional>
#include <thread>

namespace fs = std::filesystem;

struct CLIOptions
{
    std::vector<std::wstring> dlls;
    std::wstring process;
    std::wstring cmdline;
    std::wstring initRoutine;
    std::wstring initArgs;

    uint32_t pid = 0;
    uint32_t mmapFlags = 0;
    uint32_t delay = 0;
    uint32_t period = 0;
    uint32_t skip = 0;

    MapMode injectMode = Normal;
    ProcMode processMode = Existing;

    bool hijack = false;
    bool unlink = false;
    bool erasePE = false;
    bool krnHandle = false;
    bool quiet = false;
    bool injIndef = false;
    bool showHelp = false;

    std::optional<uint32_t> waitTimeoutMs;
};

static InjectContext* g_activeContext = nullptr;

static std::wstring ToLower( std::wstring value )
{
    std::transform( value.begin(), value.end(), value.begin(), []( wchar_t ch ) { return static_cast<wchar_t>(std::towlower( ch )); } );
    return value;
}

static bool ParseUint32( const std::wstring& value, uint32_t& out, int base = 0 )
{
    try
    {
        size_t idx = 0;
        out = static_cast<uint32_t>( std::stoul( value, &idx, base ) );
        return idx == value.size();
    }
    catch (...)
    {
        return false;
    }
}

static std::wstring MapModeToString( MapMode mode )
{
    switch (mode)
    {
        case Normal:        return L"normal";
        case Manual:        return L"manual-map";
        case Kernel_Thread: return L"kernel-thread";
        case Kernel_APC:    return L"kernel-apc";
        case Kernel_MMap:   return L"kernel-mmap";
        case Kernel_DriverMap: return L"kernel-driver";
        default:            return L"unknown";
    }
}

static std::wstring ProcModeToString( ProcMode mode )
{
    switch (mode)
    {
        case Existing:     return L"existing";
        case NewProcess:   return L"new-process";
        case ManualLaunch: return L"manual-launch";
        default:           return L"unknown";
    }
}

static MapMode ParseInjectMode( const std::wstring& value, bool& ok )
{
    auto normalized = ToLower( value );
    ok = true;

    if (normalized == L"normal" || normalized == L"default" || normalized == L"loadlibrary")
        return Normal;
    if (normalized == L"manual" || normalized == L"manual-map" || normalized == L"manualmap")
        return Manual;
    if (normalized == L"kernel-thread" || normalized == L"kernel_thread" || normalized == L"kthread")
        return Kernel_Thread;
    if (normalized == L"kernel-apc" || normalized == L"kernel_apc" || normalized == L"kapc")
        return Kernel_APC;
    if (normalized == L"kernel-mmap" || normalized == L"kernel_mmap")
        return Kernel_MMap;
    if (normalized == L"kernel-driver" || normalized == L"kernel_driver" || normalized == L"driver")
        return Kernel_DriverMap;

    ok = false;
    return Normal;
}

static ProcMode ParseProcessMode( const std::wstring& value, bool& ok )
{
    auto normalized = ToLower( value );
    ok = true;

    if (normalized == L"existing" || normalized == L"attach")
        return Existing;
    if (normalized == L"new" || normalized == L"launch" || normalized == L"new-process")
        return NewProcess;
    if (normalized == L"manual" || normalized == L"manual-launch" || normalized == L"wait")
        return ManualLaunch;

    ok = false;
    return Existing;
}

static void PrintUsage( const wchar_t* exeName )
{
    const std::wstring name = exeName ? fs::path( exeName ).filename().wstring() : L"xenos.exe";
    std::wcout << L"Usage:\n"
               << L"  " << name << L" --dll <path> [--dll <path> ...] [options]\n\n"
               << L"Options:\n"
               << L"  --dll, --inject <path>       Path to a DLL to inject (repeatable).\n"
               << L"  --process <name|path>        Target process name or executable path.\n"
               << L"  --pid <pid>                  Target process id for existing-mode injection.\n"
               << L"  --mode <existing|new|manual> Process acquisition strategy.\n"
               << L"  --method <normal|manual|kernel-thread|kernel-apc|kernel-mmap|kernel-driver>\n"
               << L"                                 Injection technique.\n"
               << L"  --cmdline <args>              Command line for new process mode.\n"
               << L"  --init <export>               Initialization routine to call after injection.\n"
               << L"  --init-args <text>            UTF-16 argument passed to the init routine.\n"
               << L"  --delay <ms>                  Delay before injecting (milliseconds).\n"
               << L"  --period <ms>                 Delay between multiple images (milliseconds).\n"
               << L"  --skip <count>                Skip first N matching processes in manual mode.\n"
               << L"  --mmap-flags <mask>           Manual map flags (hex or decimal).\n"
               << L"  --wait-timeout <seconds>      Abort manual wait after the specified time.\n"
               << L"  --hijack                      Hijack an existing thread for execution.\n"
               << L"  --unlink                      Unlink module after injection.\n"
               << L"  --erase-pe                    Zero PE headers after injection.\n"
               << L"  --krn-handle                  Promote process handle privileges via driver.\n"
               << L"  --indef                       Re-run manual wait injection indefinitely.\n"
               << L"  --quiet                       Suppress informational console output.\n"
               << L"  --help                        Show this message.\n";
}

static bool ParseArguments( int argc, wchar_t* argv[], CLIOptions& options, std::wstring& error )
{
    for (int i = 1; i < argc; ++i)
    {
        std::wstring arg = argv[i];

        if (arg == L"--help" || arg == L"-h" || arg == L"/?")
        {
            options.showHelp = true;
            return true;
        }

        if (arg == L"--dll" || arg == L"--inject")
        {
            if (i + 1 >= argc)
            {
                error = L"Missing value for " + arg;
                return false;
            }
            options.dlls.emplace_back( argv[++i] );
        }
        else if (arg == L"--process" || arg == L"--process-name" || arg == L"--process-path")
        {
            if (i + 1 >= argc)
            {
                error = L"Missing value for " + arg;
                return false;
            }
            options.process = argv[++i];
        }
        else if (arg == L"--cmdline")
        {
            if (i + 1 >= argc)
            {
                error = L"Missing value for --cmdline";
                return false;
            }
            options.cmdline = argv[++i];
        }
        else if (arg == L"--pid")
        {
            if (i + 1 >= argc)
            {
                error = L"Missing value for --pid";
                return false;
            }

            uint32_t value = 0;
            if (!ParseUint32( argv[++i], value ))
            {
                error = L"Invalid pid value";
                return false;
            }
            options.pid = value;
        }
        else if (arg == L"--mode")
        {
            if (i + 1 >= argc)
            {
                error = L"Missing value for --mode";
                return false;
            }

            bool ok = false;
            options.processMode = ParseProcessMode( argv[++i], ok );
            if (!ok)
            {
                error = L"Unknown process mode";
                return false;
            }
        }
        else if (arg == L"--method" || arg == L"--map-mode")
        {
            if (i + 1 >= argc)
            {
                error = L"Missing value for " + arg;
                return false;
            }

            bool ok = false;
            options.injectMode = ParseInjectMode( argv[++i], ok );
            if (!ok)
            {
                error = L"Unknown injection method";
                return false;
            }
        }
        else if (arg == L"--init")
        {
            if (i + 1 >= argc)
            {
                error = L"Missing value for --init";
                return false;
            }
            options.initRoutine = argv[++i];
        }
        else if (arg == L"--init-args")
        {
            if (i + 1 >= argc)
            {
                error = L"Missing value for --init-args";
                return false;
            }
            options.initArgs = argv[++i];
        }
        else if (arg == L"--delay")
        {
            if (i + 1 >= argc)
            {
                error = L"Missing value for --delay";
                return false;
            }

            uint32_t value = 0;
            if (!ParseUint32( argv[++i], value ))
            {
                error = L"Invalid delay value";
                return false;
            }
            options.delay = value;
        }
        else if (arg == L"--period")
        {
            if (i + 1 >= argc)
            {
                error = L"Missing value for --period";
                return false;
            }

            uint32_t value = 0;
            if (!ParseUint32( argv[++i], value ))
            {
                error = L"Invalid period value";
                return false;
            }
            options.period = value;
        }
        else if (arg == L"--skip")
        {
            if (i + 1 >= argc)
            {
                error = L"Missing value for --skip";
                return false;
            }

            uint32_t value = 0;
            if (!ParseUint32( argv[++i], value ))
            {
                error = L"Invalid skip value";
                return false;
            }
            options.skip = value;
        }
        else if (arg == L"--mmap-flags")
        {
            if (i + 1 >= argc)
            {
                error = L"Missing value for --mmap-flags";
                return false;
            }

            uint32_t value = 0;
            if (!ParseUint32( argv[++i], value ))
            {
                error = L"Invalid manual map flag value";
                return false;
            }
            options.mmapFlags = value;
        }
        else if (arg == L"--wait-timeout")
        {
            if (i + 1 >= argc)
            {
                error = L"Missing value for --wait-timeout";
                return false;
            }

            uint32_t value = 0;
            if (!ParseUint32( argv[++i], value ))
            {
                error = L"Invalid wait timeout";
                return false;
            }
            options.waitTimeoutMs = value * 1000;
        }
        else if (arg == L"--wait-timeout-ms")
        {
            if (i + 1 >= argc)
            {
                error = L"Missing value for --wait-timeout-ms";
                return false;
            }

            uint32_t value = 0;
            if (!ParseUint32( argv[++i], value ))
            {
                error = L"Invalid wait timeout";
                return false;
            }
            options.waitTimeoutMs = value;
        }
        else if (arg == L"--hijack")
        {
            options.hijack = true;
        }
        else if (arg == L"--unlink")
        {
            options.unlink = true;
        }
        else if (arg == L"--erase-pe" || arg == L"--erase")
        {
            options.erasePE = true;
        }
        else if (arg == L"--krn-handle")
        {
            options.krnHandle = true;
        }
        else if (arg == L"--indef")
        {
            options.injIndef = true;
        }
        else if (arg == L"--quiet")
        {
            options.quiet = true;
        }
        else if (arg == L"--manual")
        {
            options.processMode = ManualLaunch;
        }
        else if (arg == L"--existing")
        {
            options.processMode = Existing;
        }
        else if (arg == L"--new")
        {
            options.processMode = NewProcess;
        }
        else
        {
            error = L"Unknown option: " + arg;
            return false;
        }
    }

    return true;
}

static bool ValidateOptions( CLIOptions& options, std::wstring& error )
{
    if (options.dlls.empty())
    {
        error = L"At least one --dll argument is required";
        return false;
    }

    if (options.processMode == NewProcess && options.process.empty())
    {
        error = L"--process must be provided for new-process mode";
        return false;
    }

    if (options.processMode == ManualLaunch && options.process.empty())
    {
        error = L"--process must be provided for manual-launch mode";
        return false;
    }

    if (options.processMode == Existing && options.pid == 0 && options.process.empty())
    {
        error = L"Specify either --pid or --process when using existing mode";
        return false;
    }

    return true;
}

static std::wstring FormatStatus( NTSTATUS status )
{
    auto desc = blackbone::Utils::GetErrorDescription( status );
    return blackbone::Utils::FormatString( L"0x%08X (%ls)", status, desc.c_str() );
}

static void PrintSummary( const InjectContext& context, const CLIOptions& options )
{
    std::wcout << L"[*] Process mode     : " << ProcModeToString( options.processMode ) << std::endl;
    if (!context.procPath.empty())
        std::wcout << L"    Target          : " << context.procPath << std::endl;
    if (context.pid != 0)
        std::wcout << L"    PID             : " << context.pid << std::endl;

    std::wcout << L"[*] Injection method : " << MapModeToString( options.injectMode ) << std::endl;

    for (auto& dll : context.cfg.images)
        std::wcout << L"    DLL             : " << dll << std::endl;

    if (!options.initRoutine.empty())
        std::wcout << L"    Init routine    : " << options.initRoutine << std::endl;
    if (!options.initArgs.empty())
        std::wcout << L"    Init args       : " << options.initArgs << std::endl;

    if (options.delay)
        std::wcout << L"[*] Delay before inject: " << options.delay << L" ms" << std::endl;
    if (options.period)
        std::wcout << L"[*] Delay between DLLs: " << options.period << L" ms" << std::endl;
}

static void LogOSInfoConsole()
{
    SYSTEM_INFO info = { 0 };
    const char* osArch = "x64";

    auto pPeb = (blackbone::PEB_T*)NtCurrentTeb()->ProcessEnvironmentBlock;
    GetNativeSystemInfo( &info );

    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
        osArch = "x86";

    xlog::Normal(
        "Started on Windows %d.%d.%d.%d %s. Driver status: 0x%X",
        pPeb->OSMajorVersion,
        pPeb->OSMinorVersion,
        (pPeb->OSCSDVersion >> 8) & 0xFF,
        pPeb->OSBuildNumber,
        osArch,
        blackbone::Driver().status()
        );
}

static int ConsoleDumpNotifier( const wchar_t* path, void*, EXCEPTION_POINTERS*, bool success )
{
    std::wstring message = success
        ? L"Program crashed. Dump saved to '" + std::wstring( path ) + L"'"
        : L"Program crashed. Failed to save dump.";

    Message::ShowError( NULL, message );
    return 0;
}

static BOOL WINAPI ConsoleCtrlHandler( DWORD signal )
{
    if ((signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) && g_activeContext)
    {
        g_activeContext->waitActive = false;
        std::wcerr << std::endl << L"[!] Cancellation requested. Stopping wait..." << std::endl;
        return TRUE;
    }

    return FALSE;
}

static NTSTATUS RunInjection( InjectionCore& core, CLIOptions& options )
{
    InjectContext context;
    context.cfg.images.clear();
    context.cfg.injectMode = options.injectMode;
    context.cfg.processMode = options.processMode;
    context.cfg.mmapFlags = options.mmapFlags;
    context.cfg.delay = options.delay;
    context.cfg.period = options.period;
    context.cfg.skipProc = options.skip;
    context.cfg.hijack = options.hijack;
    context.cfg.unlink = options.unlink;
    context.cfg.erasePE = options.erasePE;
    context.cfg.krnHandle = options.krnHandle;
    context.cfg.injIndef = options.injIndef;
    context.cfg.initRoutine = options.initRoutine;
    context.cfg.initArgs = options.initArgs;
    context.cfg.procCmdLine = options.cmdline;
    context.cfg.pid = options.pid;

    context.pid = options.pid;
    context.skippedCount = 0;
    context.procList.clear();
    context.procDiff.clear();

    if (options.processMode == NewProcess)
    {
        fs::path procPath = options.process;
        if (!fs::exists( procPath ))
        {
            Message::ShowError( NULL, L"Executable not found: " + procPath.wstring() );
            return STATUS_INVALID_PARAMETER;
        }

        procPath = fs::absolute( procPath );
        context.procPath = procPath.wstring();
        context.cfg.procName = context.procPath;
    }
    else if (!options.process.empty())
    {
        context.procPath = options.process;
        context.cfg.procName = options.process;

        // If path-like, normalize to absolute for logging
        fs::path candidate = options.process;
        if (candidate.has_filename() && fs::exists( candidate ))
            context.procPath = fs::absolute( candidate ).wstring();
    }

    for (const auto& dllArg : options.dlls)
    {
        fs::path dllPath = dllArg;
        if (!dllPath.is_absolute())
            dllPath = fs::absolute( dllPath );

        if (!fs::exists( dllPath ))
        {
            Message::ShowError( NULL, L"DLL not found: " + dllPath.wstring() );
            return STATUS_INVALID_PARAMETER;
        }

        auto image = std::make_shared<blackbone::pe::PEImage>();
        auto status = image->Load( dllPath.wstring() );
        if (!NT_SUCCESS( status ))
        {
            Message::ShowError( NULL, L"Failed to load image '" + dllPath.wstring() + L"'" );
            return status;
        }

        context.images.emplace_back( image );
        context.cfg.images.emplace_back( dllPath.wstring() );

        image->Release( true );
    }

    if (options.processMode == Existing && context.pid == 0 && !options.process.empty())
    {
        auto candidates = blackbone::Process::EnumByName( options.process );
        if (!candidates.empty())
        {
            context.pid = candidates.front();
            context.cfg.pid = context.pid;
        }
        else
        {
            Message::ShowError( NULL, L"Process '" + options.process + L"' is not running" );
            return STATUS_NOT_FOUND;
        }
    }

    std::unique_ptr<std::thread> timeoutThread;
    if (options.processMode == ManualLaunch && options.waitTimeoutMs.has_value())
    {
        auto timeout = *options.waitTimeoutMs;
        timeoutThread = std::make_unique<std::thread>([&context, timeout]()
        {
            std::this_thread::sleep_for( std::chrono::milliseconds( timeout ) );
            if (context.waitActive)
                context.waitActive = false;
        });
    }

    if (options.injectMode >= Kernel_Thread)
    {
        DriverExtract::Instance().Extract();
        auto status = blackbone::Driver().EnsureLoaded();
        if (!NT_SUCCESS( status ))
        {
            Message::ShowError( NULL, L"Failed to load BlackBone driver: " + FormatStatus( status ) );
            DriverExtract::Instance().Cleanup();
            if (timeoutThread && timeoutThread->joinable())
                timeoutThread->join();
            return status;
        }
    }

    if (!options.quiet)
        PrintSummary( context, options );

    g_activeContext = &context;
    auto status = core.InjectMultiple( &context );
    g_activeContext = nullptr;

    if (timeoutThread && timeoutThread->joinable())
        timeoutThread->join();

    if (options.injectMode >= Kernel_Thread)
        DriverExtract::Instance().Cleanup();

    return status;
}

int wmain( int argc, wchar_t* argv[] )
{
    Message::EnableConsoleMode( true );

    CLIOptions options;
    std::wstring error;

    if (!ParseArguments( argc, argv, options, error ))
    {
        if (!error.empty())
            std::wcerr << L"Error: " << error << std::endl;
        PrintUsage( argv[0] );
        return 1;
    }

    if (options.showHelp)
    {
        PrintUsage( argv[0] );
        return 0;
    }

    if (!ValidateOptions( options, error ))
    {
        std::wcerr << L"Error: " << error << std::endl;
        PrintUsage( argv[0] );
        return 1;
    }

    dump::DumpHandler::Instance().CreateWatchdog( blackbone::Utils::GetExeDirectory(), dump::CreateFullDump, &ConsoleDumpNotifier );
    LogOSInfoConsole();

    SetConsoleCtrlHandler( ConsoleCtrlHandler, TRUE );

    HWND dummy = nullptr;
    InjectionCore core( dummy );

    NTSTATUS status = RunInjection( core, options );

    SetConsoleCtrlHandler( ConsoleCtrlHandler, FALSE );

    if (!NT_SUCCESS( status ))
    {
        std::wcerr << L"Injection failed with status 0x" << std::hex << std::uppercase
                   << static_cast<uint32_t>( status ) << std::nouppercase << std::dec << std::endl;
        return static_cast<int>( status );
    }

    if (!options.quiet)
        std::wcout << L"Injection completed successfully." << std::endl;

    return 0;
}
#include "stdafx.h"
#include "MainDlg.h"
#include "DumpHandler.h"
#include "DriverExtract.h"

#include <shellapi.h>

/// <summary>
/// Crash dump notify callback
/// </summary>
/// <param name="path">Dump file path</param>
/// <param name="context">User context</param>
/// <param name="expt">Exception info</param>
/// <param name="success">if false - crash dump file was not saved</param>
/// <returns>status</returns>
int DumpNotifier( const wchar_t* path, void* context, EXCEPTION_POINTERS* expt, bool success )
{
    Message::ShowError( NULL, L"Program has crashed. Dump file saved at '" + std::wstring( path ) + L"'" );
    return 0;
}

/// <summary>
/// Associate profile file extension
/// </summary>
void AssociateExtension()
{
    wchar_t tmp[255] = { 0 };
    GetModuleFileNameW( NULL, tmp, sizeof( tmp ) );

#ifdef USE64
    std::wstring ext = L".xpr64";
    std::wstring alias = L"XenosProfile64";
    std::wstring desc = L"Xenos 64-bit injection profile";
#else
    std::wstring ext = L".xpr";
    std::wstring alias = L"XenosProfile";
    std::wstring desc = L"Xenos injection profile";
#endif 
    std::wstring editWith = std::wstring( tmp ) + L" --load %1";
    std::wstring runWith = std::wstring( tmp ) + L" --run %1";
    std::wstring icon = std::wstring( tmp ) + L",-" + std::to_wstring( IDI_ICON1 );

    auto AddKey = []( const std::wstring& subkey, const std::wstring& value, const wchar_t* regValue ) {
        SHSetValue( HKEY_CLASSES_ROOT, subkey.c_str(), regValue, REG_SZ, value.c_str(), (DWORD)(value.size() * sizeof( wchar_t )) );
    };

    SHDeleteKeyW( HKEY_CLASSES_ROOT, alias.c_str() );

    AddKey( ext, alias, nullptr );
    AddKey( ext, L"Application/xml", L"Content Type" );
    AddKey( alias, desc, nullptr );
    AddKey( alias + L"\\shell", L"Run", nullptr );
    AddKey( alias + L"\\shell\\Edit\\command", editWith, nullptr );
    AddKey( alias + L"\\shell\\Run\\command", runWith, nullptr );
    AddKey( alias + L"\\DefaultIcon", icon, nullptr );
}

/// <summary>
/// Log major OS information
/// </summary>
void LogOSInfo()
{
    SYSTEM_INFO info = { 0 };
    const char* osArch = "x64";

    auto pPeb = (blackbone::PEB_T*)NtCurrentTeb()->ProcessEnvironmentBlock;
    GetNativeSystemInfo( &info );

    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
        osArch = "x86";

    xlog::Normal(
        "Started on Windows %d.%d.%d.%d %s. Driver status: 0x%X",
        pPeb->OSMajorVersion,
        pPeb->OSMinorVersion,
        (pPeb->OSCSDVersion >> 8) & 0xFF,
        pPeb->OSBuildNumber,
        osArch,
        blackbone::Driver().status()
        );
}

/// <summary>
/// Parse command line string
/// </summary>
/// <param name="param">Resulting param</param>
/// <returns>Profile action</returns>
MainDlg::StartAction ParseCmdLine( std::wstring& param )
{
    int argc = 0;
    auto pCmdLine = GetCommandLineW();
    auto argv = CommandLineToArgvW( pCmdLine, &argc );

    for (int i = 1; i < argc; i++)
    {
        if (_wcsicmp( argv[i], L"--load" ) == 0 && i + 1 < argc)
        {
            param = argv[i + 1];
            return MainDlg::LoadProfile;
        }
        if (_wcsicmp( argv[i], L"--run" ) == 0 && i + 1 < argc)
        {
            param = argv[i + 1];
            return MainDlg::RunProfile;
        }
    }

    return MainDlg::Nothing;
}

int APIENTRY wWinMain( HINSTANCE /*hInstance*/, HINSTANCE /*hPrevInstance*/, LPWSTR /*lpCmdLine*/, int /*nCmdShow*/ )
{
    // Setup dump generation
    dump::DumpHandler::Instance().CreateWatchdog( blackbone::Utils::GetExeDirectory(), dump::CreateFullDump, &DumpNotifier );
    AssociateExtension();

    std::wstring param;
    auto action = ParseCmdLine( param );
    MainDlg mainDlg( action, param );
    LogOSInfo();

    if (action != MainDlg::RunProfile)
        return (int)mainDlg.RunModeless( NULL, IDR_ACCELERATOR1 );
    else
        return mainDlg.LoadAndInject();
}