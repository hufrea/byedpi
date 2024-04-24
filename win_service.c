#include "win_service.h"
#include <minwindef.h>
#include <winsvc.h>

#define SERVICE_NAME "ByeDPI"

static SERVICE_STATUS ServiceStatus;
static SERVICE_STATUS_HANDLE hStatus;

static int svc_argc = 0;
static char **svc_argv = NULL;

int main(int argc, char *argv[]);

void service_ctrl_handler(DWORD request)
{
    switch(request)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ServiceStatus.dwWin32ExitCode = 0;
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
        default:
            break;
    }
    SetServiceStatus(hStatus, &ServiceStatus);
    return;
}

void service_main(int argc __attribute__((unused)), char *argv[] __attribute__((unused)))
{
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 1;
    ServiceStatus.dwWaitHint = 0;

    hStatus = RegisterServiceCtrlHandler(SERVICE_NAME, (LPHANDLER_FUNCTION)service_ctrl_handler);
    if (hStatus == (SERVICE_STATUS_HANDLE)0)
    {
        // Registering Control Handler failed
        return;
    }

    SetServiceStatus(hStatus, &ServiceStatus);

    // Calling main with saved argc & argv
    ServiceStatus.dwWin32ExitCode = (DWORD)main(svc_argc, svc_argv);
    ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
    SetServiceStatus(hStatus, &ServiceStatus);
    return;
}

int register_winsvc(int argc, char *argv[])
{
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)service_main},
        {NULL, NULL}
    };

    // Save args passed to the program to use instead of the service args.
    if (svc_argv) {
        return 0;
    }
    svc_argc = argc;
    svc_argv = argv;
        
    return StartServiceCtrlDispatcher(ServiceTable);
}