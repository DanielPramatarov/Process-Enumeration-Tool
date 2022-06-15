#include <iostream>
#include <string>
#include <cassert>

#include <windows.h>


extern "C" void QueryFullProcessImageNameA( HANDLE hProc, int n
                                           , char* buffer, DWORD* buffer_size);

extern "C" BOOL IsProcessCritical(HANDLE hProcess, PBOOL  Critical);

extern "C" BOOL ConvertSidToStringSidA(PSID Sid,  LPSTR* StringSid);

bool            tokenHasPrivilege( HANDLE hToken, const char* privilege);
void           showTokenPrivilege( HANDLE hToken, const char* privilege);
void show_process_token_privilege( int pid);
BOOL              isTokenElevated( HANDLE hToken );
BOOL                 SetPrivilege( HANDLE  hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege); 


int main(int argc, char** argv)
{

  if( argc < 2 )
  {
    std::printf("\n Usage: %s [COMMAND] [ARGUMENT]", argv[0] );

    std::printf("\n => Show process token information");
    std::printf("\n $ .%s proc [PID] \n", argv[0] );

    std::printf("\n => Set debug privilege and show current privileges");
    std::printf("\n $ %s priv \n", argv[0] );    
    return EXIT_FAILURE;
  }

  auto command = std::string{ argv[1] };

  if( command == "proc" )
  {
     DWORD pid =  std::stoi(argv[2]);

     
     if( pid == 0){ pid = GetCurrentProcessId(); }
     show_process_token_privilege( pid );
     return EXIT_SUCCESS;
  }

  if( command == "priv" )
  {

    HANDLE hProc = GetCurrentProcess();
    HANDLE hToken = nullptr;

    if( !OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken) )
    { 
      std::printf("Error - unable to open process Token. => Check GetLastError() error code. \n");
      std::abort();
    }

    assert( hToken != nullptr );


    std::printf( " Is process elevated (admin)? = %s \n"
                , isTokenElevated(hToken) ? "TRUE" : "FALSE" );


    SetPrivilege( hToken, SE_DEBUG_NAME, TRUE);
    showTokenPrivilege( hToken, SE_DEBUG_NAME );    


    SetPrivilege( hToken, "SeBackupPrivilege", TRUE);
    showTokenPrivilege( hToken, "SeBackupPrivilege" );

    SetPrivilege( hToken, "SeCreateGlobalPrivilege", TRUE);
    showTokenPrivilege( hToken, "SeCreateGlobalPrivilege" );

    SetPrivilege( hToken, "SeLoadDriverPrivilege", TRUE);
    showTokenPrivilege( hToken, "SeLoadDriverPrivilege" );

    return EXIT_SUCCESS;
  }


  return EXIT_SUCCESS;
}


BOOL isTokenElevated( HANDLE hToken )
{

  TOKEN_ELEVATION elevation;
  DWORD size = sizeof( TOKEN_ELEVATION );
  if( !GetTokenInformation( hToken, TokenElevation, &elevation
                            , sizeof( TOKEN_ELEVATION), &size ) )
  {
    return FALSE;
  }
  return elevation.TokenIsElevated;
}


bool tokenHasPrivilege(HANDLE hToken, const char* privilege)
{
    LUID luid;
    PRIVILEGE_SET prvset;

    if( !LookupPrivilegeValue(nullptr, privilege, &luid) )
    {
       fprintf(stderr, "Function LookipPrivilegeAndValue() failed. \n");
       std::abort();
    }

    prvset.Control                 = PRIVILEGE_SET_ALL_NECESSARY;
    prvset.Privilege[0].Luid       = luid;
    prvset.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;;
    prvset.PrivilegeCount          = 1;

    BOOL ret;
    PrivilegeCheck(hToken, &prvset, &ret);
    return ret == TRUE;
}


void showTokenPrivilege(HANDLE hToken, const char* privilege)
{

  bool p = tokenHasPrivilege(hToken, privilege);
  std::fprintf( stdout, "\n [*] Has privilege? %s = %s \n"
               , privilege, p ? "TRUE" : "FALSE" );

}

void show_process_token_privilege(int pid)
{

  assert( pid > 0 );
  HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if( hProc == nullptr )
  {  
    std::printf( " Error => Unable to open process => Error code = %ld"
                , GetLastError()); 
    std::abort();
  }


  DWORD size = MAX_PATH;
  char buffer[MAX_PATH];      

  QueryFullProcessImageNameA(hProc, 0, buffer, &size);

  HANDLE hToken = nullptr;
  if( !OpenProcessToken(hProc, TOKEN_QUERY, &hToken) )
  { 
     std::printf("Error - unable to open process Token. => Check GetLastError() error code. \n");
     std::abort();
  }



  DWORD needed;

  GetTokenInformation( hToken, TokenUser, NULL, 0, &needed);
  auto tuser = reinterpret_cast<TOKEN_USER*>( LocalAlloc( LPTR, needed) );    
  assert( tuser != nullptr );
  GetTokenInformation( hToken, TokenUser, tuser, needed, &needed);

  PSID psid = tuser->User.Sid;
  char buffer_user[500];
  char buffer_domain[500];
  DWORD size_user   = sizeof(buffer_user);
  DWORD size_domain = sizeof(buffer_domain);

  SID_NAME_USE snu;
  if( !LookupAccountSid( nullptr, psid
                         , buffer_user,  &size_user
                         , buffer_domain, &size_domain
                         , &snu ) )
  {
    std::printf( "Error. Function LookupAccountSid() failed => Last error code = %ld"
                , GetLastError());
    std::abort();
  }


  char* pBuffer_sid = nullptr;

 
  assert( ConvertSidToStringSidA(psid, &pBuffer_sid) );


  std::printf(" [TOKEN] >> Pid = %d ; EXE = %s \n", pid, buffer);
  std::printf(" User account = %s \n", buffer_user   );
  std::printf(" User domain  = %s \n", buffer_domain );
  std::printf(" SID          = %s \n", pBuffer_sid   );

  BOOL is_critical = FALSE;
  IsProcessCritical(hProc, &is_critical);
  std::printf(" Is process critical = %s \n", is_critical ? "TRUE" : "FALSE" );

  std::printf(" Is process elevated (admin)? = %s \n", isTokenElevated(hToken) ? "TRUE" : "FALSE" );

  std::printf(" Is token restricted = %s \n", IsTokenRestricted(hToken) ? "TRUE" : "FALSE" );


  showTokenPrivilege( hToken, SE_ASSIGNPRIMARYTOKEN_NAME);
  showTokenPrivilege( hToken, SE_BACKUP_NAME );
  showTokenPrivilege( hToken, SE_DEBUG_NAME );
  showTokenPrivilege( hToken, SE_INCREASE_QUOTA_NAME );

  showTokenPrivilege( hToken, SE_TCB_NAME );


  showTokenPrivilege( hToken, "SeImpersonatePrivilege");

  showTokenPrivilege( hToken, "SeLoadDriverPrivilege");

  showTokenPrivilege( hToken, "SeSystemtimePrivilege" );

  showTokenPrivilege( hToken, "SeCreateGlobalPrivilege");

  showTokenPrivilege( hToken, "SeCreateSymbolicLinkPrivilege");

  showTokenPrivilege( hToken, "SeSecurityPrivilege");

  CloseHandle(hProc);
  CloseHandle(hToken);
}


BOOL SetPrivilege(
      HANDLE  hToken            
    , LPCTSTR lpszPrivilege   
    , BOOL    bEnablePrivilege  
    ) 
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if ( !LookupPrivilegeValue(NULL, lpszPrivilege, &luid ) )        
    {
        printf("LookupPrivilegeValue error: %ld\n", GetLastError() ); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;


    if ( !AdjustTokenPrivileges(
           hToken, 
           FALSE, 
           &tp, 
           sizeof(TOKEN_PRIVILEGES), 
           (PTOKEN_PRIVILEGES) NULL, 
           (PDWORD) NULL) )
    { 
          printf("AdjustTokenPrivileges error: %ld\n", GetLastError() ); 
          return FALSE; 
    } 

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
          printf("The token does not have the specified privilege. \n");
          return FALSE;
    } 

    return TRUE;
}